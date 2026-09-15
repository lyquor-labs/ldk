//! Minimal Lyquid that mounts and executes `circle-nanopay-flow` locally.

use std::sync::Arc;

use circle_nanopay_flow::{Eip3009Authorization, PaymentConfig, PaymentRequest, PaymentState};
use lyquid::prelude::*;
use lyquid_flow::{AutoCheckpointConfig, ExitTransitions, Flow, InputHandle, Scope, TraceMode, Value};

const PAYMENT_STEP: &str = "payment";
const SUCCEEDED_EXIT: &str = "succeeded";
const FAILED_EXIT: &str = "failed";

state! {
    instance next_execution_id: u64 = 1;
    instance active_execution_id: Option<u64> = None;
    instance payment_inputs: HashMap<u64, InputHandle> = new_hashmap();
    instance payment_states: HashMap<u64, PaymentState> = new_hashmap();
}

fn err(message: impl Into<String>) -> LyquidError {
    LyquidError::LyquorRuntime(message.into())
}

fn application_flow() -> Flow {
    let transitions = ExitTransitions::new()
        .transition(circle_nanopay_flow::SUCCEEDED_EXIT, SUCCEEDED_EXIT)
        .and_then(|transitions| transitions.transition(circle_nanopay_flow::FAILED_EXIT, FAILED_EXIT))
        .expect("the static payment Flow exit transitions must be valid");
    Flow::builder("circle-nanopay-example")
        .description("Run one mounted Circle nanopayment Flow locally")
        .entry(PAYMENT_STEP)
        .exit(SUCCEEDED_EXIT)
        .exit(FAILED_EXIT)
        .flow(
            PAYMENT_STEP,
            Arc::new(
                circle_nanopay_flow::flow(PaymentConfig::base_sepolia())
                    .expect("the Base Sepolia payment configuration must be valid"),
            ),
            transitions,
            TraceMode::Expanded,
        )
        .build()
        .expect("the static payment example Flow graph must be valid")
}

#[method::instance(export = eth)]
fn is_ready(_ctx: &_) -> LyquidResult<bool> {
    Ok(true)
}

#[method::instance(export = eth)]
fn start_payment(
    ctx: &mut _, resource_url: String, max_amount_base_units: String, network: String, correlation_id: String,
    buyer_address: String, recipient: String,
) -> LyquidResult<u64> {
    let execution_id = {
        let mut active_execution_id = ctx.instance.active_execution_id.write();
        if let Some(active_execution_id) = *active_execution_id {
            return Err(err(format!("payment execution {active_execution_id} is still active")));
        }
        let mut next_execution_id = ctx.instance.next_execution_id.write();
        let execution_id = *next_execution_id;
        *next_execution_id = execution_id
            .checked_add(1)
            .ok_or_else(|| err("payment execution ID sequence exhausted"))?;
        *active_execution_id = Some(execution_id);
        execution_id
    };
    let request = PaymentRequest {
        resource_url,
        max_amount_base_units,
        network,
        correlation_id,
        buyer_address,
        recipient,
    };
    ctx.instance.payment_states.write().insert(
        execution_id,
        PaymentState::Initialized {
            request: request.clone(),
        },
    );
    trigger!(
        execute_payment(execution_id: u64 = execution_id, request: PaymentRequest = request),
        TriggerMode::Once(0)
    );
    Ok(execution_id)
}

#[method::instance(export = eth)]
fn get_payment_authorization_request(ctx: &_, execution_id: u64) -> LyquidResult<String> {
    let input = ctx
        .instance
        .payment_inputs
        .read()
        .get(&execution_id)
        .cloned()
        .ok_or_else(|| {
            err(format!(
                "payment execution {execution_id} is not awaiting authorization"
            ))
        })?;
    input.input_spec().map(|spec| spec.prompt).ok_or_else(|| {
        err(format!(
            "payment execution {execution_id} is preparing its authorization request"
        ))
    })
}

#[method::instance(export = eth)]
fn submit_payment_authorization(ctx: &mut _, execution_id: u64, authorization_json: String) -> LyquidResult<bool> {
    let authorization = serde_json::from_str::<Eip3009Authorization>(&authorization_json)
        .map_err(|error| err(format!("decode payment authorization: {error}")))?;
    let input = ctx
        .instance
        .payment_inputs
        .read()
        .get(&execution_id)
        .cloned()
        .ok_or_else(|| {
            err(format!(
                "payment execution {execution_id} is not awaiting authorization"
            ))
        })?;
    if !input.offer_input(Box::new(authorization)) {
        return Err(err(format!(
            "payment execution {execution_id} is not ready for authorization"
        )));
    }
    Ok(true)
}

#[method::instance(export = eth)]
fn get_payment_state(ctx: &_, execution_id: u64) -> LyquidResult<String> {
    let state = ctx
        .instance
        .payment_states
        .read()
        .get(&execution_id)
        .cloned()
        .ok_or_else(|| err(format!("unknown payment execution {execution_id}")))?;
    Ok(state.encode())
}

#[method::instance]
fn execute_payment(ctx: &mut _, execution_id: u64, request: PaymentRequest) -> LyquidResult<bool> {
    let mut scope = Scope::new(
        Arc::new(application_flow()),
        circle_nanopay_flow::initial_state(request.clone()),
        AutoCheckpointConfig::Disabled,
        None,
    );
    let input = scope.input_handle();
    ctx.instance.payment_inputs.write().insert(execution_id, input);
    let execution_result = scope.advance();
    ctx.instance.payment_inputs.write().remove(&execution_id);

    let state = match execution_result {
        Ok(()) => circle_nanopay_flow::payment_state(&scope).clone(),
        Err(error) => PaymentState::Failed {
            request,
            reason: error.to_string(),
        },
    };
    let succeeded = matches!(state, PaymentState::Succeeded(_));
    ctx.instance.payment_states.write().insert(execution_id, state);
    let mut active_execution_id = ctx.instance.active_execution_id.write();
    if *active_execution_id == Some(execution_id) {
        *active_execution_id = None;
    }
    Ok(succeeded)
}
