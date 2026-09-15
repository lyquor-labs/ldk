use std::sync::Arc;

use lyquid_flow::{
    Flow, FlowError, InputSpec, Scope, State, StateNamespace, StateUpdates, Step, TemplateSpec, TraceSummary,
    TurnProposal,
};

use crate::payment::{build_requirements, settle_payment, validate_config, verify_authorization};
use crate::{Eip3009Authorization, PaymentConfig, PaymentRequest, PaymentState};

pub const PAYMENT_STATE_FIELD: &str = "payment";

const AUTHORIZATION_INPUT: &str = "payment_authorization";
const REQUEST_STEP: &str = "request";
const AUTHORIZE_STEP: &str = "authorize";
const SETTLE_STEP: &str = "settle";
pub const SUCCEEDED_EXIT: &str = "succeeded";
pub const FAILED_EXIT: &str = "failed";

/// Builds the immutable payment Flow using the supplied settlement configuration.
pub fn flow(config: PaymentConfig) -> Result<Flow, String> {
    validate_config(&config)?;
    let config = Arc::new(config);
    Ok(Flow::builder("circle-nanopay-payment")
        .description("Validate, authorize, and settle one Circle x402 payment")
        .entry(REQUEST_STEP)
        .exit(SUCCEEDED_EXIT)
        .exit(FAILED_EXIT)
        .step(
            REQUEST_STEP,
            RequestPaymentStep {
                config: Arc::clone(&config),
            },
        )
        .step(
            AUTHORIZE_STEP,
            AuthorizePaymentStep {
                config: Arc::clone(&config),
            },
        )
        .step(SETTLE_STEP, SettlePaymentStep { config })
        .build()
        .expect("the static Circle nanopay Flow graph must be valid"))
}

/// Creates the State expected by a fresh payment Scope.
pub fn initial_state(request: PaymentRequest) -> State {
    State::builder()
        .field(
            PAYMENT_STATE_FIELD,
            "Current Circle nanopayment state",
            PaymentState::Initialized { request },
        )
        .build()
        .expect("the static Circle nanopay State schema must be valid")
}

/// Returns the payment state committed by a Scope running this Flow.
pub fn payment_state(scope: &Scope) -> &PaymentState {
    scope
        .state()
        .get(PAYMENT_STATE_FIELD)
        .expect("a Circle nanopay Scope must use circle_nanopay_flow::initial_state")
}

struct RequestPaymentStep {
    config: Arc<PaymentConfig>,
}

impl Step for RequestPaymentStep {
    fn description(&self, _concise: bool) -> String {
        "Accept and validate a Circle nanopayment request".to_owned()
    }

    fn input(&self, _scope: &Scope) -> Option<InputSpec> {
        None
    }

    fn model_template(&self, _scope: &Scope) -> TemplateSpec {
        TemplateSpec::Skip(TurnProposal::Advance {
            next: Some(AUTHORIZE_STEP.into()),
            updates: StateUpdates::default(),
        })
    }

    fn finalize(&self, scope: &Scope, proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
        let PaymentState::Initialized { request } = scope
            .state()
            .get::<PaymentState>(PAYMENT_STATE_FIELD)
            .expect("the payment State must be initialized")
        else {
            unreachable!("the request Step requires a submitted payment request")
        };
        let request = request.clone();
        let TurnProposal::Advance { next, updates } = proposal else {
            unreachable!("a deterministic request Step always proposes an Advance")
        };
        Ok(match build_requirements(scope.execution_id(), &self.config, &request) {
            Ok(requirements) => {
                updates.set(
                    PAYMENT_STATE_FIELD.to_owned(),
                    Some(Box::new(PaymentState::AwaitingAuthorization { request, requirements })),
                );
                TraceSummary::Summary("Accepted payment request".to_owned())
            }
            Err(reason) => {
                *next = Some(FAILED_EXIT.into());
                updates.set(
                    PAYMENT_STATE_FIELD.to_owned(),
                    Some(Box::new(PaymentState::Failed {
                        request,
                        reason: reason.clone(),
                    })),
                );
                TraceSummary::Summary(format!("Rejected payment request: {reason}"))
            }
        })
    }
}

struct AuthorizePaymentStep {
    config: Arc<PaymentConfig>,
}

impl Step for AuthorizePaymentStep {
    fn description(&self, _concise: bool) -> String {
        "Verify the buyer's EIP-3009 payment authorization".to_owned()
    }

    fn input(&self, scope: &Scope) -> Option<InputSpec> {
        let state = scope
            .state()
            .get::<PaymentState>(PAYMENT_STATE_FIELD)
            .expect("the payment State must be initialized");
        let PaymentState::AwaitingAuthorization { requirements, .. } = state else {
            unreachable!("the authorization Step requires an accepted payment request")
        };
        Some(InputSpec {
            prompt: serde_json::to_string(requirements).expect("payment requirements serialization cannot fail"),
            name: AUTHORIZATION_INPUT.to_owned(),
            value: Box::new(Eip3009Authorization::default()),
        })
    }

    fn model_template(&self, _scope: &Scope) -> TemplateSpec {
        TemplateSpec::Skip(TurnProposal::Advance {
            next: Some(SETTLE_STEP.into()),
            updates: StateUpdates::default(),
        })
    }

    fn finalize(&self, scope: &Scope, proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
        let authorization = scope
            .get::<Eip3009Authorization>(StateNamespace::Input, AUTHORIZATION_INPUT)
            .expect("the authorization Step runs only after receiving its declared input")
            .clone();
        let PaymentState::AwaitingAuthorization { request, requirements } = scope
            .state()
            .get::<PaymentState>(PAYMENT_STATE_FIELD)
            .expect("the payment State must be initialized")
        else {
            unreachable!("the authorization Step requires an accepted payment request")
        };
        let request = request.clone();
        let requirements = requirements.clone();
        let TurnProposal::Advance { next, updates } = proposal else {
            unreachable!("a deterministic authorization Step always proposes an Advance")
        };
        Ok(
            match verify_authorization(&self.config, &request, &requirements, &authorization) {
                Ok(()) => {
                    updates.set(
                        PAYMENT_STATE_FIELD.to_owned(),
                        Some(Box::new(PaymentState::Authorized {
                            request,
                            requirements,
                            authorization,
                        })),
                    );
                    TraceSummary::Summary("Verified payment authorization".to_owned())
                }
                Err(reason) => {
                    *next = Some(FAILED_EXIT.into());
                    updates.set(
                        PAYMENT_STATE_FIELD.to_owned(),
                        Some(Box::new(PaymentState::Failed {
                            request,
                            reason: reason.clone(),
                        })),
                    );
                    TraceSummary::Summary(format!("Rejected payment authorization: {reason}"))
                }
            },
        )
    }
}

struct SettlePaymentStep {
    config: Arc<PaymentConfig>,
}

impl Step for SettlePaymentStep {
    fn description(&self, _concise: bool) -> String {
        "Settle the authorized payment with the Circle x402 facilitator".to_owned()
    }

    fn input(&self, _scope: &Scope) -> Option<InputSpec> {
        None
    }

    fn model_template(&self, _scope: &Scope) -> TemplateSpec {
        TemplateSpec::Skip(TurnProposal::Advance {
            next: Some(SUCCEEDED_EXIT.into()),
            updates: StateUpdates::default(),
        })
    }

    fn finalize(&self, scope: &Scope, proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
        let PaymentState::Authorized {
            request,
            requirements: _,
            authorization,
        } = scope
            .state()
            .get::<PaymentState>(PAYMENT_STATE_FIELD)
            .expect("the payment State must be initialized")
        else {
            unreachable!("the settlement Step requires a verified authorization")
        };
        let request = request.clone();
        let authorization = authorization.clone();
        let TurnProposal::Advance { next, updates } = proposal else {
            unreachable!("a deterministic settlement Step always proposes an Advance")
        };
        Ok(match settle_payment(&self.config, &request, &authorization) {
            Ok(receipt) => {
                let transaction = receipt.transaction.clone();
                updates.set(
                    PAYMENT_STATE_FIELD.to_owned(),
                    Some(Box::new(PaymentState::Succeeded(receipt))),
                );
                TraceSummary::Summary(format!("Settled payment in transaction {transaction}"))
            }
            Err(reason) => {
                *next = Some(FAILED_EXIT.into());
                updates.set(
                    PAYMENT_STATE_FIELD.to_owned(),
                    Some(Box::new(PaymentState::Failed {
                        request,
                        reason: reason.clone(),
                    })),
                );
                TraceSummary::Summary(format!("Payment settlement failed after automatic recheck: {reason}"))
            }
        })
    }
}
