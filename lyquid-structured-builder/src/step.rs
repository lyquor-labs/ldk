use std::sync::Arc;

use lyquid_flow::{FlowError, InputSpec, Scope, StateUpdates, Step, StepId, TemplateSpec, TraceSummary, TurnProposal};
use serde_json::{Map, Value as JsonValue};

use crate::{StructuredSpec, ValueSpec};

/// Adds structured model criteria, State updates, and input/output handoff to an existing Step.
#[derive(Clone)]
pub struct StructuredStep {
    pub(super) inner: Arc<dyn Step>,
    pub(super) spec: StructuredSpec,
}

impl StructuredStep {
    fn needs_model(&self) -> bool {
        self.spec.next_steps.len() > 1 || self.spec.state_updates.iter().any(|(_, value)| value.is_model())
    }

    fn prepare_post_step_io_bindings(&self, scope: &Scope, updates: &mut StateUpdates) -> Result<(), FlowError> {
        // A child Flow may return its internal __input through accumulated updates.
        // Remove the proposal so post-Step references read this Step's original inputs.
        updates.set("__input".into(), None);

        let Some(output_spec) = &self.spec.output else {
            updates.set("__output".into(), Some(JsonValue::Null));
            return Ok(());
        };
        // Output may use a constant or another State field without a native result.
        // Mask a missing native __output with null so references cannot read the previous Step's output.
        if updates.get("__output").is_none() {
            updates.set("__output".into(), Some(JsonValue::Null));
        }
        // TODO: Support model-derived output after model response-schema support.
        let output = output_spec
            .value
            .read(scope, updates)?
            .ok_or_else(|| FlowError::from("model-derived output is not supported yet"))?;
        output_spec
            .ty
            .validate(&output)
            .map_err(|error| FlowError::context("output", error))?;
        updates.set("__output".into(), Some(output));
        Ok(())
    }

    fn prepare_next_step_input_bindings(
        &self, scope: &Scope, selected_next: &Option<StepId>, updates: &StateUpdates,
    ) -> Result<JsonValue, FlowError> {
        let Some(selected) = self
            .spec
            .next_steps
            .iter()
            .find(|candidate| &candidate.step_id == selected_next)
        else {
            return Ok(JsonValue::Object(Map::new()));
        };
        let mut inputs = Map::new();
        for (name, source) in &selected.inputs {
            // TODO: Support model-derived arguments after model response-schema support.
            let value = source
                .read(scope, updates)?
                .ok_or_else(|| format!("destination input {name:?}: model-derived arguments are not supported yet"))?;
            inputs.insert(name.clone(), value);
        }
        Ok(JsonValue::Object(inputs))
    }

    fn finalize_proposal(
        &self, scope: &Scope, proposal: &mut TurnProposal, model_called: bool,
    ) -> Result<TraceSummary, FlowError> {
        // Keep structured model decisions before the native finalizer revises the proposal.
        let (selected, model_updates) = match proposal {
            TurnProposal::Advance { next, updates } => (
                Some(next.clone()),
                self.spec
                    .state_updates
                    .iter()
                    .filter_map(|(field, source)| {
                        source
                            .is_model()
                            .then(|| updates.get(field))
                            .flatten()
                            .map(|value| (field.clone(), value.clone()))
                    })
                    .collect::<Vec<_>>(),
            ),
            TurnProposal::Restore { .. } => (None, Vec::new()),
        };
        let inherited_summary = self.inner.finalize(scope, proposal)?;
        let TurnProposal::Advance { next, updates } = proposal else {
            return Ok(inherited_summary);
        };
        if self.needs_model() && !model_called {
            return Err(
                "structured model rules require the wrapped Step to return a model template"
                    .to_owned()
                    .into(),
            );
        }
        let destinations = &self.spec.next_steps;
        if !destinations.is_empty() {
            for destination in destinations {
                scope.validate_next(&destination.step_id)?;
            }
            *next = if destinations.len() == 1 {
                destinations[0].step_id.clone()
            } else if let Some(selected) = selected &&
                destinations.iter().any(|case| case.step_id == selected)
            {
                selected
            } else {
                return Err("model selected an undeclared next Step".to_owned().into());
            };
        }
        self.prepare_post_step_io_bindings(scope, updates)?;
        let next_inputs = self.prepare_next_step_input_bindings(scope, next, updates)?;
        // Resolve State updates against the native proposal and post-Step I/O before applying them.
        let mut state_updates = Vec::new();
        for (field, source) in &self.spec.state_updates {
            let declaration = scope
                .state()
                .declared_type(field)
                .ok_or_else(|| format!("unknown State update {field:?}"))?;
            if let Some(value) = source.read(scope, updates)? {
                declaration
                    .validate(&value)
                    .map_err(|error| FlowError::context(format!("invalid State update {field}"), error))?;
                state_updates.push((field.clone(), value));
            }
        }
        // Apply state updates to the current updates object
        for (field, value) in state_updates {
            updates.set(field, Some(value));
        }
        for (field, value) in model_updates {
            updates.set(field, Some(value));
        }
        // Keep current-Step inputs through all post-Step reads, then hand off the next Step's arguments.
        updates.set("__input".into(), Some(next_inputs));
        Ok(inherited_summary)
    }
}

impl Step for StructuredStep {
    fn description(&self, concise: bool) -> String {
        self.inner.description(concise)
    }

    fn input(&self, scope: &Scope) -> Option<InputSpec> {
        self.inner.input(scope)
    }

    fn model_template(&self, scope: &Scope) -> TemplateSpec {
        let mut template = match self.inner.model_template(scope) {
            TemplateSpec::Template(template) => template,
            direct => return direct,
        };
        if !self.spec.next_steps.is_empty() {
            template.next_step_criteria = self
                .spec
                .next_steps
                .iter()
                .map(|case| (case.step_id.clone(), case.description.clone()))
                .collect();
        }
        template.state_update_criteria.retain(|(field, _)| {
            !self
                .spec
                .state_updates
                .iter()
                .any(|(configured, source)| configured == field && source.is_model())
        });
        template
            .state_update_criteria
            .extend(
                self.spec
                    .state_updates
                    .iter()
                    .filter_map(|(field, source)| match source {
                        ValueSpec::Model { description } => Some((field.clone(), description.clone())),
                        _ => None,
                    }),
            );
        TemplateSpec::Template(template)
    }

    fn model_context(&self, scope: &Scope) -> Result<JsonValue, FlowError> {
        self.inner.model_context(scope)
    }

    fn finalize(&self, scope: &Scope, proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
        self.finalize_proposal(scope, proposal, scope.model_response().is_some())
    }
}

#[cfg(test)]
mod tests {
    // Group by feature: template rules, applied results, and rejected inputs stay together.
    // Native delegation and Restore share one test; failed-turn commit checks have one representative case.
    // Test names state the expected behavior, and case names identify the input variation.
    // Shared fixtures produce native behavior; assertions stay in the tests.
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use lyquid_flow::{
        AutoCheckpointConfig, ExitTransitions, Flow, FlowError, InputSpec, ModelTemplate, Scope, ScopeId, State,
        StateNamespace, StateUpdates, Step, TemplateSpec, TraceMode, TraceSummary, TurnProposal, Type,
    };
    use lyquid_llm::{
        Backend, JsonApiResponse, LlmError, LlmResult, ModelConfig, ModelRequest, ModelResponse, PreparedJsonApiRequest,
    };
    use lyquid_test::test;
    use serde_json::{Value as JsonValue, json};

    use crate::{Input, NextStep, Output, StructuredSpec, ValueSpec, state_builder};

    struct CaptureRequest(Arc<Mutex<Vec<ModelRequest>>>);

    impl Backend for CaptureRequest {
        fn prepare_request(&self, request: &ModelRequest) -> LlmResult<PreparedJsonApiRequest> {
            self.0.lock().unwrap().push(request.clone());
            Err(LlmError::Backend {
                provider: "fixture".into(),
                message: "captured before HTTP".into(),
            })
        }

        fn parse_response(&self, _: JsonApiResponse) -> LlmResult<ModelResponse> {
            unreachable!("the fixture never sends HTTP")
        }
    }

    fn capture_model(requests: Arc<Mutex<Vec<ModelRequest>>>) -> ModelConfig {
        ModelConfig::new("fixture", CaptureRequest(requests))
    }

    #[derive(Default)]
    struct Calls {
        inputs: AtomicUsize,
        templates: AtomicUsize,
        finalizers: AtomicUsize,
        contexts: AtomicUsize,
        shared_before_finalize: Mutex<Option<u64>>,
    }

    #[derive(Default)]
    enum Mode {
        End,
        #[default]
        Direct,
        Model,
        Restore(ScopeId),
    }

    #[derive(Default)]
    struct TestStep {
        calls: Arc<Calls>,
        input: Option<InputSpec>,
        mode: Mode,
    }

    impl Step for TestStep {
        fn description(&self, concise: bool) -> String {
            match self.mode {
                Mode::End => "End".into(),
                _ => if concise { "Native" } else { "Native business Step" }.into(),
            }
        }

        fn input(&self, _scope: &Scope) -> Option<InputSpec> {
            self.calls.inputs.fetch_add(1, Ordering::SeqCst);
            self.input.clone()
        }

        fn model_template(&self, _scope: &Scope) -> TemplateSpec {
            self.calls.templates.fetch_add(1, Ordering::SeqCst);
            if matches!(self.mode, Mode::End) {
                return TemplateSpec::Skip(TurnProposal::Advance {
                    next: None,
                    updates: StateUpdates::default(),
                });
            }
            let next = Some("after".into());
            if matches!(self.mode, Mode::Model) {
                TemplateSpec::Template(ModelTemplate {
                    step_goal: "Native goal: {{ context.tag }}; count={{ state.count }}".into(),
                    next_step_criteria: vec![(next, "Native route".into())],
                    state_update_criteria: vec![
                        ("shared".into(), "Native shared criterion".into()),
                        ("count".into(), "Native count criterion".into()),
                    ],
                    allow_restore: true,
                })
            } else {
                let mut updates = StateUpdates::default();
                updates.set("seed".into(), Some(json!(4_u64)));
                updates.set("shared".into(), Some(json!(50_u64)));
                TemplateSpec::Skip(TurnProposal::Advance { next, updates })
            }
        }

        fn model_context(&self, scope: &Scope) -> Result<JsonValue, FlowError> {
            self.calls.contexts.fetch_add(1, Ordering::SeqCst);
            Ok(
                json!({"tag": "native context", "count": scope.state().get("count").and_then(serde_json::Value::as_u64)}),
            )
        }

        fn finalize(&self, scope: &Scope, proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
            self.calls.finalizers.fetch_add(1, Ordering::SeqCst);
            match &self.mode {
                Mode::End => return Ok(TraceSummary::Summary("End".into())),
                Mode::Restore(checkpoint) => {
                    *proposal = TurnProposal::Restore {
                        scope: checkpoint.clone(),
                    };
                    return Ok(TraceSummary::Summary("Native restore".into()));
                }
                _ => {}
            }
            if let TurnProposal::Advance { next, updates } = proposal {
                *self.calls.shared_before_finalize.lock().unwrap() =
                    updates.get("shared").and_then(serde_json::Value::as_u64);
                if matches!(self.mode, Mode::Model) {
                    *next = Some("selected".into());
                }
                updates.set("count".into(), Some(json!(11_u64)));
                updates.set("shared".into(), Some(json!(3_u64)));
                updates.set("cache".into(), Some(json!("native cache".to_owned())));
                if let Some(note) = scope.get(StateNamespace::Input, "note") {
                    updates.set("input_note".into(), Some(note.clone()));
                }
            }
            Ok(TraceSummary::Summary("Native summary".into()))
        }
    }

    #[derive(Default)]
    struct IoStep {
        result: Option<JsonValue>,
        seen: Arc<Mutex<Vec<JsonValue>>>,
    }

    impl Step for IoStep {
        fn description(&self, _: bool) -> String {
            "I/O operation".into()
        }

        fn input(&self, _: &Scope) -> Option<InputSpec> {
            None
        }

        fn model_template(&self, scope: &Scope) -> TemplateSpec {
            self.seen.lock().unwrap().push(json!({
                "input": scope.state().get("__input"),
                "output": scope.state().get("__output"),
            }));
            TemplateSpec::Skip(TurnProposal::Advance {
                next: None,
                updates: StateUpdates::default(),
            })
        }

        fn finalize(&self, _: &Scope, proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
            if let TurnProposal::Advance { updates, .. } = proposal &&
                let Some(result) = &self.result
            {
                updates.set("__output".into(), Some(result.clone()));
            }
            Ok(TraceSummary::Summary("Operation complete".into()))
        }
    }

    fn input_spec() -> InputSpec {
        let mut builder = InputSpec::builder();
        let note = builder.field::<String>("note", "Native note").non_blank().text_input();
        let submit = builder.submit("Continue");
        let root = builder.ui().column(vec![note, submit]);
        builder.finish(root).unwrap()
    }

    fn routes(targets: &[Option<&str>]) -> Vec<NextStep> {
        targets
            .iter()
            .map(|target| NextStep {
                step_id: target.map(Into::into),
                description: "Continue".into(),
                inputs: vec![],
            })
            .collect()
    }

    fn new_scope(step: impl Step, model: Option<ModelConfig>) -> Scope {
        new_scope_with_destination(
            step,
            TestStep {
                mode: Mode::End,
                ..Default::default()
            },
            model,
        )
    }

    fn new_scope_with_destination(step: impl Step, destination: impl Step, model: Option<ModelConfig>) -> Scope {
        let state = state_builder([])
            .field("count", "Business count", lyquid_flow::Type::U64, json!(2_u64))
            .field("seed", "Native seed", lyquid_flow::Type::U64, json!(0_u64))
            .field("shared", "Explicitly replaceable", lyquid_flow::Type::U64, json!(0_u64))
            .field("copy", "Copied count", lyquid_flow::Type::U64, json!(0_u64))
            .field("sibling", "Copied shared value", lyquid_flow::Type::U64, json!(99_u64))
            .field(
                "input_note",
                "Native input",
                lyquid_flow::Type::String,
                json!(String::new()),
            )
            .field(
                "copy_note",
                "Structured input reference",
                lyquid_flow::Type::String,
                json!(String::new()),
            )
            .field("cache", "Native cache", lyquid_flow::Type::String, json!(""))
            .build()
            .unwrap();
        let flow = Flow::builder("structured-test")
            .entry("wrapped")
            .step("wrapped", step)
            .step("after", destination)
            .step(
                "selected",
                TestStep {
                    mode: Mode::End,
                    ..Default::default()
                },
            )
            .exit("done")
            .build()
            .unwrap();
        Scope::new(Arc::new(flow), state, AutoCheckpointConfig::Unbounded, model)
    }

    #[test]
    fn initialized_io_supplies_entry_arguments_and_clears_undeclared_output() {
        let spec = StructuredSpec {
            inputs: vec![Input {
                name: "root".into(),
                description: "Entry argument".into(),
                required: true,
                ty: Type::U64,
            }],
            state_updates: vec![(
                "captured".into(),
                ValueSpec::reference(StateNamespace::Default, "__input"),
            )],
            ..Default::default()
        };
        let state = state_builder([("root".into(), json!(1))])
            .field("captured", "Post-Step arguments", Type::Dynamic, JsonValue::Null)
            .build()
            .unwrap();
        spec.validate_inputs(state.get("__input")).unwrap();
        assert_eq!(state.declared_type("__input"), Some(&Type::Dynamic));
        assert_eq!(state.declared_type("__output"), Some(&Type::Dynamic));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let step = spec
            .with(IoStep {
                result: Some(json!(7)),
                seen: seen.clone(),
            })
            .unwrap();
        let flow = Flow::builder("initialized-io")
            .entry("work")
            .step("work", step)
            .build()
            .unwrap();
        let mut scope = Scope::new(Arc::new(flow), state, AutoCheckpointConfig::Disabled, None);

        scope.advance().unwrap();

        assert!(scope.is_finished());
        assert_eq!(
            *seen.lock().unwrap(),
            vec![json!({"input": {"root": 1}, "output": null})]
        );
        assert_eq!(scope.state().get("captured"), Some(&json!({"root": 1})));
        assert_eq!(scope.state().get("__input"), Some(&json!({})));
        assert_eq!(scope.state().get("__output"), Some(&JsonValue::Null));
    }

    #[test]
    fn spec_rejects_invalid_rules() {
        for (case, state_updates, next, expected) in [
            (
                "input_binding_update",
                vec![("__input".into(), ValueSpec::constant(json!({})))],
                vec![],
                "use the Inputs, Output, and Next Step sections for I/O bindings",
            ),
            (
                "output_binding_update",
                vec![("__output".into(), ValueSpec::constant(1))],
                vec![],
                "use the Inputs, Output, and Next Step sections for I/O bindings",
            ),
            (
                "duplicate_update",
                vec![
                    ("count".into(), ValueSpec::constant(1)),
                    ("count".into(), ValueSpec::constant(2)),
                ],
                vec![],
                "duplicate State update",
            ),
            (
                "blank_reference",
                vec![("count".into(), ValueSpec::reference(StateNamespace::Default, " \t"))],
                vec![],
                "State reference: must be nonblank",
            ),
            (
                "blank_model",
                vec![("count".into(), ValueSpec::model(""))],
                vec![],
                "model description: must be nonblank",
            ),
            (
                "invalid_template",
                vec![("count".into(), ValueSpec::model("{{"))],
                vec![],
                "invalid count template",
            ),
            (
                "duplicate_destination",
                vec![],
                routes(&[None, None]),
                "duplicate next Step",
            ),
        ] {
            let error = StructuredSpec {
                state_updates,
                next_steps: next,
                ..Default::default()
            }
            .with(TestStep::default())
            .err()
            .expect(case);
            assert!(error.to_string().contains(expected), "{case}: {error}");
            if case == "invalid_template" {
                assert!(error.0.diagnostics[0].source.as_ref().unwrap().is::<tera::Error>());
            }
        }
        for definition in [
            json!({"inputs": [{"name": " ", "description": "", "required": true, "ty": {"kind": "string"}}]}),
            json!({"output": {"description": "Count", "ty": {"kind": "u64"}, "value": {"source": "constant", "value": "bad"}}}),
            json!({"next_steps": [{"step_id": "after", "description": "Continue", "inputs": [["count", {"source": "model", "description": "{{"}]]}]}),
        ] {
            let spec: StructuredSpec = serde_json::from_value(definition).unwrap();
            assert!(spec.validate_inputs(None).is_err());
            assert!(spec.validate_output(None).is_err());
            assert!(spec.with(TestStep::default()).is_err());
        }
    }

    #[test]
    fn supplied_inputs_validate_presence_and_type() {
        for (case, required, ty, missing_error, null_error) in [
            (
                "required_string",
                true,
                Type::String,
                Some("missing required input"),
                Some("expected string"),
            ),
            ("optional_string", false, Type::String, None, Some("expected string")),
            (
                "required_nullable_string",
                true,
                Type::Option(Box::new(Type::String)),
                Some("missing required input"),
                None,
            ),
            (
                "optional_nullable_string",
                false,
                Type::Option(Box::new(Type::String)),
                None,
                None,
            ),
        ] {
            let spec = StructuredSpec {
                inputs: vec![Input {
                    name: "value".into(),
                    description: "Text value".into(),
                    required,
                    ty,
                }],
                ..Default::default()
            };
            spec.clone().with(TestStep::default()).expect(case);
            for (inputs, expected_error) in [
                (None, missing_error),
                (Some(json!({})), missing_error),
                (Some(json!({"value": null})), null_error),
                (Some(json!({"value": "text"})), None),
                (Some(json!({"value": 42})), Some("expected string")),
            ] {
                let result = spec.validate_inputs(inputs.as_ref());
                match expected_error {
                    None => result.expect(case),
                    Some(message) => {
                        let error = result.expect_err(case);
                        assert_eq!(error.diagnostics[0].context, "input \"value\"", "{case}: {inputs:?}");
                        assert!(
                            error.diagnostics[0].message.contains(message),
                            "{case}: {inputs:?}: {error}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn supplied_inputs_require_an_object_with_declared_keys() {
        let spec = StructuredSpec::default();
        spec.clone().with(TestStep::default()).unwrap();
        for (inputs, expected_error) in [
            (None, None),
            (Some(json!({})), None),
            (Some(json!(null)), Some(("invocation inputs", "must be an object"))),
            (Some(json!([])), Some(("invocation inputs", "must be an object"))),
            (Some(json!(42)), Some(("invocation inputs", "must be an object"))),
            (Some(json!("text")), Some(("invocation inputs", "must be an object"))),
            (Some(json!(true)), Some(("invocation inputs", "must be an object"))),
            (
                Some(json!({"value": "text"})),
                Some(("input \"value\"", "undeclared input parameter")),
            ),
        ] {
            let result = spec.validate_inputs(inputs.as_ref());
            match expected_error {
                None => result.unwrap(),
                Some((context, message)) => {
                    let error = result.expect_err("invalid input object");
                    assert_eq!(error.diagnostics[0].context, context, "{inputs:?}");
                    assert_eq!(error.diagnostics[0].message, message, "{inputs:?}");
                }
            }
        }
    }

    #[test]
    fn supplied_output_validates_presence_and_type() {
        let values = [None, Some(json!(null)), Some(json!(7)), Some(json!("text"))];
        for (case, ty, expected_errors) in [
            (
                "no_output",
                None,
                [
                    None,
                    Some("Step declares no output"),
                    Some("Step declares no output"),
                    Some("Step declares no output"),
                ],
            ),
            (
                "u64_output",
                Some(Type::U64),
                [
                    Some("missing declared output"),
                    Some("expected u64"),
                    None,
                    Some("expected u64"),
                ],
            ),
            (
                "nullable_u64_output",
                Some(Type::Option(Box::new(Type::U64))),
                [Some("missing declared output"), None, None, Some("expected u64")],
            ),
        ] {
            let spec = StructuredSpec {
                output: ty.map(|ty| Output {
                    description: "Count".into(),
                    ty,
                    value: ValueSpec::constant(7),
                }),
                ..Default::default()
            };
            spec.clone().with(TestStep::default()).expect(case);
            for (value, expected_error) in values.iter().zip(expected_errors) {
                let result = spec.validate_output(value.as_ref());
                match expected_error {
                    None => result.expect(case),
                    Some(message) => {
                        let error = result.expect_err(case);
                        assert_eq!(error.diagnostics[0].context, "output", "{case}: {value:?}");
                        assert!(
                            error.diagnostics[0].message.contains(message),
                            "{case}: {value:?}: {error}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn destination_handoff_only_rejects_unresolved_arguments() {
        for (case, inputs, native_route, expected) in [
            ("missing", vec![], false, Ok(json!({}))),
            ("native_route_missing", vec![], true, Ok(json!({}))),
            (
                "wrong_type",
                vec![("order_id".into(), ValueSpec::constant("abc"))],
                false,
                Ok(json!({"order_id": "abc"})),
            ),
            (
                "undeclared",
                vec![
                    ("order_id".into(), ValueSpec::constant(7)),
                    ("extra".into(), ValueSpec::constant(true)),
                ],
                false,
                Ok(json!({"order_id": 7, "extra": true})),
            ),
            (
                "missing_reference",
                vec![(
                    "order_id".into(),
                    ValueSpec::reference(StateNamespace::Default, "missing"),
                )],
                false,
                Err("missing State reference default.missing"),
            ),
            (
                "model_argument",
                vec![("order_id".into(), ValueSpec::model("Choose an order"))],
                false,
                Err("model-derived arguments are not supported yet"),
            ),
        ] {
            let source = StructuredSpec {
                output: Some(Output {
                    description: "Provisional output".into(),
                    ty: Type::U64,
                    value: ValueSpec::constant(42),
                }),
                next_steps: if native_route {
                    vec![]
                } else {
                    vec![NextStep {
                        step_id: Some("after".into()),
                        description: "Continue".into(),
                        inputs,
                    }]
                },
                state_updates: vec![("shared".into(), ValueSpec::constant(9))],
                ..Default::default()
            }
            .with(TestStep::default())
            .expect(case);
            let destination = StructuredSpec {
                inputs: vec![Input {
                    name: "order_id".into(),
                    description: "Order".into(),
                    required: true,
                    ty: Type::U64,
                }],
                ..Default::default()
            }
            .with(TestStep {
                mode: Mode::End,
                ..Default::default()
            })
            .expect(case);
            let mut scope = new_scope_with_destination(source, destination, None);
            let before = scope.state().to_json();
            let checkpoints = scope.checkpoint_ids().count();

            let result = scope.advance();

            match expected {
                Ok(inputs) => {
                    result.expect(case);
                    assert_eq!(scope.current_step().0, "after", "{case}");
                    assert_eq!(scope.state().get("__input"), Some(&inputs), "{case}");
                    assert_eq!(scope.state().get("__output"), Some(&json!(42)), "{case}");
                    assert_eq!(scope.state().get("shared"), Some(&json!(9)), "{case}");
                    assert_eq!(scope.trace().entries.len(), 1, "{case}");

                    // Entry also leaves validation to the consumer.
                    scope.advance().expect(case);
                    assert!(scope.is_finished(), "{case}");
                }
                Err(expected) => {
                    let error = result.expect_err(case);
                    assert!(error.to_string().contains(expected), "{case}: {error}");
                    assert_eq!(scope.current_step().0, "wrapped", "{case}");
                    assert_eq!(scope.state().to_json(), before, "{case}");
                    assert!(scope.trace().entries.is_empty(), "{case}");
                    assert_eq!(scope.checkpoint_ids().count(), checkpoints, "{case}");
                }
            }
        }
    }

    #[test]
    fn destination_inputs_resolve_constants_and_native_proposed_state() {
        for (case, argument, required, expected_inputs) in [
            ("constant", Some(ValueSpec::constant(7)), true, json!({"order_id": 7})),
            (
                "native_proposal",
                Some(ValueSpec::reference(StateNamespace::Default, "count")),
                true,
                json!({"order_id": 11}),
            ),
            (
                "committed_fallback",
                Some(ValueSpec::reference(StateNamespace::Default, "fallback")),
                true,
                json!({"order_id": 9}),
            ),
            ("optional_omitted", None, false, json!({})),
        ] {
            let source = StructuredSpec {
                next_steps: vec![NextStep {
                    step_id: Some("after".into()),
                    description: "Continue".into(),
                    inputs: argument.into_iter().map(|value| ("order_id".into(), value)).collect(),
                }],
                // Argument references use the native proposal, before these replacements.
                state_updates: vec![("count".into(), ValueSpec::constant("structured"))],
                ..Default::default()
            }
            .with(TestStep::default())
            .expect(case);
            let destination = StructuredSpec {
                inputs: vec![Input {
                    name: "order_id".into(),
                    description: "Order".into(),
                    required,
                    ty: Type::U64,
                }],
                ..Default::default()
            }
            .with(TestStep {
                mode: Mode::End,
                ..Default::default()
            })
            .expect(case);
            let flow = Flow::builder("destination-inputs")
                .entry("source")
                .step("source", source)
                .step("after", destination)
                .build()
                .expect(case);
            let state = state_builder([])
                .field("count", "Native result", Type::Dynamic, json!("committed"))
                .field("seed", "Native seed", Type::U64, json!(0))
                .field("shared", "Native update", Type::U64, json!(0))
                .field("fallback", "Unchanged order", Type::U64, json!(9))
                .field("cache", "Native cache", Type::String, json!(""))
                .build()
                .expect(case);
            let mut scope = Scope::new(Arc::new(flow), state, AutoCheckpointConfig::Unbounded, None);

            scope.advance().expect(case);

            assert_eq!(scope.current_step().0, "after", "{case}");
            assert_eq!(scope.state().get("__input"), Some(&expected_inputs), "{case}");
            assert_eq!(scope.state().get("count"), Some(&json!("structured")), "{case}");
            assert_eq!(scope.state().get("seed"), Some(&json!(4)), "{case}");
            assert_eq!(scope.trace().entries.len(), 1, "{case}");
            assert_eq!(
                scope.trace().entries[0].state.to_json(),
                scope.state().to_json(),
                "{case}"
            );
        }
    }

    #[test]
    fn destination_inputs_only_evaluate_the_selected_route() {
        let source = StructuredSpec {
            next_steps: vec![
                NextStep {
                    step_id: Some("after".into()),
                    description: "Selected route".into(),
                    inputs: vec![("order_id".into(), ValueSpec::constant(7))],
                },
                NextStep {
                    step_id: Some("selected".into()),
                    description: "Unused route".into(),
                    inputs: vec![("unused".into(), ValueSpec::model("Not evaluated"))],
                },
            ],
            ..Default::default()
        }
        .with(TestStep {
            mode: Mode::Model,
            ..Default::default()
        })
        .unwrap();
        let destination = StructuredSpec {
            inputs: vec![Input {
                name: "order_id".into(),
                description: "Order".into(),
                required: true,
                ty: Type::U64,
            }],
            ..Default::default()
        }
        .with(TestStep::default())
        .unwrap();
        let scope = new_scope_with_destination(source.clone(), destination, None);
        let mut proposal = TurnProposal::Advance {
            next: Some("after".into()),
            updates: StateUpdates::default(),
        };

        source.finalize_proposal(&scope, &mut proposal, true).unwrap();

        let TurnProposal::Advance { next, updates } = proposal else {
            panic!("expected Advance")
        };
        assert_eq!(next, Some("after".into()));
        assert_eq!(updates.get("count"), Some(&json!(11)));
    }

    #[test]
    fn destination_arguments_allow_native_steps_and_exits() {
        for target in ["after", "done"] {
            let step = StructuredSpec {
                next_steps: vec![NextStep {
                    step_id: Some(target.into()),
                    description: "Continue".into(),
                    inputs: vec![("order_id".into(), ValueSpec::constant(7))],
                }],
                ..Default::default()
            }
            .with(TestStep::default())
            .unwrap();
            let mut scope = new_scope(step, None);

            scope.advance().unwrap();

            assert_eq!(scope.is_finished(), target == "done", "{target}");
            if target == "after" {
                assert_eq!(scope.current_step().0, "after");
            }
            assert_eq!(scope.state().get("__input"), Some(&json!({"order_id": 7})), "{target}");
            assert_eq!(scope.trace().entries.len(), 1, "{target}");
        }
    }

    #[test]
    fn mounted_destination_does_not_enforce_input_declarations() {
        let child = Flow::builder("child")
            .entry("internal")
            .step("internal", TestStep::default())
            .exit("after")
            .build()
            .unwrap();
        for (inputs, expected) in [
            (
                vec![("order_id".into(), ValueSpec::constant(7))],
                json!({"order_id": 7}),
            ),
            (vec![], json!({})),
        ] {
            let source = StructuredSpec {
                next_steps: vec![NextStep {
                    step_id: Some("child".into()),
                    description: "Enter child".into(),
                    inputs,
                }],
                ..Default::default()
            }
            .with(TestStep {
                mode: Mode::End,
                ..Default::default()
            })
            .unwrap();
            let destination = StructuredSpec {
                inputs: vec![Input {
                    name: "order_id".into(),
                    description: "Order".into(),
                    required: true,
                    ty: Type::U64,
                }],
                ..Default::default()
            }
            .with(child.clone())
            .unwrap();
            let parent = Flow::builder("parent")
                .entry("source")
                .step("source", source)
                .exit("done")
                .flow_with(
                    "child",
                    child.clone(),
                    ExitTransitions::new().transition("after", "done").unwrap(),
                    TraceMode::Expanded,
                    destination,
                )
                .build()
                .unwrap();
            let mut scope = Scope::new(
                Arc::new(parent),
                state_builder([]).build().unwrap(),
                AutoCheckpointConfig::Unbounded,
                None,
            );
            scope.advance().unwrap();

            assert_eq!(scope.current_step().0, "child");
            assert_eq!(scope.trace().entries.len(), 1);
            assert_eq!(scope.state().get("__output"), Some(&JsonValue::Null));
            assert_eq!(scope.state().get("__input"), Some(&expected));
        }
    }

    #[test]
    fn io_handoff_resolves_post_step_values_and_clears_stale_output() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let a = StructuredSpec {
            output: Some(Output {
                description: "Native result".into(),
                ty: Type::U64,
                value: ValueSpec::reference(StateNamespace::Default, "__output"),
            }),
            next_steps: vec![NextStep {
                step_id: Some("b".into()),
                description: "Continue".into(),
                inputs: vec![(
                    "record".into(),
                    ValueSpec::reference(StateNamespace::Default, "__output"),
                )],
            }],
            state_updates: vec![(
                "captured_input".into(),
                ValueSpec::reference(StateNamespace::Default, "__input"),
            )],
            ..Default::default()
        }
        .with(IoStep {
            result: Some(json!(42)),
            seen: seen.clone(),
        })
        .unwrap();
        let b = StructuredSpec {
            inputs: vec![Input {
                name: "record".into(),
                description: "Record".into(),
                required: true,
                ty: Type::U64,
            }],
            next_steps: vec![NextStep {
                step_id: Some("c".into()),
                description: "Continue".into(),
                inputs: vec![(
                    "value".into(),
                    ValueSpec::reference(StateNamespace::Default, "__output"),
                )],
            }],
            state_updates: vec![
                (
                    "captured_input".into(),
                    ValueSpec::reference(StateNamespace::Default, "__input"),
                ),
                (
                    "captured_output".into(),
                    ValueSpec::reference(StateNamespace::Default, "__output"),
                ),
            ],
            ..Default::default()
        }
        .with(IoStep {
            result: Some(json!(123)),
            seen: seen.clone(),
        })
        .unwrap();
        let c = StructuredSpec {
            inputs: vec![Input {
                name: "value".into(),
                description: "Value".into(),
                required: true,
                ty: Type::Dynamic,
            }],
            output: Some(Output {
                description: "Completion".into(),
                ty: Type::String,
                value: ValueSpec::constant("done"),
            }),
            ..Default::default()
        }
        .with(IoStep {
            seen: seen.clone(),
            ..Default::default()
        })
        .unwrap();
        let flow = Flow::builder("handoff")
            .entry("a")
            .step("a", a)
            .step("b", b)
            .step("c", c)
            .build()
            .unwrap();
        let state = State::builder()
            .field("__input", "Step arguments", Type::Dynamic, json!({"root": 1}))
            .field("__output", "Step result", Type::Dynamic, json!(99))
            .field("captured_input", "Current Step arguments", Type::Dynamic, json!({}))
            .field("captured_output", "Current Step result", Type::Dynamic, json!("stale"))
            .build()
            .unwrap();
        let mut scope = Scope::new(Arc::new(flow), state, AutoCheckpointConfig::Unbounded, None);

        scope.advance().unwrap();
        assert_eq!(scope.current_step().0, "b");
        assert_eq!(scope.state().get("__input"), Some(&json!({"record": 42})));
        assert_eq!(scope.state().get("__output"), Some(&json!(42)));
        assert_eq!(scope.state().get("captured_input"), Some(&json!({"root": 1})));
        let checkpoint = scope.checkpoint();

        scope.advance().unwrap();
        assert_eq!(scope.current_step().0, "c");
        assert_eq!(scope.state().get("__input"), Some(&json!({"value": null})));
        assert_eq!(scope.state().get("__output"), Some(&JsonValue::Null));
        assert_eq!(scope.state().get("captured_input"), Some(&json!({"record": 42})));
        assert_eq!(scope.state().get("captured_output"), Some(&JsonValue::Null));

        scope.advance().unwrap();
        assert!(scope.is_finished());
        assert_eq!(scope.state().get("__input"), Some(&json!({})));
        assert_eq!(scope.state().get("__output"), Some(&json!("done")));
        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                json!({"input": {"root": 1}, "output": 99}),
                json!({"input": {"record": 42}, "output": 42}),
                json!({"input": {"value": null}, "output": null}),
            ]
        );
        assert_eq!(scope.trace().entries.len(), 3);
        assert_eq!(scope.trace().entries[0].state.get("__output"), Some(&json!(42)));
        assert_eq!(scope.trace().entries[1].state.get("__output"), Some(&JsonValue::Null));
        assert_eq!(scope.trace().entries[2].state.to_json(), scope.state().to_json());

        scope.restore(&checkpoint).unwrap();
        assert_eq!(scope.current_step().0, "b");
        assert_eq!(scope.state().get("__input"), Some(&json!({"record": 42})));
        assert_eq!(scope.state().get("__output"), Some(&json!(42)));
        assert_eq!(scope.trace().entries.len(), 1);
    }

    #[test]
    fn output_validation_rejects_invalid_turns_and_masks_previous_output() {
        for (case, value, ty, expected_error) in [
            (
                "missing_native_result",
                ValueSpec::reference(StateNamespace::Default, "__output"),
                Type::U64,
                Some("expected u64"),
            ),
            (
                "null_result",
                ValueSpec::reference(StateNamespace::Default, "__output"),
                Type::Option(Box::new(Type::U64)),
                None,
            ),
            (
                "model_output",
                ValueSpec::model("Derive output"),
                Type::U64,
                Some("model-derived output is not supported yet"),
            ),
        ] {
            let step = StructuredSpec {
                output: Some(Output {
                    description: "Result".into(),
                    ty,
                    value,
                }),
                state_updates: vec![("count".into(), ValueSpec::constant(5))],
                ..Default::default()
            }
            .with(IoStep::default())
            .expect(case);
            let flow = Flow::builder("output-validation")
                .entry("a")
                .step("a", step)
                .build()
                .expect(case);
            let state = State::builder()
                .field("__input", "Step arguments", Type::Dynamic, json!({}))
                .field("__output", "Previous result", Type::Dynamic, json!(42))
                .field("count", "Count", Type::U64, json!(0))
                .build()
                .expect(case);
            let mut scope = Scope::new(Arc::new(flow), state, AutoCheckpointConfig::Unbounded, None);
            let before = scope.state().to_json();
            let result = scope.advance();
            if let Some(expected) = expected_error {
                let error = result.expect_err(case);
                assert!(error.to_string().contains(expected), "{case}: {error}");
                assert_eq!(scope.state().to_json(), before, "{case}");
                assert!(!scope.is_finished(), "{case}");
                assert!(scope.trace().entries.is_empty(), "{case}");
            } else {
                result.expect(case);
                assert!(scope.is_finished());
                assert_eq!(scope.state().get("__output"), Some(&JsonValue::Null));
                assert_eq!(scope.state().get("count"), Some(&json!(5)));
            }
        }
    }

    #[test]
    fn flow_handoff_keeps_outer_inputs_and_exposes_child_output() {
        let child_step = StructuredSpec {
            output: Some(Output {
                description: "Child result".into(),
                ty: Type::U64,
                value: ValueSpec::constant(5),
            }),
            next_steps: routes(&[Some("done")]),
            ..Default::default()
        }
        .with(IoStep::default())
        .unwrap();
        let child = Flow::builder("child")
            .entry("work")
            .step("work", child_step)
            .exit("done")
            .build()
            .unwrap();
        let source = StructuredSpec {
            next_steps: vec![NextStep {
                step_id: Some("child".into()),
                description: "Enter child".into(),
                inputs: vec![("outer".into(), ValueSpec::constant("value"))],
            }],
            ..Default::default()
        }
        .with(IoStep::default())
        .unwrap();
        let wrapper = StructuredSpec {
            inputs: vec![Input {
                name: "outer".into(),
                description: "Outer argument".into(),
                required: true,
                ty: Type::String,
            }],
            output: Some(Output {
                description: "Flow result".into(),
                ty: Type::U64,
                value: ValueSpec::reference(StateNamespace::Default, "__output"),
            }),
            state_updates: vec![(
                "outer_inputs".into(),
                ValueSpec::reference(StateNamespace::Default, "__input"),
            )],
            next_steps: vec![NextStep {
                step_id: Some("sink".into()),
                description: "Consume result".into(),
                inputs: vec![
                    (
                        "record".into(),
                        ValueSpec::reference(StateNamespace::Default, "__output"),
                    ),
                    (
                        "original".into(),
                        ValueSpec::reference(StateNamespace::Default, "__input"),
                    ),
                ],
            }],
        }
        .with(child.clone())
        .unwrap();
        let sink = StructuredSpec {
            inputs: vec![
                Input {
                    name: "record".into(),
                    description: "Result".into(),
                    required: true,
                    ty: Type::U64,
                },
                Input {
                    name: "original".into(),
                    description: "Original arguments".into(),
                    required: true,
                    ty: Type::Mapping(Box::new(Type::String)),
                },
            ],
            ..Default::default()
        }
        .with(IoStep::default())
        .unwrap();
        let parent = Flow::builder("parent")
            .entry("source")
            .step("source", source)
            .step("sink", sink)
            .flow_with(
                "child",
                child,
                ExitTransitions::new().transition("done", "sink").unwrap(),
                TraceMode::Expanded,
                wrapper,
            )
            .build()
            .unwrap();
        let state = state_builder([])
            .field("outer_inputs", "Flow arguments", Type::Dynamic, json!({}))
            .build()
            .unwrap();
        let mut scope = Scope::new(Arc::new(parent), state, AutoCheckpointConfig::Unbounded, None);

        scope.advance().unwrap();
        assert_eq!(scope.current_step().0, "child");
        assert_eq!(scope.state().get("__input"), Some(&json!({"outer": "value"})));
        scope.advance().unwrap();
        assert_eq!(scope.current_step().0, "sink");
        assert_eq!(scope.state().get("outer_inputs"), Some(&json!({"outer": "value"})));
        assert_eq!(
            scope.state().get("__input"),
            Some(&json!({"record": 5, "original": {"outer": "value"}}))
        );
        assert_eq!(scope.state().get("__output"), Some(&json!(5)));
        assert_eq!(scope.trace().entries.len(), 2);
    }

    #[test]
    fn builder_and_json_preserve_spec() {
        let case = "all_sources_and_setter_order";
        let updates = vec![
            ("shared".into(), ValueSpec::constant(9)),
            ("copy".into(), ValueSpec::reference(StateNamespace::Default, "count")),
            ("copy_note".into(), ValueSpec::reference(StateNamespace::Input, "note")),
            ("cached".into(), ValueSpec::reference(StateNamespace::Default, "cache")),
            ("count".into(), ValueSpec::model("Derive the count")),
        ];
        let next = vec![NextStep {
            step_id: None,
            description: "Complete the Flow".into(),
            inputs: vec![],
        }];
        let spec = StructuredSpec::builder()
            .state_updates(updates.clone())
            .next_steps(next.clone())
            .build();
        let reversed = StructuredSpec::builder()
            .next_steps(next)
            .state_updates(updates)
            .build();
        let json = serde_json::to_value(&spec).expect(case);
        assert_eq!(json.as_object().expect(case).len(), 4, "{case}");
        assert_eq!(
            json["next_steps"],
            json!([{"step_id": null, "description": "Complete the Flow", "inputs": []}]),
            "{case}"
        );
        assert_eq!(
            json["state_updates"][1][1],
            json!({"source": "state", "namespace": "default", "field": "count"}),
            "{case}"
        );
        assert_eq!(serde_json::to_value(reversed).expect(case), json, "{case}");
        let restored: StructuredSpec = serde_json::from_value(json.clone()).expect(case);
        assert_eq!(serde_json::to_value(&restored).expect(case), json, "{case}");
        restored.with(TestStep::default()).expect(case);
        let empty = StructuredSpec::builder().next_steps(vec![]).build();
        let expected = serde_json::to_value(StructuredSpec::default()).unwrap();
        assert_eq!(expected["next_steps"], json!([]));
        assert_eq!(serde_json::to_value(empty).unwrap(), expected);
        for definition in [json!({}), json!({"next_steps": []})] {
            let spec: StructuredSpec = serde_json::from_value(definition).expect("empty_next");
            assert_eq!(serde_json::to_value(&spec).unwrap(), expected, "empty_next");
            spec.with(TestStep::default()).expect("empty_next");
        }
        for field in ["description", "template", "input", "summary", "next"] {
            assert!(
                serde_json::from_value::<StructuredSpec>(json!({(field): null})).is_err(),
                "unknown_field/{field}"
            );
        }
    }

    #[test]
    fn structured_updates_preserve_nested_json_objects() {
        let value = json!({"z": u64::MAX, "nested": {"b": [null, true], "a": 1.0}});
        for source in [
            ValueSpec::constant(value.clone()),
            ValueSpec::reference(StateNamespace::Default, "source"),
        ] {
            let step = StructuredSpec {
                state_updates: vec![("target".into(), source)],
                ..Default::default()
            }
            .with(TestStep {
                mode: Mode::End,
                ..Default::default()
            })
            .unwrap();
            let flow = Flow::builder("json-objects")
                .entry("copy")
                .step("copy", step)
                .build()
                .unwrap();
            let mapping = lyquid_flow::Type::Mapping(Box::new(lyquid_flow::Type::Dynamic));
            let state = state_builder([])
                .field("source", "Committed source", mapping.clone(), value.clone())
                .field("target", "Copied object", mapping, json!({}))
                .build()
                .unwrap();
            let mut scope = Scope::new(Arc::new(flow), state, AutoCheckpointConfig::Unbounded, None);
            scope.advance().unwrap();
            let copied = scope.state().get("target").unwrap();
            assert_eq!(copied, &value);
            assert_eq!(copied["z"].as_u64(), Some(u64::MAX));
            assert!(copied["nested"]["a"].is_f64());
            assert_eq!(copied.to_string(), value.to_string());
        }
    }

    #[test]
    fn mounted_flow_applies_structured_rules_after_child_completion() {
        let child = Flow::builder("child")
            .entry("native")
            .step("native", TestStep::default())
            .exit("after")
            .build()
            .unwrap();
        let spec = StructuredSpec {
            state_updates: vec![("shared".into(), ValueSpec::constant(9))],
            next_steps: routes(&[Some("selected")]),
            ..Default::default()
        };
        let parent = Flow::builder("parent")
            .entry("child")
            .exit("native_done")
            .exit("selected")
            .flow_with(
                "child",
                child.clone(),
                ExitTransitions::new().transition("after", "native_done").unwrap(),
                TraceMode::Expanded,
                spec.with(child).unwrap(),
            )
            .build()
            .unwrap();
        let state = state_builder([])
            .field("count", "Business count", lyquid_flow::Type::U64, json!(2_u64))
            .field("seed", "Native seed", lyquid_flow::Type::U64, json!(0_u64))
            .field("shared", "Explicitly replaceable", lyquid_flow::Type::U64, json!(0_u64))
            .field("cache", "Native cache", lyquid_flow::Type::String, json!(""))
            .build()
            .unwrap();
        let mut scope = Scope::new(Arc::new(parent), state, AutoCheckpointConfig::Unbounded, None);

        scope.advance().unwrap();

        assert!(scope.is_finished());
        assert_eq!(scope.current_step().0, "selected");
        assert_eq!(scope.state().get("count"), Some(&json!(11)));
        assert_eq!(scope.state().get("shared"), Some(&json!(9)));
    }

    #[test]
    fn configured_updates_override_native_values() {
        let configured = vec![
            ("shared".into(), ValueSpec::constant(9)),
            ("copy".into(), ValueSpec::reference(StateNamespace::Default, "count")),
            (
                "sibling".into(),
                ValueSpec::reference(StateNamespace::Default, "shared"),
            ),
            (
                "copy_note".into(),
                ValueSpec::reference(StateNamespace::Default, "cache"),
            ),
            (
                "input_note".into(),
                ValueSpec::reference(StateNamespace::Default, "copy_note"),
            ),
        ];
        for (case, rules) in [
            ("finalized_state", configured.clone()),
            ("reversed_updates", configured.into_iter().rev().collect()),
        ] {
            let step = StructuredSpec {
                state_updates: rules,
                ..Default::default()
            }
            .with(TestStep::default())
            .expect(case);
            let mut scope = new_scope(step, None);
            scope.advance().expect(case);
            for (field, expected) in [("count", 11), ("shared", 9), ("seed", 4), ("copy", 11), ("sibling", 3)] {
                assert_eq!(
                    scope.state().get(field).and_then(serde_json::Value::as_u64),
                    Some(expected),
                    "{case}/{field}"
                );
            }
            assert_eq!(scope.state().get("copy_note"), Some(&json!("native cache")), "{case}");
            assert_eq!(scope.state().get("input_note"), Some(&json!("")), "{case}");
            assert_eq!(scope.trace().entries.len(), 1, "{case}");
            assert_eq!(
                scope.trace().entries[0].state.to_json(),
                scope.state().to_json(),
                "{case}"
            );
        }
        for (case, model_value, expected) in [("model_present", Some(42_u64), 42), ("model_omitted", None, 11)] {
            let calls = Arc::new(Calls::default());
            let step = StructuredSpec {
                state_updates: vec![
                    ("count".into(), ValueSpec::model("Choose the count")),
                    ("shared".into(), ValueSpec::constant(9)),
                ],
                ..Default::default()
            }
            .with(TestStep {
                calls: calls.clone(),
                mode: Mode::Model,
                ..Default::default()
            })
            .expect(case);
            let scope = new_scope(step.clone(), None);
            let TemplateSpec::Template(template) = step.model_template(&scope) else {
                panic!("{case}: expected Template")
            };
            assert_eq!(
                template
                    .state_update_criteria
                    .iter()
                    .map(|(field, criterion)| (field.as_str(), criterion.as_str()))
                    .collect::<Vec<_>>(),
                vec![("shared", "Native shared criterion"), ("count", "Choose the count")],
                "{case}: replace model criteria while retaining native criteria for constant fields"
            );
            let mut updates = StateUpdates::default();
            updates.set("shared".into(), Some(json!(50_u64)));
            if let Some(value) = model_value {
                updates.set("count".into(), Some(json!(value)));
            }
            let mut proposal = TurnProposal::Advance {
                next: Some("after".into()),
                updates,
            };
            // Inject an already-decoded proposal to test rule merging, without a model call.
            step.finalize_proposal(&scope, &mut proposal, true).expect(case);
            let TurnProposal::Advance { updates, .. } = proposal else {
                panic!("{case}: expected Advance")
            };
            assert_eq!(
                updates.get("count").and_then(serde_json::Value::as_u64),
                Some(expected),
                "{case}"
            );
            assert_eq!(
                updates.get("shared").and_then(serde_json::Value::as_u64),
                Some(9),
                "{case}"
            );
            assert_eq!(*calls.shared_before_finalize.lock().unwrap(), Some(50), "{case}");
            assert_eq!(calls.templates.load(Ordering::SeqCst), 1, "{case}");
            assert_eq!(calls.finalizers.load(Ordering::SeqCst), 1, "{case}");
        }
        for (case, rules, expected) in [
            (
                "wrong_type",
                vec![("count".into(), ValueSpec::constant("wrong"))],
                "invalid State update count",
            ),
            (
                "missing_reference",
                vec![("count".into(), ValueSpec::reference(StateNamespace::Default, "missing"))],
                "missing State reference default.missing",
            ),
            (
                "unknown_target",
                vec![("missing".into(), ValueSpec::constant(5))],
                "unknown State update",
            ),
        ] {
            let step = StructuredSpec {
                state_updates: rules,
                ..Default::default()
            }
            .with(TestStep::default())
            .expect(case);
            let scope = new_scope(step.clone(), None);
            let TemplateSpec::Skip(mut proposal) = step.model_template(&scope) else {
                panic!("{case}: expected Skip")
            };
            let error = step.finalize(&scope, &mut proposal).err().expect(case);
            assert!(
                matches!(&error, FlowError::Execution(diagnostics) if diagnostics.to_string().contains(expected)),
                "{case}: {error}"
            );
            if case == "wrong_type" {
                let validation_error = std::error::Error::source(&error).unwrap();
                assert!(validation_error.is::<lyquid_flow::types::Error>(), "{case}");
            }
        }
        let requests = Arc::new(Mutex::new(Vec::new()));
        for (case, model) in [
            ("skip_model_value_without_backend", None),
            ("skip_model_value_with_backend", Some(capture_model(requests.clone()))),
        ] {
            let step = StructuredSpec {
                state_updates: vec![("count".into(), ValueSpec::model("Choose the count"))],
                ..Default::default()
            }
            .with(TestStep::default())
            .expect(case);
            let error = new_scope(step, model).advance().unwrap_err();
            assert!(
                matches!(&error, FlowError::Execution(diagnostics)
                    if diagnostics.to_string() == "structured model rules require the wrapped Step to return a model template"),
                "{case}: {error}"
            );
            assert!(requests.lock().unwrap().is_empty(), "{case}");
        }
    }

    #[test]
    fn configured_next_overrides_native_route() {
        let fixed = routes(&[Some("selected")]);
        let choices = vec![
            NextStep {
                step_id: Some("done".into()),
                description: "Ready".into(),
                inputs: vec![],
            },
            NextStep {
                step_id: None,
                description: "Complete".into(),
                inputs: vec![],
            },
        ];
        for (case, mode, next, selected, expected) in [
            ("skip_empty", Mode::Direct, vec![], None, Ok(Some("after"))),
            ("skip_fixed", Mode::Direct, fixed, None, Ok(Some("selected"))),
            ("skip_complete", Mode::Direct, routes(&[None]), None, Ok(None)),
            ("model_empty", Mode::Model, vec![], Some("after"), Ok(Some("selected"))),
            (
                "model_choice",
                Mode::Model,
                choices.clone(),
                Some("done"),
                Ok(Some("done")),
            ),
            ("model_complete", Mode::Model, choices.clone(), None, Ok(None)),
            (
                "undeclared_route",
                Mode::Model,
                choices.clone(),
                Some("after"),
                Err(("", "model selected an undeclared next Step")),
            ),
            (
                "unknown_route",
                Mode::Direct,
                routes(&[Some("missing")]),
                None,
                Err(("next Step missing", "unknown destination")),
            ),
        ] {
            let configured_next = !next.is_empty();
            let step = StructuredSpec {
                next_steps: next,
                ..Default::default()
            }
            .with(TestStep {
                mode,
                ..Default::default()
            })
            .expect(case);
            let scope = new_scope(step.clone(), None);
            let (mut proposal, model_called) = match step.model_template(&scope) {
                TemplateSpec::Skip(proposal) => (proposal, false),
                TemplateSpec::Template(template) => {
                    let expected = if configured_next {
                        vec![(Some("done"), "Ready"), (None, "Complete")]
                    } else {
                        vec![(Some("after"), "Native route")]
                    };
                    assert_eq!(
                        template
                            .next_step_criteria
                            .iter()
                            .map(|(next, criterion)| (next.as_ref().map(|next| next.0.as_str()), criterion.as_str()))
                            .collect::<Vec<_>>(),
                        expected,
                        "{case}: configured destinations replace native candidates"
                    );
                    (
                        TurnProposal::Advance {
                            next: selected.map(Into::into),
                            updates: StateUpdates::default(),
                        },
                        true,
                    )
                }
            };
            // Model cases inject decoded proposals; this test only exercises routing rules.
            let result = step.finalize_proposal(&scope, &mut proposal, model_called);
            match expected {
                Ok(expected) => {
                    result.expect(case);
                    let TurnProposal::Advance { next, .. } = proposal else {
                        panic!("{case}: expected Advance")
                    };
                    assert_eq!(next.as_ref().map(|id| id.0.as_str()), expected, "{case}");
                }
                Err((context, message)) => {
                    let error = result.err().expect(case);
                    assert!(
                        matches!(&error, FlowError::Execution(diagnostics)
                            if matches!(diagnostics.diagnostics.as_slice(), [diagnostic]
                                if diagnostic.context == context && diagnostic.message == message)),
                        "{case}: {error}"
                    );
                }
            }
        }
        let case = "skip_multiple_destinations";
        let requests = Arc::new(Mutex::new(Vec::new()));
        let step = StructuredSpec {
            next_steps: choices,
            ..Default::default()
        }
        .with(TestStep::default())
        .expect(case);
        let error = new_scope(step, Some(capture_model(requests.clone())))
            .advance()
            .unwrap_err();
        assert!(
            matches!(&error, FlowError::Execution(diagnostics)
                if diagnostics.to_string() == "structured model rules require the wrapped Step to return a model template"),
            "{case}: {error}"
        );
        assert!(requests.lock().unwrap().is_empty(), "{case}");
    }

    #[test]
    fn wrapper_preserves_step_behavior_and_restore() {
        let input = input_spec();
        let restored: InputSpec = serde_json::from_value(serde_json::to_value(&input).unwrap()).unwrap();
        let reference = StructuredSpec {
            state_updates: vec![("copy_note".into(), ValueSpec::reference(StateNamespace::Input, "note"))],
            ..Default::default()
        };
        for (case, spec, input, expected_copy) in [
            ("empty_rules", StructuredSpec::default(), input.clone(), ""),
            ("native_input", reference.clone(), input, "hello"),
            ("json_input", reference, restored, "hello"),
        ] {
            let calls = Arc::new(Calls::default());
            let step = spec
                .with(TestStep {
                    calls: calls.clone(),
                    input: Some(input),
                    ..Default::default()
                })
                .expect(case);
            assert_eq!(
                (step.description(false), step.description(true)),
                ("Native business Step".to_owned(), "Native".to_owned()),
                "{case}"
            );
            let mut scope = new_scope(step, None);
            let (input, _) = scope.run_until_input().expect(case).expect(case);
            assert_eq!(input.schema(), input_spec().schema(), "{case}");
            assert_eq!(calls.templates.load(Ordering::SeqCst), 0, "{case}");
            scope.input_handle().submit_input(r#"{"note":"hello"}"#).expect(case);
            scope.advance().expect(case);
            assert_eq!(
                scope.state().to_json(),
                json!({
                    "__input": {}, "__output": null,
                    "count": 11, "seed": 4, "shared": 3, "copy": 0, "sibling": 99,
                    "input_note": "hello", "copy_note": expected_copy,
                    "cache": "native cache",
                }),
                "{case}"
            );
            assert!(scope.get(StateNamespace::Input, "note").is_none(), "{case}");
            assert_eq!(scope.current_step().0, "after", "{case}");
            assert_eq!(
                (
                    calls.inputs.load(Ordering::SeqCst),
                    calls.templates.load(Ordering::SeqCst),
                    calls.finalizers.load(Ordering::SeqCst),
                    calls.contexts.load(Ordering::SeqCst)
                ),
                (1, 1, 1, 0),
                "{case}"
            );
            assert_eq!(scope.trace().entries.len(), 1, "{case}");
            assert!(
                matches!(&scope.trace().entries[0].summary, TraceSummary::Summary(text) if text == "Native summary"),
                "{case}"
            );
        }

        let case = "model_context";
        let step = StructuredSpec::default()
            .with(TestStep {
                mode: Mode::Model,
                ..Default::default()
            })
            .expect(case);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let mut scope = new_scope(step, Some(capture_model(requests.clone())));
        let error = scope.advance().unwrap_err();
        assert!(matches!(error, FlowError::Model(_)), "{case}: {error}");
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1, "{case}");
        let request = &requests[0];
        assert!(
            request.prompt.contains("Native goal: native context; count=2"),
            "{case}"
        );
        assert!(request.prompt.contains("Native route"), "{case}");
        let system = request.system.as_ref().expect(case);
        let contract: JsonValue = serde_json::from_str(&system[system.find('{').expect(case)..]).expect(case);
        assert!(contract.get("restore").is_some(), "{case}");

        let case = "restore_bypasses_rules";
        let mut scope = new_scope(TestStep::default(), None);
        let checkpoint = scope.checkpoint();
        let step = StructuredSpec {
            state_updates: vec![("undeclared".into(), ValueSpec::model("Ignored after restore"))],
            next_steps: routes(&[Some("undeclared")]),
            ..Default::default()
        }
        .with(TestStep {
            mode: Mode::Restore(checkpoint.clone()),
            ..Default::default()
        })
        .expect(case);
        let TemplateSpec::Skip(mut proposal) = step.model_template(&scope) else {
            panic!("{case}: expected Skip")
        };
        let summary = step.finalize(&scope, &mut proposal).expect(case);
        assert!(
            matches!(proposal, TurnProposal::Restore { scope } if scope.0 == checkpoint.0),
            "{case}"
        );
        assert!(
            matches!(summary, TraceSummary::Summary(text) if text == "Native restore"),
            "{case}"
        );
    }

    #[test]
    fn failed_rules_leave_turn_uncommitted() {
        let step = StructuredSpec {
            // The first structured update succeeds, then the unknown field fails.
            state_updates: vec![
                ("count".into(), ValueSpec::constant(5)),
                ("missing".into(), ValueSpec::constant(5)),
            ],
            ..Default::default()
        }
        .with(TestStep::default())
        .unwrap();
        let mut scope = new_scope(step, None);
        let before = (
            scope.state().to_json(),
            scope.current_step().0.clone(),
            scope.trace().entries.len(),
            scope.checkpoint_ids().map(ToString::to_string).collect::<Vec<_>>(),
        );
        let error = scope.advance().unwrap_err();
        assert!(
            matches!(&error, FlowError::Execution(diagnostics) if diagnostics.to_string().contains("unknown State update")),
            "{error}"
        );
        assert_eq!(
            (
                scope.state().to_json(),
                scope.current_step().0.clone(),
                scope.trace().entries.len(),
                scope.checkpoint_ids().map(ToString::to_string).collect::<Vec<_>>(),
            ),
            before
        );
    }

    #[test]
    fn model_failure_retries_without_finalizing() {
        let calls = Arc::new(Calls::default());
        let step = StructuredSpec {
            state_updates: vec![("count".into(), ValueSpec::model("Choose the count"))],
            ..Default::default()
        }
        .with(TestStep {
            calls: calls.clone(),
            mode: Mode::Model,
            ..Default::default()
        })
        .unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let mut scope = new_scope(step, Some(capture_model(requests.clone())));
        for (case, attempts) in [("first_attempt", 1), ("retry", 2)] {
            let error = scope.advance().unwrap_err();
            assert!(
                matches!(&error, FlowError::Model(error) if error.to_string().contains("captured before HTTP")),
                "{case}: {error}"
            );
            assert_eq!(requests.lock().unwrap().len(), attempts, "{case}");
            assert_eq!(
                (
                    calls.templates.load(Ordering::SeqCst),
                    calls.contexts.load(Ordering::SeqCst),
                    calls.finalizers.load(Ordering::SeqCst)
                ),
                (attempts, attempts, 0),
                "{case}"
            );
        }
    }
}
