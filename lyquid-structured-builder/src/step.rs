use std::sync::Arc;

use lyquid_flow::{FlowError, InputSpec, Scope, Step, TemplateSpec, TraceSummary, TurnProposal, ViewSpec};
use serde_json::Value as JsonValue;

use crate::{NextStep, StructuredSpec, ValueSource};

/// Adds structured model criteria and final State updates to an existing Step.
#[derive(Clone)]
pub struct StructuredStep {
    pub(super) inner: Arc<dyn Step>,
    pub(super) spec: StructuredSpec,
}

impl StructuredStep {
    fn needs_model(&self) -> bool {
        self.spec.next.as_ref().is_some_and(NextStep::needs_model) ||
            self.spec.state_updates.iter().any(|(_, value)| value.is_model())
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
        if let Some(destinations) = &self.spec.next {
            for destination in destinations.destinations() {
                scope.validate_next(&destination)?;
            }
            *next = if destinations.steps.len() == 1 {
                destinations.steps[0].next.clone()
            } else if let Some(selected) = selected &&
                destinations.steps.iter().any(|case| case.next == selected)
            {
                selected
            } else {
                return Err("model selected an undeclared next Step".to_owned().into());
            };
        }
        // Every source reads the current State, independently of other proposed updates.
        for (field, source) in &self.spec.state_updates {
            let declaration = scope
                .state()
                .declared_type(field)
                .ok_or_else(|| format!("unknown State update {field:?}"))?;
            if let Some(value) = source.read(scope)? {
                declaration
                    .validate(&value)
                    .map_err(|error| FlowError::context(format!("invalid State update {field}"), error))?;
                updates.set(field.clone(), Some(value));
            }
        }
        for (field, value) in model_updates {
            updates.set(field, Some(value));
        }
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

    fn view(&self, scope: &Scope) -> Result<ViewSpec, FlowError> {
        self.inner.view(scope)
    }

    fn model_template(&self, scope: &Scope) -> TemplateSpec {
        let mut template = match self.inner.model_template(scope) {
            TemplateSpec::Template(template) => template,
            direct => return direct,
        };
        if let Some(next) = &self.spec.next {
            template.next_step_criteria = next
                .steps
                .iter()
                .map(|case| (case.next.clone(), case.description.clone()))
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
                        ValueSource::Model { description } => Some((field.clone(), description.clone())),
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
        AutoCheckpointConfig, Flow, FlowError, InputSpec, ModelTemplate, Scope, ScopeId, State, StateNamespace,
        StateUpdates, Step, TemplateSpec, TraceSummary, TurnProposal, ViewSpec,
    };
    use lyquid_llm::{
        Backend, JsonApiResponse, LlmError, LlmResult, ModelConfig, ModelRequest, ModelResponse, PreparedJsonApiRequest,
    };
    use lyquid_test::test;
    use serde_json::{Value as JsonValue, json};

    use crate::{NextCase, NextStep, StructuredSpec, ValueSource};

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

        fn view(&self, scope: &Scope) -> Result<ViewSpec, FlowError> {
            let ui = ViewSpec::builder();
            ui.data(
                "native",
                json!({"count": scope.state().get("count").and_then(serde_json::Value::as_u64)}),
            );
            Ok(ViewSpec::finish(&ui, ui.text("Native result"))?)
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
                updates.set_in(
                    StateNamespace::Tool,
                    "cache".into(),
                    Some(json!("native cache".to_owned())),
                );
                if let Some(note) = scope.get(StateNamespace::Input, "note") {
                    updates.set("input_note".into(), Some(note.clone()));
                }
            }
            Ok(TraceSummary::Summary("Native summary".into()))
        }
    }

    fn input_spec() -> InputSpec {
        let mut builder = InputSpec::builder();
        let note = builder.field::<String>("note", "Native note").non_blank().text_input();
        let submit = builder.submit("Continue");
        let root = builder.ui().column(vec![note, submit]);
        builder.finish(root).unwrap()
    }

    fn routes(targets: &[Option<&str>]) -> NextStep {
        NextStep {
            steps: targets
                .iter()
                .map(|target| NextCase {
                    next: target.map(Into::into),
                    description: "Continue".into(),
                })
                .collect(),
        }
    }

    fn new_scope(step: impl Step, model: Option<ModelConfig>) -> Scope {
        let state = State::builder()
            .field("count", "Business count", lyquid_flow::Type::U64, json!(2_u64))
            .field("seed", "Native seed", lyquid_flow::Type::U64, json!(0_u64))
            .field("shared", "Explicitly replaceable", lyquid_flow::Type::U64, json!(0_u64))
            .field("copy", "Original count", lyquid_flow::Type::U64, json!(0_u64))
            .field(
                "sibling",
                "Original shared value",
                lyquid_flow::Type::U64,
                json!(99_u64),
            )
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
            .field_in(
                StateNamespace::Tool,
                "cache",
                "Native tool data",
                lyquid_flow::Type::String,
                json!(""),
            )
            .build()
            .unwrap();
        let flow = Flow::builder("structured-test")
            .entry("wrapped")
            .step("wrapped", step)
            .step(
                "after",
                TestStep {
                    mode: Mode::End,
                    ..Default::default()
                },
            )
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
    fn spec_rejects_invalid_rules() {
        for (case, state_updates, next, expected) in [
            (
                "duplicate_update",
                vec![
                    ("count".into(), ValueSource::constant(1)),
                    ("count".into(), ValueSource::constant(2)),
                ],
                None,
                "duplicate State update",
            ),
            (
                "blank_reference",
                vec![("count".into(), ValueSource::reference(StateNamespace::Default, " \t"))],
                None,
                "State reference: must be nonblank",
            ),
            (
                "blank_model",
                vec![("count".into(), ValueSource::model(""))],
                None,
                "model description: must be nonblank",
            ),
            (
                "invalid_template",
                vec![("count".into(), ValueSource::model("{{"))],
                None,
                "invalid count template",
            ),
            (
                "empty_destinations",
                vec![],
                Some(routes(&[])),
                "at least one next Step is required",
            ),
            (
                "duplicate_destination",
                vec![],
                Some(routes(&[None, None])),
                "duplicate next Step",
            ),
        ] {
            let error = StructuredSpec { state_updates, next }
                .with(TestStep::default())
                .err()
                .expect(case);
            assert!(error.to_string().contains(expected), "{case}: {error}");
            if case == "invalid_template" {
                assert!(error.0.diagnostics[0].source.as_ref().unwrap().is::<tera::Error>());
            }
        }
        let flow = Flow::builder("child")
            .entry("end")
            .step(
                "end",
                TestStep {
                    mode: Mode::End,
                    ..Default::default()
                },
            )
            .build()
            .unwrap();
        let error = StructuredSpec::default().with(flow).err().expect("flow_wrapper");
        assert!(
            error.to_string().contains("cannot wrap a Flow"),
            "flow_wrapper: {error}"
        );
    }

    #[test]
    fn builder_and_json_preserve_spec() {
        let case = "all_sources_and_setter_order";
        let updates = vec![
            ("shared".into(), ValueSource::constant(9)),
            ("copy".into(), ValueSource::reference(StateNamespace::Default, "count")),
            (
                "copy_note".into(),
                ValueSource::reference(StateNamespace::Input, "note"),
            ),
            ("cached".into(), ValueSource::reference(StateNamespace::Tool, "cache")),
            ("count".into(), ValueSource::model("Derive the count")),
        ];
        let spec = StructuredSpec::builder()
            .state_updates(updates.clone())
            .next(NextStep::default())
            .build();
        let reversed = StructuredSpec::builder()
            .next(NextStep::default())
            .state_updates(updates)
            .build();
        let json = serde_json::to_value(&spec).expect(case);
        assert_eq!(json.as_object().expect(case).len(), 2, "{case}");
        assert_eq!(
            json["next"],
            json!({"steps": [{"next": null, "description": "Complete the Flow"}]}),
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
        let empty: StructuredSpec = serde_json::from_str("{}").expect("empty_spec");
        assert_eq!(
            serde_json::to_value(empty).unwrap(),
            serde_json::to_value(StructuredSpec::default()).unwrap(),
            "empty_spec"
        );
        for field in ["description", "template", "input", "summary"] {
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
            ValueSource::constant(value.clone()),
            ValueSource::reference(StateNamespace::Default, "source"),
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
            let state = State::builder()
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
    fn configured_updates_override_native_values() {
        let configured = vec![
            ("shared".into(), ValueSource::constant(9)),
            ("copy".into(), ValueSource::reference(StateNamespace::Default, "count")),
            (
                "sibling".into(),
                ValueSource::reference(StateNamespace::Default, "shared"),
            ),
        ];
        for (case, rules) in [
            ("current_state", configured.clone()),
            ("reversed_updates", configured.into_iter().rev().collect()),
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
            step.finalize(&scope, &mut proposal).expect(case);
            let TurnProposal::Advance { updates, .. } = proposal else {
                panic!("{case}: expected Advance")
            };
            for (field, expected) in [("count", 11), ("shared", 9), ("seed", 4), ("copy", 2), ("sibling", 0)] {
                assert_eq!(
                    updates.get(field).and_then(serde_json::Value::as_u64),
                    Some(expected),
                    "{case}/{field}"
                );
            }
        }
        for (case, model_value, expected) in [("model_present", Some(42_u64), 42), ("model_omitted", None, 11)] {
            let calls = Arc::new(Calls::default());
            let step = StructuredSpec {
                state_updates: vec![
                    ("count".into(), ValueSource::model("Choose the count")),
                    ("shared".into(), ValueSource::constant(9)),
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
                vec![("count".into(), ValueSource::constant("wrong"))],
                "invalid State update count",
            ),
            (
                "missing_reference",
                vec![(
                    "count".into(),
                    ValueSource::reference(StateNamespace::Default, "missing"),
                )],
                "missing State reference default.missing",
            ),
            (
                "unknown_target",
                vec![("missing".into(), ValueSource::constant(5))],
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
                state_updates: vec![("count".into(), ValueSource::model("Choose the count"))],
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
        let choices = NextStep {
            steps: vec![
                NextCase {
                    next: Some("done".into()),
                    description: "Ready".into(),
                },
                NextCase {
                    next: None,
                    description: "Complete".into(),
                },
            ],
        };
        for (case, mode, next, selected, expected) in [
            ("skip_native", Mode::Direct, None, None, Ok(Some("after"))),
            ("skip_fixed", Mode::Direct, Some(fixed), None, Ok(Some("selected"))),
            ("skip_complete", Mode::Direct, Some(NextStep::default()), None, Ok(None)),
            ("model_native", Mode::Model, None, Some("after"), Ok(Some("selected"))),
            (
                "model_choice",
                Mode::Model,
                Some(choices.clone()),
                Some("done"),
                Ok(Some("done")),
            ),
            ("model_complete", Mode::Model, Some(choices.clone()), None, Ok(None)),
            (
                "undeclared_route",
                Mode::Model,
                Some(choices.clone()),
                Some("after"),
                Err(("", "model selected an undeclared next Step")),
            ),
            (
                "unknown_route",
                Mode::Direct,
                Some(routes(&[Some("missing")])),
                None,
                Err(("next Step missing", "unknown destination")),
            ),
        ] {
            let configured_next = next.is_some();
            let step = StructuredSpec {
                next,
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
            next: Some(choices),
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
            state_updates: vec![(
                "copy_note".into(),
                ValueSource::reference(StateNamespace::Input, "note"),
            )],
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
            assert_eq!(scope.view().expect(case).ui().data()["native"]["count"], 2, "{case}");
            let (input, _) = scope.run_until_input().expect(case).expect(case);
            assert_eq!(input.schema(), input_spec().schema(), "{case}");
            assert_eq!(calls.templates.load(Ordering::SeqCst), 0, "{case}");
            scope.input_handle().submit_input(r#"{"note":"hello"}"#).expect(case);
            scope.advance().expect(case);
            assert_eq!(
                scope.state().to_json(),
                json!({
                    "count": 11, "seed": 4, "shared": 3, "copy": 0, "sibling": 99,
                    "input_note": "hello", "copy_note": expected_copy,
                }),
                "{case}"
            );
            assert_eq!(
                scope.state().to_json_in(StateNamespace::Tool),
                json!({"cache": "native cache"}),
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
            assert_eq!(scope.view().expect(case).ui().data()["native"]["count"], 11, "{case}");
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
            state_updates: vec![("undeclared".into(), ValueSource::model("Ignored after restore"))],
            next: Some(routes(&[Some("undeclared")])),
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
                ("count".into(), ValueSource::constant(5)),
                ("missing".into(), ValueSource::constant(5)),
            ],
            ..Default::default()
        }
        .with(TestStep::default())
        .unwrap();
        let mut scope = new_scope(step, None);
        let before = (
            scope.state().to_json(),
            scope.state().to_json_in(StateNamespace::Tool),
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
                scope.state().to_json_in(StateNamespace::Tool),
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
            state_updates: vec![("count".into(), ValueSource::model("Choose the count"))],
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
