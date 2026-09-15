use lyquid_llm::ModelRequest;
use serde_json::{Map as JsonMap, Value as JsonValue, json};
use tera::{Context, Tera};

use crate::scope::Scope;
use crate::state::{State, StateNamespace, StateUpdates};
use crate::step::StepId;
use crate::trace::{Trace, TraceSummary};
use crate::turn::TurnProposal;

/// Rendering values used to complete one Step-owned template.
pub(super) struct PromptContext<'a> {
    /// Flow-level purpose supplied to the model.
    pub(super) flow_description: &'a str,
    /// Current execution State and Trace exposed to the prompt.
    pub(super) scope: &'a Scope,
    /// Valid local transitions and their model-facing descriptions for this execution.
    pub(super) next_options: Vec<(Option<StepId>, String)>,
}

/// Builds the complete model request for one template-backed Step.
pub(super) fn build_request(model: &str, template: String, context: PromptContext<'_>) -> Result<ModelRequest, String> {
    let PromptContext {
        flow_description,
        scope,
        next_options,
    } = context;

    let prompt = render(scope, &template)
        .map_err(|error| format!("failed to render prompt for Step {}: {error}", scope.current_step()))?;
    let response_contract = response_contract(scope, &next_options)?;
    let flow_description = match flow_description {
        "" => "Execute the current Flow.",
        description => description,
    };
    let flow_context = format!(
        "# Flow\n{flow_description}\n\n# Response contract\nReturn exactly one JSON object matching this contract:\n{response_contract}"
    );
    Ok(ModelRequest::new(model, prompt).system(flow_context))
}

/// Parses a model response into a proposed local Advance or Restore.
pub(super) fn parse_response(state: &State, output: &str) -> Result<TurnProposal, String> {
    let output: JsonValue = serde_json::from_str(output).map_err(|error| format!("invalid model output: {error}"))?;

    let proposal_type = output
        .get("type")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| "model output `type` must be `advance` or `restore`".to_owned())?;
    if proposal_type == "restore" {
        if output.get("next").is_some() || output.get("updates").is_some() {
            return Err("Restore model output must not include `next` or `updates`".to_owned());
        }
        let scope = output
            .get("scope")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "Restore model output `scope` must be a Scope checkpoint ID".to_owned())?;
        return Ok(TurnProposal::Restore { scope: scope.into() });
    }
    if proposal_type != "advance" {
        return Err("model output `type` must be `advance` or `restore`".to_owned());
    }
    if output.get("scope").is_some() {
        return Err("Advance model output must not include `scope`".to_owned());
    }

    let next = match output.get("next") {
        Some(JsonValue::String(next)) => Some(StepId::from(next.as_str())),
        Some(JsonValue::Null) => None,
        _ => return Err("model output `next` must be a Step ID or null".to_owned()),
    };

    let proposed_updates = output
        .get("updates")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| "model output `updates` must be an object".to_owned())?;

    let mut updates = StateUpdates::default();
    for (name, encoded) in proposed_updates {
        let field = state
            .fields
            .get(name)
            .ok_or_else(|| format!("unknown State field {name}"))?;
        let value = field.value.decode(&encoded.to_string())?;
        updates.set(name.clone(), Some(value));
    }
    Ok(TurnProposal::Advance { next, updates })
}

/// Renders the current Step's Tera template.
///
/// ```text
/// step_prompt = render(template, {
///     state: current_state,
///     input: current_input,
///     trace: selected_trace,
/// })
/// ```
///
/// The Tera template receives committed State, current input, and the complete local `trace` in
/// chronological order:
///
/// Ordinary committed fields are exposed as `state.<name>`, such as `state.summary`.
/// Current input bindings are exposed as `input.<name>`, such as `input.answer`.
///
/// `trace = [{ first.step, first.state, first.summary }, ...]`
///
fn render(scope: &Scope, template: &str) -> Result<String, String> {
    let mut context = Context::new();
    context.insert("state", &state_json(scope.state())?);
    context.insert("input", &input_json(scope.updates())?);
    context.insert("trace", &trace_json(scope.trace())?);
    Tera::one_off(template, &context, false).map_err(|error| format!("{error:#}"))
}

/// Builds the model response contract from valid local transitions and State fields.
fn response_contract(scope: &Scope, next_options: &[(Option<StepId>, String)]) -> Result<String, String> {
    let state = scope.state();
    let update_fields = state
        .fields
        .iter()
        .map(|(name, field)| {
            Ok((
                name.clone(),
                json!({
                    "description": field.description,
                    "value": parse_encoded(&field.value.encode(), name)?,
                }),
            ))
        })
        .collect::<Result<JsonMap<_, _>, String>>()?;
    let next_options = next_options
        .iter()
        .map(|(next, description)| {
            json!({
                "value": next.as_ref().map(|next| &next.0),
                "description": description,
            })
        })
        .collect::<Vec<_>>();
    let mut checkpoint_options = scope.checkpoint_ids().collect::<Vec<_>>();
    checkpoint_options.sort();
    let checkpoint_options = checkpoint_options
        .into_iter()
        .map(|id| {
            json!({
                "value": id.0,
                "description": format!("Restore Scope checkpoint {id}"),
            })
        })
        .collect::<Vec<_>>();
    // TODO: Use provider-native structured output / JSON Schema to enforce the model response format.
    let response_contract = json!({
        "advance": {
            "description": "Return `{\"type\":\"advance\",\"next\":...,\"updates\":{...}}` to advance.",
            "next": {
                "description": concat!(
                    "Return `next` as exactly one raw value from `options[].value`. ",
                    "Return the value itself, not the `{description, value}` option descriptor."
                ),
                "options": next_options,
            },
            "updates": {
                "description": concat!(
                    "Return `updates` as a JSON object mapping field names to new replacement values. ",
                    "Use only keys from `fields`; omit unchanged fields. Each value must have the same JSON type ",
                    "as `fields[key].value`. Return the raw value, not the `{description, value}` descriptor."
                ),
                "fields": update_fields,
            },
        },
        "restore": {
            "description": "Return `{\"type\":\"restore\",\"scope\":...}` to restore one available Scope.",
            "scope": {
                "description": "Return `scope` as exactly one raw value from `options[].value`.",
                "options": checkpoint_options,
            },
        },
    });
    Ok(serde_json::to_string_pretty(&response_contract).expect("JSON response contract cannot fail"))
}

/// Projects current State values into the map exposed to Tera.
fn state_json(state: &State) -> Result<JsonValue, String> {
    let fields = state
        .fields
        .iter()
        .map(|(name, field)| Ok((name.clone(), parse_encoded(&field.value.encode(), name)?)))
        .collect::<Result<JsonMap<_, _>, String>>()?;
    Ok(JsonValue::Object(fields))
}

/// Projects the current Step input into the map exposed to Tera.
fn input_json(updates: &StateUpdates) -> Result<JsonValue, String> {
    let fields = updates
        .ephemeral
        .get(&StateNamespace::Input)
        .into_iter()
        .flat_map(|fields| fields.iter())
        .map(|(name, value)| Ok((name.clone(), parse_encoded(&value.encode(), name)?)))
        .collect::<Result<JsonMap<_, _>, String>>()?;
    Ok(JsonValue::Object(fields))
}

/// Projects Trace entries as their stored Step IDs and State snapshots.
fn trace_json(trace: &Trace) -> Result<JsonValue, String> {
    let entries = trace
        .entries
        .iter()
        .map(|entry| {
            Ok(json!({
                "step": entry.step.0,
                "state": state_json(entry.state.as_ref())?,
                "summary": trace_summary_json(&entry.summary)?,
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(JsonValue::Array(entries))
}

fn trace_summary_json(summary: &TraceSummary) -> Result<JsonValue, String> {
    match summary {
        TraceSummary::Summary(summary) => Ok(JsonValue::String(summary.clone())),
        TraceSummary::SubFlow(trace) => trace_json(trace),
    }
}

fn parse_encoded(encoded: &str, field_name: &str) -> Result<JsonValue, String> {
    serde_json::from_str(encoded).map_err(|error| format!("State field {field_name} encoded invalid JSON: {error}"))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use lyquid::prelude::new_hashmap;
    use lyquid_llm::ModelRequest;
    use lyquid_test::test;
    use serde_json::{Value as JsonValue, json};

    use super::{PromptContext, build_request};
    use crate::{
        AutoCheckpointConfig, Flow, FlowError, InputSpec, List, Mapping, Scope, State, StateNamespace, StateUpdates,
        Step, StepId, TemplateSpec, Trace, TraceEntry, TraceSummary, TurnProposal,
    };

    const RESPONSE_CONTRACT_MARKER: &str =
        "# Response contract\nReturn exactly one JSON object matching this contract:\n";

    struct TestStep {
        description: &'static str,
        next: Option<StepId>,
        updates: StateUpdates,
        summary: TraceSummary,
    }

    impl Step for TestStep {
        fn description(&self, _concise: bool) -> String {
            self.description.to_owned()
        }

        fn input(&self, _scope: &Scope) -> Option<InputSpec> {
            None
        }

        fn model_template(&self, _scope: &Scope) -> TemplateSpec {
            // Advance deterministically to seed committed State and Trace. Prompt rendering is exercised directly
            // through `build_request` below, so this fixture must not invoke a model.
            TemplateSpec::Skip(TurnProposal::Advance {
                next: self.next.clone(),
                updates: self.updates.clone(),
            })
        }

        fn finalize(&self, _scope: &Scope, _proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
            Ok(self.summary.clone())
        }
    }

    fn prompt_fixture() -> (Arc<Flow>, Scope) {
        let mut scores = new_hashmap();
        scores.insert("quality".to_owned(), 9_u64);
        let state = State::builder()
            .field("title", "Current release title", "Draft".to_owned())
            .field(
                "tasks",
                "Ordered release tasks",
                List(vec!["write".to_owned(), "review".to_owned()]),
            )
            .field("scores", "Release quality scores", Mapping(scores))
            .build()
            .expect("the prompt fixture State should be valid");

        let mut prepare_updates = StateUpdates::default();
        prepare_updates.set("title".to_owned(), Some(Box::new("Ready".to_owned())));
        let flow = Arc::new(
            Flow::builder("release")
                .description("Prepare a release.")
                .entry("prepare")
                .exit("done")
                .step(
                    "prepare",
                    TestStep {
                        description: "Prepare the release",
                        next: Some(StepId::from("review")),
                        updates: prepare_updates,
                        summary: TraceSummary::Summary("prepared".to_owned()),
                    },
                )
                .step(
                    "review",
                    TestStep {
                        description: "Review the release",
                        next: Some(StepId::from("done")),
                        updates: StateUpdates::default(),
                        summary: TraceSummary::Summary("reviewed".to_owned()),
                    },
                )
                .build()
                .expect("the prompt fixture Flow should be valid"),
        );
        let mut scope = Scope::new(Arc::clone(&flow), state, AutoCheckpointConfig::Disabled, None);
        scope
            .advance()
            .expect("the fixture Step should commit its State and Trace");
        scope.set(StateNamespace::Input, "approved".to_owned(), Some(Box::new(true)));

        (flow, scope)
    }

    fn contract_json(request: &ModelRequest) -> JsonValue {
        let system = request
            .system
            .as_deref()
            .expect("a Flow model request should have system context");
        let (_, encoded) = system
            .split_once(RESPONSE_CONTRACT_MARKER)
            .expect("system context should contain the response contract marker");
        serde_json::from_str(encoded).expect("the response contract should be valid JSON")
    }

    #[test]
    fn renders_prompt_context() {
        let (flow, scope) = prompt_fixture();
        let request = build_request(
            "test-model",
            concat!(
                "title={{ state.title }}\n",
                "tasks={% for task in state.tasks %}{{ task }}{% if not loop.last %},{% endif %}{% endfor %}\n",
                "decision={% if input.approved %}approved{% else %}rejected{% endif %}\n",
                "trace={% for entry in trace %}",
                "{{ entry.step }}:{{ entry.state.title }}:{{ entry.summary }}",
                "{% endfor %}",
            )
            .to_owned(),
            PromptContext {
                flow_description: flow.description(),
                scope: &scope,
                next_options: flow.next_options(false),
            },
        )
        .expect("the prompt fixture should render");

        assert_eq!(request.model, "test-model");
        assert_eq!(
            request.prompt,
            "title=Ready\ntasks=write,review\ndecision=approved\ntrace=prepare:Ready:prepared"
        );
        assert!(
            request
                .system
                .as_deref()
                .expect("the request should contain Flow context")
                .starts_with("# Flow\nPrepare a release.\n\n# Response contract\n")
        );

        let default_description = build_request(
            "test-model",
            "static prompt".to_owned(),
            PromptContext {
                flow_description: "",
                scope: &scope,
                next_options: flow.next_options(false),
            },
        )
        .expect("the default Flow description should render");
        assert!(
            default_description
                .system
                .as_deref()
                .expect("the request should contain default Flow context")
                .starts_with("# Flow\nExecute the current Flow.\n\n# Response contract\n")
        );
    }

    #[test]
    fn renders_chronological_and_nested_trace() {
        // Build one child Trace with two Steps: `child-plan` followed by `child-finish`.
        let child_planned_state = Arc::new(
            State::builder()
                .field("status", "Child status", "planned".to_owned())
                .build()
                .expect("the planned child State should be valid"),
        );
        let child_finished_state = Arc::new(
            State::builder()
                .field("status", "Child status", "finished".to_owned())
                .build()
                .expect("the finished child State should be valid"),
        );
        let child_trace = Trace {
            entries: vec![
                TraceEntry {
                    step: StepId::from("child-plan"),
                    state: child_planned_state,
                    summary: TraceSummary::Summary("planned".to_owned()),
                },
                TraceEntry {
                    step: StepId::from("child-finish"),
                    state: child_finished_state,
                    summary: TraceSummary::Summary("finished".to_owned()),
                },
            ],
        };

        let parent_state = State::builder()
            .field("status", "Parent status", "not-started".to_owned())
            .build()
            .expect("the parent State should be valid");
        let mut first_updates = StateUpdates::default();
        first_updates.set("status".to_owned(), Some(Box::new("first-complete".to_owned())));
        let mut second_updates = StateUpdates::default();
        second_updates.set("status".to_owned(), Some(Box::new("second-complete".to_owned())));

        // The parent Flow records two entries. The first has a normal text summary; the second
        // embeds the child Trace above as a SubFlow summary.
        let flow = Arc::new(
            Flow::builder("trace")
                .entry("first")
                .step(
                    "first",
                    TestStep {
                        description: "Run first Step",
                        next: Some(StepId::from("second")),
                        updates: first_updates,
                        summary: TraceSummary::Summary("first committed".to_owned()),
                    },
                )
                .step(
                    "second",
                    TestStep {
                        description: "Run child Flow",
                        next: None,
                        updates: second_updates,
                        summary: TraceSummary::SubFlow(child_trace),
                    },
                )
                .build()
                .expect("the Trace fixture Flow should be valid"),
        );
        let mut scope = Scope::new(Arc::clone(&flow), parent_state, AutoCheckpointConfig::Disabled, None);

        // Advancing commits State snapshots in execution order:
        // `first` sees status=first-complete, then `second` sees status=second-complete.
        scope.advance().expect("the first Step should commit");
        scope.advance().expect("the second Step should commit");

        // Render the outer Trace first, then iterate the SubFlow stored in the second entry's
        // summary. This is the shape authors can use in a real Tera prompt template.
        let request = build_request(
            "test-model",
            concat!(
                "parent={% for entry in trace %}",
                "{{ entry.step }}:{{ entry.state.status }}{% if not loop.last %}>{% endif %}",
                "{% endfor %}\n",
                "first-summary={{ trace[0].summary }}\n",
                "child={% for entry in trace[1].summary %}",
                "{{ entry.step }}:{{ entry.state.status }}:{{ entry.summary }}",
                "{% if not loop.last %}>{% endif %}{% endfor %}",
            )
            .to_owned(),
            PromptContext {
                flow_description: flow.description(),
                scope: &scope,
                next_options: flow.next_options(false),
            },
        )
        .expect("the chronological nested Trace should render");

        // The separators make ordering explicit: both parent and child entries must remain
        // chronological, with the State snapshot and summary attached to the correct Step.
        assert_eq!(
            request.prompt,
            concat!(
                "parent=first:first-complete>second:second-complete\n",
                "first-summary=first committed\n",
                "child=child-plan:planned:planned>child-finish:finished:finished",
            )
        );
    }

    #[test]
    fn renders_response_contract() {
        let (flow, mut scope) = prompt_fixture();
        let mut checkpoint_ids = vec![scope.checkpoint(), scope.checkpoint()];
        checkpoint_ids.sort();

        let root_request = build_request(
            "test-model",
            "root".to_owned(),
            PromptContext {
                flow_description: flow.description(),
                scope: &scope,
                next_options: flow.next_options(false),
            },
        )
        .expect("the root response contract should render");
        let root_contract = contract_json(&root_request);

        assert_eq!(
            root_contract["advance"]["updates"]["fields"]["title"],
            json!({
                "description": "Current release title",
                "value": "Ready",
            })
        );
        assert_eq!(
            root_contract["advance"]["updates"]["fields"]["tasks"],
            json!({
                "description": "Ordered release tasks",
                "value": ["write", "review"],
            })
        );
        assert_eq!(
            root_contract["advance"]["updates"]["fields"]["scores"],
            json!({
                "description": "Release quality scores",
                "value": {"quality": 9},
            })
        );

        let root_options = root_contract["advance"]["next"]["options"]
            .as_array()
            .expect("root next options should be an array");
        assert_eq!(
            root_options,
            &vec![
                json!({"description": "Exit the current Flow through done", "value": "done"}),
                json!({"description": "Prepare the release", "value": "prepare"}),
                json!({"description": "Review the release", "value": "review"}),
                json!({"description": "Complete the current Flow", "value": null}),
            ]
        );

        let expected_checkpoints = checkpoint_ids
            .iter()
            .map(|id| {
                json!({
                    "description": format!("Restore Scope checkpoint {id}"),
                    "value": id.0,
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            root_contract["restore"]["scope"]["options"]
                .as_array()
                .expect("checkpoint options should be an array"),
            &expected_checkpoints
        );

        let child_request = build_request(
            "test-model",
            "child".to_owned(),
            PromptContext {
                flow_description: flow.description(),
                scope: &scope,
                next_options: flow.next_options(true),
            },
        )
        .expect("the child response contract should render");
        let child_contract = contract_json(&child_request);
        let child_options = child_contract["advance"]["next"]["options"]
            .as_array()
            .expect("child next options should be an array");
        assert_eq!(child_options.as_slice(), &root_options[..root_options.len() - 1]);
    }
}
