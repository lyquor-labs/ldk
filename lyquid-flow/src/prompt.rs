use std::fmt::Write as _;

use lyquid_llm::ModelRequest;
use serde_json::{Map as JsonMap, Value as JsonValue, json};
use tera::{Context, Tera};

use crate::TurnProposal;
use crate::flow::Flow;
use crate::scope::Scope;
use crate::state::{State, StateNamespace, StateUpdates};
use crate::step::{ModelTemplate, StepId};
use crate::trace::{Trace, TraceSummary};

/// Builds the complete model request from a template validated by Scope.
pub(super) fn build_request(
    model: &str, template: &ModelTemplate, flow: &Flow, scope: &Scope,
) -> Result<ModelRequest, String> {
    let prompt = render_step_prompt(flow, scope, template)?;
    let response_contract = response_contract(scope, &template.next_step_criteria, &template.state_update_criteria)?;
    let flow_description = match flow.description() {
        "" => "Execute the current Flow.",
        description => description,
    };
    let flow_context = format!(
        "# Flow\n{flow_description}\n\n# Response contract\nReturn exactly one JSON object matching this contract:\n{response_contract}"
    );
    Ok(ModelRequest::new(model, prompt).system(flow_context))
}

/// Parses a model response into a proposed local Advance or Restore.
pub(super) fn parse_response(state: &State, template: &ModelTemplate, output: &str) -> Result<TurnProposal, String> {
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
    if !template
        .next_step_criteria
        .iter()
        .any(|(declared, _)| declared == &next)
    {
        let target = next
            .as_ref()
            .map_or_else(|| "Flow completion".to_owned(), |step| format!("Step {step}"));
        return Err(format!("model output selected undeclared next target {target}"));
    }

    let proposed_updates = output
        .get("updates")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| "model output `updates` must be an object".to_owned())?;

    let mut updates = StateUpdates::default();
    for (name, encoded) in proposed_updates {
        if !template.state_update_criteria.iter().any(|(field, _)| field == name) {
            return Err(format!("model output attempted undeclared State update {name}"));
        }
        let field = state
            .fields
            .get(name)
            .ok_or_else(|| format!("unknown State field {name}"))?;
        let value = field.value.decode(&encoded.to_string())?;
        updates.set(name.clone(), Some(value));
    }
    Ok(TurnProposal::Advance { next, updates })
}

/// Renders and joins all three sections using one shared Tera context.
///
/// The context exposes committed `state`, current `input`, and the complete local `trace` in chronological order.
/// Trace entries contain their Step ID, State snapshot, and summary, including nested child Traces.
/// `step` maps every local Step and exit ID to its raw string, without changing the permitted next destinations.
fn render_step_prompt(flow: &Flow, scope: &Scope, template: &ModelTemplate) -> Result<String, String> {
    let mut context = Context::new();
    context.insert("state", &state_json(scope.state())?);
    context.insert("input", &input_json(scope.updates())?);
    context.insert("trace", &trace_json(scope.trace())?);
    let steps = flow
        .step_ids()
        .chain(flow.exits())
        .map(|id| (id.0.clone(), JsonValue::String(id.0.clone())))
        .collect::<JsonMap<_, _>>();
    context.insert("step", &steps);

    let render = |section: &str, value: &str| {
        Tera::one_off(value, &context, false)
            .map(|rendered| rendered.trim().to_owned())
            .map_err(|error| {
                format!(
                    "failed to render {section} for Step {}: {error:#}",
                    scope.current_step()
                )
            })
    };

    let step_goal = render("step goal", &template.step_goal)?;
    if step_goal.is_empty() {
        return Err("a model template must render a non-empty step goal".to_owned());
    }

    let mut prompt = format!("# Step goal\n{step_goal}\n\n# Next step criteria\n");
    for (next, criterion) in &template.next_step_criteria {
        let condition = render("next-step criterion", criterion)?;
        if condition.is_empty() {
            return Err("a model template must render non-empty next-step criteria".to_owned());
        }
        let next = next.as_ref().map_or("null (complete the Flow)", |step| step.0.as_str());
        writeln!(&mut prompt, "- `{next}`: {condition}").expect("writing a Step prompt to String cannot fail");
    }

    prompt.push_str("\n# State update criteria\n");
    if template.state_update_criteria.is_empty() {
        prompt.push_str("No State updates are permitted. Return `updates` as `{}`.");
    } else {
        prompt.push_str("Update a field only when its criterion applies; omit every unchanged field.\n");
        for (field, criterion) in &template.state_update_criteria {
            let condition = render("State update criterion", criterion)?;
            if condition.is_empty() {
                return Err(format!(
                    "model template must render a non-empty update criterion for State field {field}"
                ));
            }
            writeln!(&mut prompt, "- `{field}`: {condition}")
                .expect("writing a State update criterion to String cannot fail");
        }
        while prompt.ends_with('\n') {
            prompt.pop();
        }
    }
    Ok(prompt)
}

/// Builds the model response contract from valid local transitions and State fields.
fn response_contract(
    scope: &Scope, next_steps: &[(Option<StepId>, String)], state_updates: &[(String, String)],
) -> Result<String, String> {
    let state = scope.state();
    let update_fields = state_updates
        .iter()
        .map(|(name, _)| {
            let field = state
                .fields
                .get(name)
                .expect("model template State fields are validated before building the request");
            Ok((
                name.clone(),
                json!({
                    "description": field.description,
                    "value": parse_encoded(&field.value.encode(), name)?,
                }),
            ))
        })
        .collect::<Result<JsonMap<_, _>, String>>()?;
    let next_options = next_steps
        .iter()
        .map(|(next, _)| json!({ "value": next.as_ref().map(|next| &next.0) }))
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
                    "Use only keys from `fields`; omit unchanged fields, and return `{}` if no update criterion applies. ",
                    "Each value must have the same JSON type ",
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

    use super::{build_request, parse_response};
    use crate::{
        AutoCheckpointConfig, ExitTransitions, Flow, FlowError, InputSpec, List, Mapping, ModelTemplate, Scope, State,
        StateNamespace, StateUpdates, Step, StepId, TemplateSpec, Trace, TraceEntry, TraceMode, TraceSummary,
        TurnProposal,
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

    fn prompt_fixture(description: &str) -> (Arc<Flow>, Scope) {
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
                .description(description)
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
        let (flow, mut scope) = prompt_fixture("Prepare a release.");
        scope.set(
            StateNamespace::Input,
            "literal".to_owned(),
            Some(Box::new("{{ state.title }}".to_owned())),
        );
        let template = ModelTemplate::new(
            concat!(
                "title={{ state.title }}\n",
                "tasks={% for task in state.tasks %}{{ task }}{% if not loop.last %},{% endif %}{% endfor %}\n",
                "decision={% if input.approved %}approved{% else %}rejected{% endif %}\n",
                "trace={% for entry in trace %}",
                "{{ entry.step }}:{{ entry.state.title }}:{{ entry.summary }}",
                "{% endfor %}\n",
                "steps={{ step.prepare }},{{ step.review }},{{ step.done }}",
            ),
            vec![(
                Some("review".into()),
                concat!(
                    "Continue to {{ step.review }} when {{ state.title }} is ",
                    "{% if input.approved %}approved{% else %}rejected{% endif %} ",
                    "after {{ trace[0].summary }}",
                )
                .to_owned(),
            )],
            vec![(
                "title".to_owned(),
                "Replace with the literal text {{ input.literal }} when returning to {{ step.review }}".to_owned(),
            )],
        );
        let request = build_request("test-model", &template, &flow, &scope).expect("the prompt fixture should render");

        assert_eq!(request.model, "test-model");
        assert_eq!(
            request.prompt,
            concat!(
                "# Step goal\n",
                "title=Ready\ntasks=write,review\ndecision=approved\ntrace=prepare:Ready:prepared\n",
                "steps=prepare,review,done\n\n",
                "# Next step criteria\n",
                "- `review`: Continue to review when Ready is approved after prepared\n\n",
                "# State update criteria\n",
                "Update a field only when its criterion applies; omit every unchanged field.\n",
                "- `title`: Replace with the literal text {{ state.title }} when returning to review",
            )
        );
        assert!(
            request
                .system
                .as_deref()
                .expect("the request should contain Flow context")
                .starts_with("# Flow\nPrepare a release.\n\n# Response contract\n")
        );
        let contract = contract_json(&request);
        assert_eq!(contract["advance"]["next"]["options"], json!([{ "value": "review" }]));
        assert_eq!(
            contract["advance"]["updates"]["fields"]
                .as_object()
                .expect("declared State update fields should be an object")
                .keys()
                .collect::<Vec<_>>(),
            vec!["title"]
        );

        let default_template = ModelTemplate::new(
            "static prompt",
            vec![(None, "The work is complete".to_owned())],
            Vec::new(),
        );
        let (default_flow, default_scope) = prompt_fixture("");
        let default_description = build_request("test-model", &default_template, &default_flow, &default_scope)
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
    fn renders_step_references() {
        let (child, child_scope) = prompt_fixture("");
        let parent = Arc::new(
            Flow::builder("parent")
                .entry("release-flow")
                .flow(
                    "release-flow",
                    Arc::clone(&child),
                    ExitTransitions::new().transition("done", "release.done").unwrap(),
                    TraceMode::Expanded,
                )
                .exit("release.done")
                .build()
                .unwrap(),
        );
        let parent_scope = Scope::new(
            Arc::clone(&parent),
            State::default(),
            AutoCheckpointConfig::Disabled,
            None,
        );
        let template = ModelTemplate::new(
            r#"After {{ step["release-flow"] }}, the next step would be {{ step["release.done"] }}"#,
            vec![(Some("release.done".into()), "The release is complete".to_owned())],
            Vec::new(),
        );
        let request = build_request("test-model", &template, &parent, &parent_scope).unwrap();
        assert!(
            request
                .prompt
                .contains("After release-flow, the next step would be release.done")
        );

        // A mount is visible as one parent-local Step; neither Flow can reference the other's internals or exits.
        for (flow, scope, missing) in [
            (&parent, &parent_scope, "review"),
            (&parent, &parent_scope, "done"),
            (&child, &child_scope, "release-flow"),
            (&child, &child_scope, "release.done"),
        ] {
            let mut template = template.clone();
            template.step_goal = format!("{{{{ step[\"{missing}\"] }}}}");
            let error = super::render_step_prompt(flow, scope, &template).unwrap_err();
            assert!(error.contains("failed to render step goal"), "{error}");
            assert!(error.contains(missing), "{error}");
        }
    }

    #[test]
    fn rejects_unknown_step() {
        let (flow, scope) = prompt_fixture("");
        for section in ["step goal", "next-step criterion", "State update criterion"] {
            let mut template = ModelTemplate::new(
                "Review the release",
                vec![(Some("review".into()), "Review again".to_owned())],
                vec![("title".to_owned(), "Use the approved title".to_owned())],
            );
            let text = match section {
                "step goal" => &mut template.step_goal,
                "next-step criterion" => &mut template.next_step_criteria[0].1,
                _ => &mut template.state_update_criteria[0].1,
            };
            *text = "Continue to {{ step.missing }}".to_owned();
            let error = build_request("test-model", &template, &flow, &scope).unwrap_err();
            assert!(
                error.contains(&format!("failed to render {section} for Step review")),
                "{error}"
            );
            assert!(error.contains("step.missing"), "{error}");
        }
    }

    #[test]
    fn renders_response_contract() {
        let (flow, mut scope) = prompt_fixture("Prepare a release.");
        let mut checkpoint_ids = vec![scope.checkpoint(), scope.checkpoint()];
        checkpoint_ids.sort();

        let template = ModelTemplate::new(
            "Review the release",
            vec![
                (Some("done".into()), "The review passed".to_owned()),
                (Some("review".into()), "Another review pass is required".to_owned()),
                (None, "No further workflow work is required".to_owned()),
            ],
            vec![
                ("title".to_owned(), "Replace when the approved title changes".to_owned()),
                ("tasks".to_owned(), "Replace when the ordered work changes".to_owned()),
                ("scores".to_owned(), "Replace when a quality score changes".to_owned()),
            ],
        );

        let root_request =
            build_request("test-model", &template, &flow, &scope).expect("the root response contract should render");
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
                json!({"value": "done"}),
                json!({"value": "review"}),
                json!({"value": null}),
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
        let template = ModelTemplate::new(
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
            vec![(None, "The traced work is complete".to_owned())],
            Vec::new(),
        );
        let request = build_request("test-model", &template, &flow, &scope)
            .expect("the chronological nested Trace should render");

        // The separators make ordering explicit: both parent and child entries must remain
        // chronological, with the State snapshot and summary attached to the correct Step.
        assert_eq!(
            request.prompt,
            concat!(
                "# Step goal\n",
                "parent=first:first-complete>second:second-complete\n",
                "first-summary=first committed\n",
                "child=child-plan:planned:planned>child-finish:finished:finished\n\n",
                "# Next step criteria\n",
                "- `null (complete the Flow)`: The traced work is complete\n\n",
                "# State update criteria\n",
                "No State updates are permitted. Return `updates` as `{}`.",
            )
        );
    }

    #[test]
    fn rejects_invalid_model_proposal() {
        let (_, scope) = prompt_fixture("");
        let template = ModelTemplate::new(
            "Review the release",
            vec![(Some("review".into()), "Another review pass is required".to_owned())],
            vec![("title".to_owned(), "Replace when the approved title changes".to_owned())],
        );

        let allowed = parse_response(
            scope.state(),
            &template,
            r#"{"type":"advance","next":"review","updates":{"title":"Approved"}}"#,
        )
        .expect("the declared destination and State field should be accepted");
        let TurnProposal::Advance { next, updates } = allowed else {
            unreachable!()
        };
        assert_eq!(next.map(|next| next.0).as_deref(), Some("review"));
        assert_eq!(updates.get::<String>("title").map(String::as_str), Some("Approved"));

        let undeclared_next = parse_response(
            scope.state(),
            &template,
            r#"{"type":"advance","next":"done","updates":{}}"#,
        )
        .err()
        .expect("an undeclared destination should be rejected");
        assert_eq!(
            undeclared_next,
            "model output selected undeclared next target Step done"
        );

        let undeclared_update = parse_response(
            scope.state(),
            &template,
            r#"{"type":"advance","next":"review","updates":{"tasks":["ship"]}}"#,
        )
        .err()
        .expect("an undeclared State field should be rejected");
        assert_eq!(
            undeclared_update,
            "model output attempted undeclared State update tasks"
        );
    }
}
