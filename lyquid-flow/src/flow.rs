use std::any::Any;
use std::fmt;
use std::sync::Arc;

use lyquid::prelude::{HashMap, HashSet, hashbrown::hash_map::Entry, new_hashmap, new_hashset};
use serde::{Deserialize, Serialize};

use crate::scope::{FlowError, Scope};
use crate::state::StateUpdates;
use crate::step::{InputSpec, Step, StepId, TemplateSpec};
use crate::trace::TraceSummary;
use crate::turn::TurnProposal;

/// Stable developer-supplied identity of one Flow definition.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct FlowId(pub String);

impl From<&str> for FlowId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl fmt::Display for FlowId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Deterministically connects every declared exit of a child Flow Step to exactly one target in its parent Flow.
///
/// Duplicate mappings are rejected when they are declared. When the parent Flow is built, validation
/// also requires every child exit to have a mapping, rejects mappings for undeclared child exits, and
/// verifies that every mapped target is a Step or declared exit local to the parent Flow.
#[derive(Clone)]
pub struct ExitTransitions {
    transitions: HashMap<StepId, StepId>,
}

impl Default for ExitTransitions {
    fn default() -> Self {
        Self::new()
    }
}

impl ExitTransitions {
    /// Starts an empty exit-transition declaration.
    pub fn new() -> Self {
        Self {
            transitions: new_hashmap(),
        }
    }

    /// Connects one child exit transition to a target in the parent Flow.
    ///
    /// Returns an error if that exit already has a parent target.
    pub fn transition(mut self, exit: impl Into<StepId>, next: impl Into<StepId>) -> Result<Self, String> {
        match self.transitions.entry(exit.into()) {
            Entry::Occupied(entry) => Err(format!("duplicate target for exit transition {}", entry.key())),
            Entry::Vacant(entry) => {
                entry.insert(next.into());
                Ok(self)
            }
        }
    }

    fn target(&self, exit: &StepId) -> Option<&StepId> {
        self.transitions.get(exit)
    }
}

/// Controls how a completed child Flow is represented in its parent's Trace.
#[derive(Clone)]
pub enum TraceMode {
    /// Retain the child Flow's complete nested Trace.
    Expanded,
    /// Replace the child Trace with this one-line summary.
    Collapsed(String),
}

/// Collects the Steps, sole entry, and exits for one reusable Flow.
pub struct FlowBuilder {
    /// Stable identity of this reusable Flow definition.
    id: FlowId,
    /// Flow-level purpose supplied to the model and parent Flow descriptions.
    description: String,
    /// Entry declarations retained until `build` verifies there is exactly one.
    entries: Vec<StepId>,
    /// Named boundary targets through which this Flow may complete when mounted.
    exits: HashSet<StepId>,
    /// Local Step implementations retained until their IDs and child wiring are validated.
    steps: Vec<(StepId, Arc<dyn Step>)>,
}

impl FlowBuilder {
    /// Describes this Flow for model context and when viewed as a composite Step by its parent.
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Declares the sole Step through which this Flow is entered.
    pub fn entry(mut self, entry: impl Into<StepId>) -> Self {
        self.entries.push(entry.into());
        self
    }

    /// Declares a boundary target through which this Flow may return.
    pub fn exit(mut self, exit: impl Into<StepId>) -> Self {
        self.exits.insert(exit.into());
        self
    }

    /// Registers one leaf Step implementation under its local stable ID.
    ///
    /// Register child Flows with [`FlowBuilder::flow`] so their mount configuration is retained.
    pub fn step<S>(mut self, id: impl Into<StepId>, step: S) -> Self
    where
        S: Step + 'static,
    {
        self.steps.push((id.into(), Arc::new(step)));
        self
    }

    /// Registers a child Flow, connects its exits, and selects how its Trace is recorded.
    ///
    /// The reusable graph is shallow-cloned so this mount owns its exit mapping and Trace mode.
    pub fn flow(
        mut self, id: impl Into<StepId>, flow: impl Into<Arc<Flow>>, exit_transitions: ExitTransitions,
        trace_mode: TraceMode,
    ) -> Self {
        let mut flow = flow.into().as_ref().clone();
        flow.exit_transitions = exit_transitions;
        flow.trace_mode = trace_mode;
        self.steps.push((id.into(), Arc::new(flow)));
        self
    }

    /// Validates and freezes this reusable Flow graph.
    pub fn build(self) -> Result<Flow, String> {
        let [entry] = self.entries.as_slice() else {
            return Err("Flow requires exactly one entry Step".into());
        };

        let mut steps = new_hashmap();
        for (id, node) in self.steps {
            if steps.insert(id.clone(), node).is_some() {
                return Err(format!("duplicate Step {id}"));
            }
        }
        validate_entry(entry, &steps)?;
        validate_exit_boundaries(&self.exits, &steps)?;
        validate_child_exit_transitions(&steps)?;

        let flow = Flow {
            id: self.id,
            description: self.description,
            entry: entry.clone(),
            exits: self.exits,
            steps,
            exit_transitions: ExitTransitions::new(),
            trace_mode: TraceMode::Expanded,
        };
        flow.validate_exit_transition_targets()?;
        Ok(flow)
    }
}

/// A reusable workflow graph that also implements [`Step`] when mounted with [`FlowBuilder::flow`].
///
/// Mounting shallow-clones the graph and attaches that parent's exit mapping and Trace mode to the
/// clone, leaving the original Flow reusable. A parent executes the configured clone as one Step by
/// forking a child [`crate::Scope`]. The child inherits an immutable snapshot of its parent Scope
/// while keeping local State versions and Trace entries until it exits. The parent then
/// applies the child's accumulated State updates and follows the configured exit transition.
#[derive(Clone)]
pub struct Flow {
    /// Stable identity used to qualify checkpoints created by bound Scopes.
    id: FlowId,
    /// Flow-level purpose supplied to model context and parent Flow descriptions.
    description: String,
    /// Local Step entered when an execution starts.
    entry: StepId,
    /// Named boundary targets exposed when this Flow is mounted as a Step.
    exits: HashSet<StepId>,
    /// Validated local Step implementations indexed by stable ID.
    steps: HashMap<StepId, Arc<dyn Step>>,
    /// Parent-local targets configured when this Flow is mounted as a Step.
    exit_transitions: ExitTransitions,
    /// Representation configured for this Flow's Trace when mounted as a Step.
    trace_mode: TraceMode,
}

impl Flow {
    /// Starts declaring a reusable Flow with its stable identity.
    pub fn builder(id: impl Into<FlowId>) -> FlowBuilder {
        FlowBuilder {
            id: id.into(),
            description: String::new(),
            entries: Vec::new(),
            exits: new_hashset(),
            steps: Vec::new(),
        }
    }

    pub(super) fn description(&self) -> &str {
        &self.description
    }

    pub(super) fn id(&self) -> &FlowId {
        &self.id
    }

    pub(super) fn entry(&self) -> &StepId {
        &self.entry
    }

    pub(super) fn step(&self, id: &StepId) -> Option<&dyn Step> {
        self.steps.get(id).map(AsRef::as_ref)
    }

    pub(super) fn step_cloned(&self, id: &StepId) -> Option<Arc<dyn Step>> {
        self.steps.get(id).map(Arc::clone)
    }

    pub(super) fn child_flow(&self, id: &StepId) -> Option<Arc<Self>> {
        let step = Arc::clone(self.steps.get(id)?);
        let step: Arc<dyn Any + Send + Sync> = step;
        step.downcast().ok()
    }

    /// Returns all valid `next` options and their descriptions in stable order.
    /// Adds the `next: null` completion option only when this Flow runs as the root.
    pub(super) fn next_options(&self, requires_exit: bool) -> Vec<(Option<StepId>, String)> {
        let mut targets = self.steps.keys().chain(self.exits.iter()).cloned().collect::<Vec<_>>();
        targets.sort();

        let mut options = targets
            .into_iter()
            .map(|target| {
                let description = if self.exits.contains(&target) {
                    format!("Exit the current Flow through {target}")
                } else {
                    self.steps
                        .get(&target)
                        .expect("next targets come from validated Flow Steps")
                        .description(true)
                };
                (Some(target), description)
            })
            .collect::<Vec<_>>();
        if !requires_exit {
            options.push((None, "Complete the current Flow".to_owned()));
        }
        options
    }

    pub(super) fn exits(&self) -> &HashSet<StepId> {
        &self.exits
    }

    fn validate_exit_transition_targets(&self) -> Result<(), String> {
        for flow in self
            .steps
            .values()
            .filter_map(|step| (step.as_ref() as &dyn Any).downcast_ref::<Self>())
        {
            for next in flow.exit_transitions.transitions.values() {
                if !self.steps.contains_key(next) && !self.exits.contains(next) {
                    return Err(format!("unknown next Step {next}"));
                }
            }
        }
        Ok(())
    }
}

impl Step for Flow {
    fn input(&self, _scope: &Scope) -> Option<InputSpec> {
        None
    }

    fn description(&self, _concise: bool) -> String {
        if self.description.is_empty() {
            "Run child Flow".to_owned()
        } else {
            self.description.clone()
        }
    }

    fn model_template(&self, _scope: &Scope) -> TemplateSpec {
        TemplateSpec::Skip(TurnProposal::Advance {
            next: Some(self.entry.clone()),
            updates: StateUpdates::default(),
        })
    }

    fn finalize(&self, scope: &Scope, proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
        let TurnProposal::Advance { next, updates } = proposal else {
            panic!("a child Flow completes by advancing through one of its declared exit transitions");
        };
        let exit = next
            .as_ref()
            .expect("a child Flow completes through one of its declared exit transitions");
        let target = self
            .exit_transitions
            .target(exit)
            .expect("all mounted Flow exits have validated parent transitions")
            .clone();
        let child = scope
            .running_child()
            .expect("a child Flow is finalized only after its child Scope completes");
        let summary = match &self.trace_mode {
            TraceMode::Expanded => TraceSummary::SubFlow(child.trace().clone()),
            TraceMode::Collapsed(summary) => TraceSummary::Summary(summary.clone()),
        };
        *next = Some(target);
        *updates = child.accumulated_updates();
        Ok(summary)
    }
}

fn validate_entry(entry: &StepId, steps: &HashMap<StepId, Arc<dyn Step>>) -> Result<(), String> {
    if steps.contains_key(entry) {
        Ok(())
    } else {
        Err(format!("unknown Flow entry Step {entry}"))
    }
}

fn validate_exit_boundaries(exits: &HashSet<StepId>, steps: &HashMap<StepId, Arc<dyn Step>>) -> Result<(), String> {
    if let Some(exit) = exits.iter().find(|exit| steps.contains_key(*exit)) {
        return Err(format!("Flow exit {exit} conflicts with a registered Step"));
    }
    Ok(())
}

fn validate_child_exit_transitions(steps: &HashMap<StepId, Arc<dyn Step>>) -> Result<(), String> {
    for (id, flow) in steps.iter().filter_map(|(id, step)| {
        (step.as_ref() as &dyn Any)
            .downcast_ref::<Flow>()
            .map(|flow| (id, flow))
    }) {
        validate_exit_transitions(id, flow, &flow.exit_transitions)?;
    }
    Ok(())
}

fn validate_exit_transitions(id: &StepId, flow: &Flow, exit_transitions: &ExitTransitions) -> Result<(), String> {
    if flow.exits.is_empty() {
        return Err(format!(
            "child Flow Step {id} must declare at least one exit transition"
        ));
    }

    let declared = &exit_transitions.transitions;
    if let Some(exit) = declared.keys().find(|exit| !flow.exits.contains(*exit)) {
        return Err(format!("{exit} is not an exit transition of child Flow Step {id}"));
    }
    if let Some(exit) = flow.exits.iter().find(|exit| !declared.contains_key(*exit)) {
        return Err(format!(
            "exit transition {exit} of child Flow Step {id} has no parent target"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lyquid_test::test;

    struct TestStep;

    impl Step for TestStep {
        fn description(&self, _concise: bool) -> String {
            "Test Step".to_owned()
        }

        fn input(&self, _scope: &Scope) -> Option<InputSpec> {
            None
        }

        fn model_template(&self, _scope: &Scope) -> TemplateSpec {
            TemplateSpec::Skip(TurnProposal::Advance {
                next: None,
                updates: StateUpdates::default(),
            })
        }

        fn finalize(&self, _scope: &Scope, _proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
            Ok(TraceSummary::Summary("tested".to_owned()))
        }
    }

    fn child_with_exits(id: &str, exits: &[&str]) -> Flow {
        let mut builder = Flow::builder(id).entry("inside").step("inside", TestStep);
        for exit in exits {
            builder = builder.exit(*exit);
        }
        builder.build().expect("test child Flow should be valid")
    }

    #[test]
    fn builds_flow_structure() {
        let flow = Flow::builder("test-flow")
            .description("Test Flow")
            .entry("start")
            .exit("done")
            .step("start", TestStep)
            .build()
            .expect("test Flow should be valid");

        assert_eq!(flow.id.0, "test-flow");
        assert_eq!(flow.description, "Test Flow");
        assert_eq!(flow.entry.0, "start");
        assert!(flow.steps.contains_key(&StepId::from("start")));
        assert!(flow.exits.contains(&StepId::from("done")));
    }

    #[test]
    fn retains_child_flow_mount_structure() {
        let child = Flow::builder("child")
            .entry("inside")
            .exit("done")
            .step("inside", TestStep)
            .build()
            .expect("the child Flow should be valid");
        let parent = Flow::builder("parent")
            .entry("child")
            .exit("finished")
            .flow(
                "child",
                child,
                ExitTransitions::new()
                    .transition("done", "finished")
                    .expect("the child exit transition should be valid"),
                TraceMode::Expanded,
            )
            .build()
            .expect("the parent Flow should be valid");

        let mounted = parent
            .child_flow(&StepId::from("child"))
            .expect("the mounted Step should retain its child Flow");
        assert_eq!(mounted.id.0, "child");
        assert_eq!(mounted.entry.0, "inside");
        assert_eq!(
            mounted
                .exit_transitions
                .target(&StepId::from("done"))
                .expect("the child exit should retain its parent target")
                .0,
            "finished"
        );
        assert!(matches!(mounted.trace_mode, TraceMode::Expanded));
    }

    #[test]
    fn validates_flow_entries() {
        let valid = Flow::builder("test-flow")
            .entry("start")
            .step("start", TestStep)
            .build()
            .expect("a Flow with one known entry should be valid");

        assert_eq!(valid.entry.0, "start");

        let missing = Flow::builder("test-flow").step("start", TestStep).build();

        assert_eq!(missing.err().as_deref(), Some("Flow requires exactly one entry Step"));

        let multiple = Flow::builder("test-flow")
            .entry("start")
            .entry("other")
            .step("start", TestStep)
            .step("other", TestStep)
            .build();

        assert_eq!(multiple.err().as_deref(), Some("Flow requires exactly one entry Step"));

        let unknown = Flow::builder("test-flow")
            .entry("missing")
            .step("start", TestStep)
            .build();

        assert_eq!(unknown.err().as_deref(), Some("unknown Flow entry Step missing"));
    }

    #[test]
    fn rejects_conflicting_flow_names() {
        let duplicate_steps = Flow::builder("test-flow")
            .entry("start")
            .step("start", TestStep)
            .step("start", TestStep)
            .build();

        assert_eq!(duplicate_steps.err().as_deref(), Some("duplicate Step start"));

        let child = child_with_exits("child", &["done"]);
        let transitions = ExitTransitions::new()
            .transition("done", "finished")
            .expect("the child exit transition should be valid");
        let duplicate_step_and_flow = Flow::builder("parent")
            .entry("shared")
            .exit("finished")
            .step("shared", TestStep)
            .flow("shared", child, transitions, TraceMode::Expanded)
            .build();

        assert_eq!(duplicate_step_and_flow.err().as_deref(), Some("duplicate Step shared"));

        let step_and_exit = Flow::builder("test-flow")
            .entry("start")
            .exit("shared")
            .step("start", TestStep)
            .step("shared", TestStep)
            .build();

        assert_eq!(
            step_and_exit.err().as_deref(),
            Some("Flow exit shared conflicts with a registered Step")
        );
    }

    #[test]
    fn validates_child_exit_mappings() {
        let valid_child = child_with_exits("child", &["continue", "finish"]);
        let valid_transitions = ExitTransitions::new()
            .transition("continue", "next")
            .expect("the child exit-to-Step transition should be valid")
            .transition("finish", "finished")
            .expect("the child exit-to-exit transition should be valid");
        let parent = Flow::builder("parent")
            .entry("child")
            .exit("finished")
            .flow("child", valid_child, valid_transitions, TraceMode::Expanded)
            .step("next", TestStep)
            .build()
            .expect("complete child exit mappings should be valid");

        let mounted = parent
            .child_flow(&StepId::from("child"))
            .expect("the mounted Step should retain its child Flow");
        assert_eq!(
            mounted
                .exit_transitions
                .target(&StepId::from("continue"))
                .map(|target| target.0.as_str()),
            Some("next")
        );
        assert_eq!(
            mounted
                .exit_transitions
                .target(&StepId::from("finish"))
                .map(|target| target.0.as_str()),
            Some("finished")
        );

        let duplicate = ExitTransitions::new()
            .transition("done", "first")
            .expect("the first child exit transition should be valid")
            .transition("done", "second")
            .err()
            .expect("a child exit must have only one parent target");

        assert_eq!(duplicate, "duplicate target for exit transition done");

        let child_without_exits = child_with_exits("child", &[]);
        let no_exits = Flow::builder("parent")
            .entry("child")
            .exit("finished")
            .flow(
                "child",
                child_without_exits,
                ExitTransitions::new(),
                TraceMode::Expanded,
            )
            .build();

        assert_eq!(
            no_exits.err().as_deref(),
            Some("child Flow Step child must declare at least one exit transition")
        );

        let child = child_with_exits("child", &["done"]);
        let transitions = ExitTransitions::new()
            .transition("done", "finished")
            .expect("the declared child exit transition should be valid")
            .transition("cancelled", "finished")
            .expect("the extra child exit transition should be unique");
        let undeclared = Flow::builder("parent")
            .entry("child")
            .exit("finished")
            .flow("child", child, transitions, TraceMode::Expanded)
            .build();

        assert_eq!(
            undeclared.err().as_deref(),
            Some("cancelled is not an exit transition of child Flow Step child")
        );

        let child = child_with_exits("child", &["done", "cancelled"]);
        let transitions = ExitTransitions::new()
            .transition("done", "finished")
            .expect("the declared child exit transition should be valid");
        let missing = Flow::builder("parent")
            .entry("child")
            .exit("finished")
            .flow("child", child, transitions, TraceMode::Expanded)
            .build();

        assert_eq!(
            missing.err().as_deref(),
            Some("exit transition cancelled of child Flow Step child has no parent target")
        );

        let child = child_with_exits("child", &["done"]);
        let transitions = ExitTransitions::new()
            .transition("done", "missing")
            .expect("the child exit transition should be valid");
        let unknown_target = Flow::builder("parent")
            .entry("child")
            .exit("finished")
            .flow("child", child, transitions, TraceMode::Expanded)
            .build();

        assert_eq!(unknown_target.err().as_deref(), Some("unknown next Step missing"));
    }
}
