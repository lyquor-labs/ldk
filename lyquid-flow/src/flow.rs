use std::fmt;
use std::sync::Arc;

use lyquid::prelude::{HashMap, HashSet, hashbrown::hash_map::Entry, new_hashmap, new_hashset};
use serde::{Deserialize, Serialize};

use crate::scope::{FlowError, Scope};
use crate::state::StateUpdates;
use crate::step::{Step, StepId, TemplateSpec};
use crate::trace::TraceSummary;
use crate::{BuildError, Diagnostic, InputSpec, TurnProposal};

type ViewFn = fn(&Scope) -> Result<crate::ViewSpec, FlowError>;
type HistoryFn = fn(&Scope, Option<&serde_json::Value>) -> Result<Option<serde_json::Value>, FlowError>;

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
    pub fn transition(mut self, exit: impl Into<StepId>, next: impl Into<StepId>) -> Result<Self, BuildError> {
        match self.transitions.entry(exit.into()) {
            Entry::Occupied(entry) => {
                Err(Diagnostic::new(format!("exit {}", entry.key()), "duplicate parent target").into())
            }
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
    /// Optional persistent view of committed State; None presents an empty view.
    view: Option<ViewFn>,
    /// Optional selector for service history checkpoints and metadata at successful input boundaries.
    /// None omits public history checkpoints; execution Trace is unaffected.
    history: Option<HistoryFn>,
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
    /// Child Flow graphs indexed by the same local IDs as their Step implementations.
    flows: HashMap<StepId, Arc<Flow>>,
}

impl FlowBuilder {
    /// Selects checkpoint timing and display metadata for a service-hosted root Flow.
    /// Called at successful input boundaries with committed active-child State and the selected
    /// revision's metadata. Return None to omit this boundary from public history.
    pub fn history(mut self, history: HistoryFn) -> Self {
        self.history = Some(history);
        self
    }

    /// Sets the function that renders this Flow's state into a ViewSpec.
    ///
    /// The same view function is used throughout this Flow's execution.
    /// During a child Flow, it receives the active child's Scope; after the child
    /// joins, it receives this Flow's Scope.
    /// It should read committed state through Scope::state without side effects.
    /// If no view function is set, the view is empty.
    pub fn view(mut self, view: fn(&Scope) -> Result<crate::ViewSpec, FlowError>) -> Self {
        self.view = Some(view);
        self
    }

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
    /// Use [`Self::flow`] or [`Self::flow_with`] to mount a child Flow.
    /// Passing a Flow here returns an execution error without committing the turn.
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
        let id = id.into();
        let flow = self.mount_flow(id.clone(), flow, exit_transitions, trace_mode);
        self.steps.push((id, flow));
        self
    }

    /// Mounts a child Flow with the Step used by the parent.
    ///
    /// The mount owns its exit transitions and Trace mode. Construct the Step from the same
    /// child graph; its Flow finalizer reads this configuration from the running child Scope.
    /// The Step must preserve the Flow's entry proposal and delegate finalization to it.
    /// Its input and model template are evaluated before the child starts;
    /// its finalizer runs after the child completes.
    /// Accepted input remains available to the finalizer and its retries until the parent commits.
    pub fn flow_with<S: Step + 'static>(
        mut self, id: impl Into<StepId>, flow: impl Into<Arc<Flow>>, exit_transitions: ExitTransitions,
        trace_mode: TraceMode, step: S,
    ) -> Self {
        let id = id.into();
        self.mount_flow(id.clone(), flow, exit_transitions, trace_mode);
        self.step(id, step)
    }

    fn mount_flow(
        &mut self, id: StepId, flow: impl Into<Arc<Flow>>, exit_transitions: ExitTransitions, trace_mode: TraceMode,
    ) -> Arc<Flow> {
        let mut flow = flow.into().as_ref().clone();
        flow.exit_transitions = exit_transitions;
        flow.trace_mode = trace_mode;
        let flow = Arc::new(flow);
        self.flows.insert(id, Arc::clone(&flow));
        flow
    }

    /// Validates and freezes this reusable Flow graph.
    pub fn build(self) -> Result<Flow, BuildError> {
        let [entry] = self.entries.as_slice() else {
            return Err(Diagnostic::new(
                "Flow entry",
                format!("expected exactly one entry Step, got {}", self.entries.len()),
            )
            .into());
        };

        let mut steps = new_hashmap();
        for (id, node) in self.steps {
            if steps.insert(id.clone(), node).is_some() {
                return Err(Diagnostic::new(format!("Step {id}"), "duplicate Step").into());
            }
        }
        validate_entry(entry, &steps)?;
        validate_exit_boundaries(&self.exits, &steps)?;
        validate_child_exit_transitions(&self.flows)?;

        let flow = Flow {
            view: self.view,
            history: self.history,
            id: self.id,
            description: self.description,
            entry: entry.clone(),
            exits: self.exits,
            steps,
            flows: self.flows,
            exit_transitions: ExitTransitions::new(),
            trace_mode: TraceMode::Expanded,
        };
        flow.validate_exit_transition_targets()?;
        Ok(flow)
    }
}

/// A reusable workflow graph that also implements [`Step`] when mounted with [`FlowBuilder::flow`]
/// or [`FlowBuilder::flow_with`].
///
/// Mounting shallow-clones the graph and configures that mount's exit mapping and Trace mode.
/// [`FlowBuilder::flow_with`] registers a caller-supplied Step for that mount.
/// A parent executes the child graph by forking a child [`crate::Scope`].
/// The child inherits an immutable snapshot of its parent Scope while keeping local State versions
/// and Trace entries until it exits. The parent then
/// applies the child's accumulated State updates and follows the configured exit transition.
#[derive(Clone)]
pub struct Flow {
    /// Optional persistent view of committed State; None presents an empty view.
    pub(super) view: Option<ViewFn>,
    /// Optional selector for service history checkpoints and metadata at successful input boundaries.
    /// None omits public history checkpoints; execution Trace is unaffected.
    pub(super) history: Option<HistoryFn>,
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
    /// Child graphs indexed by the same local IDs as their Step implementations.
    flows: HashMap<StepId, Arc<Self>>,
    /// Parent-local targets configured when this Flow is mounted as a Step.
    exit_transitions: ExitTransitions,
    /// Representation configured for this Flow's Trace when mounted as a Step.
    trace_mode: TraceMode,
}

impl Flow {
    /// Starts declaring a reusable Flow with its stable identity.
    pub fn builder(id: impl Into<FlowId>) -> FlowBuilder {
        FlowBuilder {
            view: None,
            history: None,
            id: id.into(),
            description: String::new(),
            entries: Vec::new(),
            exits: new_hashset(),
            steps: Vec::new(),
            flows: new_hashmap(),
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

    pub(super) fn step_ids(&self) -> impl Iterator<Item = &StepId> {
        self.steps.keys()
    }

    pub(super) fn step_cloned(&self, id: &StepId) -> Option<Arc<dyn Step>> {
        self.steps.get(id).map(Arc::clone)
    }

    pub(super) fn child_flow(&self, id: &StepId) -> Option<Arc<Self>> {
        self.flows.get(id).map(Arc::clone)
    }

    pub(super) fn exits(&self) -> &HashSet<StepId> {
        &self.exits
    }

    fn validate_exit_transition_targets(&self) -> Result<(), BuildError> {
        for (child, flow) in &self.flows {
            for (exit, next) in &flow.exit_transitions.transitions {
                if !self.steps.contains_key(next) && !self.exits.contains(next) {
                    return Err(Diagnostic::new(
                        format!("child {child} exit {exit}"),
                        format!("unknown next Step {next}"),
                    )
                    .into());
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
        let child = scope
            .running_child()
            .ok_or_else(|| FlowError::from("child Flow must be mounted with FlowBuilder::flow"))?;
        let TurnProposal::Advance { next, updates } = proposal else {
            panic!("a child Flow completes by advancing through one of its declared exit transitions");
        };
        let exit = next
            .as_ref()
            .expect("a child Flow completes through one of its declared exit transitions");
        let mounted = child.flow();
        let target = mounted
            .exit_transitions
            .target(exit)
            .expect("all mounted Flow exits have validated parent transitions")
            .clone();
        let summary = match &mounted.trace_mode {
            TraceMode::Expanded => TraceSummary::SubFlow(child.trace().clone()),
            TraceMode::Collapsed(summary) => TraceSummary::Summary(summary.clone()),
        };
        *next = Some(target);
        *updates = child.accumulated_updates();
        Ok(summary)
    }
}

fn validate_entry(entry: &StepId, steps: &HashMap<StepId, Arc<dyn Step>>) -> Result<(), BuildError> {
    if steps.contains_key(entry) {
        Ok(())
    } else {
        Err(Diagnostic::new(format!("entry {entry}"), "unknown Flow entry Step").into())
    }
}

fn validate_exit_boundaries(exits: &HashSet<StepId>, steps: &HashMap<StepId, Arc<dyn Step>>) -> Result<(), BuildError> {
    if let Some(exit) = exits.iter().find(|exit| steps.contains_key(*exit)) {
        return Err(Diagnostic::new(format!("exit {exit}"), "conflicts with a registered Step").into());
    }
    Ok(())
}

fn validate_child_exit_transitions(flows: &HashMap<StepId, Arc<Flow>>) -> Result<(), BuildError> {
    for (id, flow) in flows {
        validate_exit_transitions(id, flow, &flow.exit_transitions)?;
    }
    Ok(())
}

fn validate_exit_transitions(id: &StepId, flow: &Flow, exit_transitions: &ExitTransitions) -> Result<(), BuildError> {
    if flow.exits.is_empty() {
        return Err(Diagnostic::new(format!("child {id}"), "must declare at least one exit transition").into());
    }

    let declared = &exit_transitions.transitions;
    if let Some(exit) = declared.keys().find(|exit| !flow.exits.contains(*exit)) {
        return Err(Diagnostic::new(format!("child {id} exit {exit}"), "not a declared exit transition").into());
    }
    if let Some(exit) = flow.exits.iter().find(|exit| !declared.contains_key(*exit)) {
        return Err(Diagnostic::new(format!("child {id} exit {exit}"), "has no parent target").into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AutoCheckpointConfig, State, Type, ViewSpec};
    use lyquid::prelude::Mutex;
    use lyquid_test::test;
    use serde_json::json;

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

    struct ObservedStep<S> {
        inner: S,
        name: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
        exit: Option<StepId>,
        fail_once: Mutex<bool>,
    }

    impl<S: Step> Step for ObservedStep<S> {
        fn description(&self, concise: bool) -> String {
            self.inner.description(concise)
        }

        fn input(&self, scope: &Scope) -> Option<InputSpec> {
            self.calls.lock().push(format!("{}.input", self.name));
            self.inner.input(scope)
        }

        fn model_template(&self, scope: &Scope) -> TemplateSpec {
            self.calls.lock().push(format!("{}.template", self.name));
            self.inner.model_template(scope)
        }

        fn model_context(&self, _scope: &Scope) -> Result<serde_json::Value, FlowError> {
            panic!("these Steps skip the model")
        }

        fn finalize(&self, scope: &Scope, proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
            self.calls.lock().push(format!("{}.finalize", self.name));
            let summary = self.inner.finalize(scope, proposal)?;
            let TurnProposal::Advance { next, updates } = proposal else {
                panic!("these Steps always advance")
            };
            if let Some(exit) = &self.exit {
                *next = Some(exit.clone());
            }
            updates.set("result".into(), Some(json!(self.name)));
            if std::mem::take(&mut *self.fail_once.lock()) {
                return Err("finalization failed".into());
            }
            Ok(summary)
        }
    }

    #[test]
    fn mounted_step_hooks_and_finalizer_retry() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let child = Flow::builder("child")
            .view(|_| panic!("a mounted child must not select the parent's State view"))
            .entry("inside")
            .exit("done")
            .step(
                "inside",
                ObservedStep {
                    inner: TestStep,
                    name: "child",
                    calls: Arc::clone(&calls),
                    exit: Some("done".into()),
                    fail_once: Mutex::new(false),
                },
            )
            .build()
            .unwrap();
        let step = ObservedStep {
            inner: child.clone(),
            name: "parent",
            calls: Arc::clone(&calls),
            exit: None,
            fail_once: Mutex::new(true),
        };
        let parent = Flow::builder("parent")
            .view(|scope| {
                let ui = ViewSpec::builder();
                ui.data("result", scope.state().get("result"));
                Ok(ViewSpec::finish(&ui, ui.text("Parent State"))?)
            })
            .entry("child")
            .exit("finished")
            .flow_with(
                "child",
                child,
                ExitTransitions::new().transition("done", "finished").unwrap(),
                TraceMode::Collapsed("mounted child".into()),
                step,
            )
            .build()
            .unwrap();
        let state = State::builder()
            .field("result", "Result", Type::String, json!(""))
            .build()
            .unwrap();
        let mut scope = Scope::new(Arc::new(parent), state, AutoCheckpointConfig::Disabled, None);

        assert!(scope.advance().is_err());
        assert_eq!(
            *calls.lock(),
            [
                "parent.input",
                "parent.template",
                "child.input",
                "child.template",
                "child.finalize",
                "parent.finalize",
            ]
        );
        assert_eq!(scope.state().get("result"), Some(&json!("")));
        assert!(scope.trace().entries.is_empty());
        assert!(!scope.is_finished());
        let waiting = scope.view().unwrap();
        assert_eq!(waiting.ui().data()["result"], "child");
        let saved = scope.clone();
        let checkpoint = scope.checkpoint();

        scope.advance().unwrap();
        assert!(scope.is_finished());
        assert_eq!(calls.lock().len(), 7);
        assert_eq!(calls.lock().last().unwrap(), "parent.finalize");
        assert_eq!(scope.state().get("result"), Some(&json!("parent")));
        assert_eq!(scope.trace().entries.len(), 1);
        assert!(matches!(
            &scope.trace().entries[0].summary,
            TraceSummary::Summary(summary) if summary == "mounted child"
        ));
        let completed = scope.view().unwrap();
        assert_eq!(completed.ui().data()["result"], "parent");
        assert_eq!(saved.view().unwrap().ui().data()["result"], "child");

        scope.restore(&checkpoint).unwrap();
        assert!(!scope.is_finished());
        assert_eq!(scope.state().get("result"), Some(&json!("")));
        assert_eq!(scope.view().unwrap().ui().data()["result"], "child");
        scope.advance().unwrap();
        assert!(scope.is_finished());
        assert_eq!(scope.view().unwrap().ui().data()["result"], "parent");

        let mut parent = scope.flow().clone();
        parent.view = None;
        let mut scope = Scope::new(
            Arc::new(parent),
            scope.state().clone(),
            AutoCheckpointConfig::Disabled,
            None,
        );
        let empty = serde_json::to_value(ViewSpec::default()).unwrap();
        assert_eq!(serde_json::to_value(scope.view().unwrap()).unwrap(), empty);
        scope.advance().unwrap();
        assert!(scope.is_finished());
        assert_eq!(serde_json::to_value(scope.view().unwrap()).unwrap(), empty);
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
    fn unmounted_flow_step_returns_execution_error() {
        let parent = Flow::builder("parent")
            .entry("child")
            .step("child", child_with_exits("child", &["done"]))
            .build()
            .unwrap();
        let state = State::builder()
            .field("count", "Unchanged count", Type::U64, json!(1))
            .build()
            .unwrap();
        let mut scope = Scope::new(Arc::new(parent), state, AutoCheckpointConfig::Disabled, None);

        let error = scope.advance().unwrap_err();

        assert_eq!(error.to_string(), "child Flow must be mounted with FlowBuilder::flow");
        assert_eq!(scope.state().get("count"), Some(&json!(1)));
        assert!(scope.trace().entries.is_empty());
        assert_eq!(scope.current_step().0, "child");
        assert!(!scope.is_finished());
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

        assert_eq!(
            missing.err().unwrap().to_string(),
            "Flow entry: expected exactly one entry Step, got 0"
        );

        let multiple = Flow::builder("test-flow")
            .entry("start")
            .entry("other")
            .step("start", TestStep)
            .step("other", TestStep)
            .build();

        assert_eq!(
            multiple.err().unwrap().to_string(),
            "Flow entry: expected exactly one entry Step, got 2"
        );

        let unknown = Flow::builder("test-flow")
            .entry("missing")
            .step("start", TestStep)
            .build();

        assert_eq!(
            unknown.err().unwrap().to_string(),
            "entry missing: unknown Flow entry Step"
        );
    }

    #[test]
    fn rejects_conflicting_flow_names() {
        let duplicate_steps = Flow::builder("test-flow")
            .entry("start")
            .step("start", TestStep)
            .step("start", TestStep)
            .build();

        assert_eq!(duplicate_steps.err().unwrap().to_string(), "Step start: duplicate Step");

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

        assert_eq!(
            duplicate_step_and_flow.err().unwrap().to_string(),
            "Step shared: duplicate Step"
        );

        let step_and_exit = Flow::builder("test-flow")
            .entry("start")
            .exit("shared")
            .step("start", TestStep)
            .step("shared", TestStep)
            .build();

        assert_eq!(
            step_and_exit.err().unwrap().to_string(),
            "exit shared: conflicts with a registered Step"
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

        assert_eq!(duplicate.to_string(), "exit done: duplicate parent target");

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
            no_exits.err().unwrap().to_string(),
            "child child: must declare at least one exit transition"
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
            undeclared.err().unwrap().to_string(),
            "child child exit cancelled: not a declared exit transition"
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
            missing.err().unwrap().to_string(),
            "child child exit cancelled: has no parent target"
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

        assert_eq!(
            unknown_target.err().unwrap().to_string(),
            "child child exit done: unknown next Step missing"
        );
    }
}
