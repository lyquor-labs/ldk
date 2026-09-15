use std::collections::VecDeque;
use std::fmt::{self, Write as _};
use std::num::NonZeroUsize;
use std::sync::Arc;

use lyquid::prelude::{HashMap, Mutex, new_hashmap};
use lyquid_llm::{Backend, FinishReason, ModelRequest};
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::flow::Flow;
use crate::prompt;
use crate::state::{State, StateNamespace, StateUpdates};
use crate::step::{Input, InputSpec, Step, StepId, TemplateSpec};
use crate::trace::{Trace, TraceEntry, TraceSummary};
use crate::turn::TurnProposal;

/// Opaque identity of one Scope execution or saved Scope checkpoint.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ScopeId(pub String);

impl From<&str> for ScopeId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl fmt::Display for ScopeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Generates a collision-resistant identity for a newly created Scope execution.
fn new_execution_id() -> ScopeId {
    let bytes = lyquid::prelude::lyquor_api::random_bytes(16)
        .expect("Lyquor runtime must provide entropy for Scope execution IDs");

    assert_eq!(bytes.len(), 16, "Scope execution ID entropy must contain 16 bytes");
    let mut id = String::with_capacity(32);
    for byte in bytes {
        write!(&mut id, "{byte:02x}").expect("writing a Scope execution ID to String cannot fail");
    }
    ScopeId(id)
}

/// Controls automatic Flow-local checkpoints for one Scope execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutoCheckpointConfig {
    /// Do not create automatic checkpoints.
    Disabled,
    /// Retain only the most recent automatic checkpoints.
    Recent(NonZeroUsize),
    /// Retain every automatic checkpoint for the lifetime of the Scope.
    Unbounded,
}

/// Errors produced while advancing a Scope.
#[derive(Debug, thiserror::Error)]
pub enum FlowError {
    /// The configured model backend failed.
    #[error("model call failed: {0}")]
    Model(#[from] lyquid_llm::LlmError),
    /// Flow validation or Step execution failed.
    #[error("{0}")]
    Execution(String),
}

impl From<String> for FlowError {
    fn from(error: String) -> Self {
        Self::Execution(error)
    }
}

/// Fully resolved target of a transition within one Scope.
enum ResolvedTarget {
    /// Begin another Step in this Scope.
    Step(StepId),
    /// Finish this Scope, optionally through a declared exit.
    Finished(Option<StepId>),
}

/// Cloneable input endpoint for one Scope execution tree.
///
/// A root Scope and every nested child Scope share the same endpoint. Because Flow execution is
/// sequential, at most one Step in that tree can have a pending request. Clones may be stored or
/// passed to another instance function without sharing the mutable Scope itself.
#[derive(Clone)]
pub struct InputHandle {
    pending: Arc<Mutex<Option<PendingInput>>>,
}

/// One active Step input request and the endpoint that resumes its blocked execution.
struct PendingInput {
    /// Contract used to type-check values offered while the Step is waiting.
    spec: InputSpec,
    /// One-shot endpoint used to deliver the accepted value to the waiting Step.
    sender: lyquid::oneshot::Sender<Input>,
}

impl InputHandle {
    fn new() -> Self {
        Self {
            pending: Arc::new(Mutex::new(None)),
        }
    }

    /// Offers one value to the current input request and wakes the blocked execution.
    ///
    /// Returns `true` when the value matched and was delivered. Returns `false` when there is no
    /// current request or its expected concrete value type differs; a mismatch leaves the request
    /// pending so a corrected value can still be offered.
    pub fn offer_input(&self, input: Input) -> bool {
        let sender = {
            let mut pending = self.pending.lock();
            let Some(request) = pending.as_ref() else {
                return false;
            };
            if request.spec.value.as_ref().type_id() != input.as_ref().type_id() {
                return false;
            }
            pending
                .take()
                .expect("the pending input request was checked above")
                .sender
        };

        sender.send(input).is_ok()
    }

    /// Returns the input contract currently published by this execution tree.
    ///
    /// The contract remains available while [`Scope::advance`] waits for its value, including
    /// requests made by nested child Flows.
    pub fn input_spec(&self) -> Option<InputSpec> {
        self.pending.lock().as_ref().map(|pending| pending.spec.clone())
    }

    fn wait(&self, spec: InputSpec) -> Result<Input, String> {
        let (sender, receiver) = lyquid::oneshot::channel();
        {
            let mut pending = self.pending.lock();
            if pending.is_some() {
                return Err("the Flow execution already has a pending input request".to_owned());
            }
            *pending = Some(PendingInput { spec, sender });
        }

        receiver
            .recv()
            .map_err(|_| "the pending input request closed before delivery".to_owned())
    }
}

/// Read-only State and Trace inherited from an enclosing Scope.
#[derive(Clone)]
pub struct ScopeSnapshot {
    /// Earlier enclosing Scope snapshot, if this execution is nested more than one level.
    parent: Option<Arc<Self>>,
    /// State version visible when the child Scope was forked.
    state: Arc<State>,
    /// Trace visible when the child Scope was forked.
    trace: Arc<Trace>,
}

impl ScopeSnapshot {
    /// Returns the next enclosing Scope snapshot, if any.
    pub fn parent(&self) -> Option<&Self> {
        self.parent.as_deref()
    }

    /// Returns the inherited State version.
    pub fn state(&self) -> &State {
        self.state.as_ref()
    }

    /// Returns the inherited Trace.
    pub fn trace(&self) -> &Trace {
        self.trace.as_ref()
    }
}

/// Mutable execution state for one reusable Flow graph.
pub struct Scope {
    /// Immutable connection logic bound to this execution.
    flow: Arc<Flow>,
    /// Unique identity of this mutable execution.
    execution_id: ScopeId,
    /// Read-only execution snapshot inherited from the enclosing Scope.
    parent: Option<ScopeSnapshot>,
    /// Latest committed State version visible to this Flow execution.
    state: Arc<State>,
    /// Ordered Trace entries committed locally by this Flow execution.
    trace: Arc<Trace>,
    /// Uncommitted values owned by the active Step.
    updates: StateUpdates,
    /// Whole-field replacements committed locally since this execution was created or forked.
    accumulated_updates: StateUpdates,
    /// Current Step, or the exit through which a finished Scope returned.
    ///
    /// While a child Flow Step is running, this remains the child's Step ID in the parent Flow;
    /// the child Scope owns its independent internal cursor. When Finalization completes a
    /// root Flow with `None`, this remains the Step that completed it.
    current_step: StepId,
    /// Model configuration shared with template-backed child Scopes.
    model_config: Option<ModelConfig>,
    /// Input endpoint shared by the complete root-to-leaf execution tree.
    input_handle: InputHandle,
    /// Whether this execution must finish through one of its Flow's declared exits.
    requires_exit: bool,
    /// Automatic checkpoint policy for this execution and newly created child Scopes.
    auto_checkpoint_config: AutoCheckpointConfig,
    /// Immutable restore points belonging only to this Flow execution.
    checkpoints: HashMap<ScopeId, Self>,
    /// Automatic checkpoints ordered from oldest to newest for bounded retention.
    auto_checkpoints: VecDeque<ScopeId>,
    /// Monotonic sequence used to allocate checkpoint IDs without reusing retained or removed IDs.
    next_checkpoint_sequence: u64,
    /// Current runner position and any active child execution.
    phase: RunPhase,
}

/// Clones this execution point into an independently usable Scope.
///
/// The clone and its active descendant Scopes receive fresh execution IDs on a new shared input
/// endpoint. Flow-local checkpoint collections are not copied at any level, so the returned Scope
/// begins with no restore history of its own.
impl Clone for Scope {
    fn clone(&self) -> Self {
        let phase = match &self.phase {
            RunPhase::Start => RunPhase::Start,
            RunPhase::RunningChild(child) => RunPhase::RunningChild(child.clone()),
            RunPhase::Finished(exit) => RunPhase::Finished(exit.clone()),
        };

        let mut cloned = Self {
            flow: Arc::clone(&self.flow),
            execution_id: new_execution_id(),
            parent: self.parent.clone(),
            state: Arc::clone(&self.state),
            trace: Arc::clone(&self.trace),
            updates: self.updates.clone(),
            accumulated_updates: self.accumulated_updates.clone(),
            current_step: self.current_step.clone(),
            model_config: self.model_config.clone(),
            input_handle: InputHandle::new(),
            requires_exit: self.requires_exit,
            auto_checkpoint_config: self.auto_checkpoint_config,
            checkpoints: new_hashmap(),
            auto_checkpoints: VecDeque::new(),
            next_checkpoint_sequence: 0,
            phase,
        };
        let input_handle = cloned.input_handle.clone();
        cloned.rebind_input_handle(input_handle);
        cloned
    }
}

impl Scope {
    /// Creates one execution bound to a reusable Flow and its initial State.
    ///
    /// Reaching a model-backed Step returns an error when `model_config` is `None`.
    pub fn new(
        flow: Arc<Flow>, state: State, auto_checkpoint_config: AutoCheckpointConfig, model_config: Option<ModelConfig>,
    ) -> Self {
        let current_step = flow.entry().clone();
        let mut scope = Self {
            flow,
            execution_id: new_execution_id(),
            parent: None,
            state: Arc::new(state),
            trace: Arc::new(Trace::default()),
            updates: StateUpdates::default(),
            accumulated_updates: StateUpdates::default(),
            current_step,
            model_config,
            input_handle: InputHandle::new(),
            requires_exit: false,
            auto_checkpoint_config,
            checkpoints: new_hashmap(),
            auto_checkpoints: VecDeque::new(),
            next_checkpoint_sequence: 0,
            phase: RunPhase::Start,
        };
        scope.auto_checkpoint();
        scope
    }

    /// Returns the unique identity of this mutable execution.
    pub fn execution_id(&self) -> &ScopeId {
        &self.execution_id
    }

    /// Returns the read-only parent snapshot inherited by this nested execution, if any.
    pub fn parent(&self) -> Option<&ScopeSnapshot> {
        self.parent.as_ref()
    }

    /// Returns the latest immutable State version visible in this execution.
    pub fn state(&self) -> &State {
        self.state.as_ref()
    }

    /// Returns the Trace committed locally by this Flow.
    pub fn trace(&self) -> &Trace {
        self.trace.as_ref()
    }

    /// Returns one Step-scoped value from the requested namespace.
    pub fn get<V: crate::Value>(&self, namespace: StateNamespace, name: &str) -> Option<&V> {
        match namespace {
            StateNamespace::Default => self.updates.get(name),
            StateNamespace::Input => self.updates.get_ephemeral(namespace, name),
        }
    }

    /// Adds, replaces, or removes one Step-scoped value in the requested namespace.
    pub fn set(&mut self, namespace: StateNamespace, name: String, value: Option<Box<dyn crate::Value>>) {
        match namespace {
            StateNamespace::Default => self.updates.set(name, value),
            StateNamespace::Input => self.updates.set_ephemeral(namespace, name, value),
        }
    }

    pub(super) fn updates(&self) -> &StateUpdates {
        &self.updates
    }

    /// Returns a cloneable endpoint that can offer input without sharing this mutable Scope.
    ///
    /// The returned handle also serves input requests made by nested child Flows in this execution.
    pub fn input_handle(&self) -> InputHandle {
        self.input_handle.clone()
    }

    /// Returns this Scope's current Step ID, its final exit, or the Step that completed it.
    ///
    /// This remains the composite Step ID while a child Flow is running.
    pub fn current_step(&self) -> &StepId {
        &self.current_step
    }

    /// Reports whether this Scope has completed, with or without a declared exit.
    pub fn is_finished(&self) -> bool {
        matches!(self.phase, RunPhase::Finished(_))
    }

    /// Advances this execution by one Step at its Flow's level.
    ///
    /// When the current Step is a mounted Flow, this runs the child Flow until it exits and then
    /// commits the mounted Flow once as the parent Step. Template-backed Steps call the model
    /// backend retained by this Scope.
    pub fn advance(&mut self) -> Result<(), FlowError> {
        let previous_updates = self.updates.clone();
        let result = if self.running_child().is_some() {
            self.advance_child()
        } else if self.is_finished() {
            Ok(())
        } else {
            self.begin_step()
        };
        if result.is_err() {
            // Roll back Step-scoped State changes from the failed execution attempt.
            self.updates = previous_updates;
        }
        result
    }

    /// Enters a fresh Step, waits for input when required, and evaluates its model template.
    fn begin_step(&mut self) -> Result<(), FlowError> {
        let step = self.current_step_cloned()?;
        if let Some(spec) = step.input(self) {
            let name = spec.name.clone();
            let input = self.wait_for_input(spec)?;
            self.set(StateNamespace::Input, name, Some(input));
        }
        self.process_model_template(step)
    }

    /// Forks and starts a child Scope with inherited State and shared runtime configuration.
    fn start_child(&mut self, child_flow: Arc<Flow>) -> Result<(), FlowError> {
        let updates = std::mem::take(&mut self.updates);
        let child = self.fork_child(child_flow, updates);
        self.phase = RunPhase::RunningChild(Box::new(child));
        self.advance_child()
    }

    /// Runs the active child until it reaches an exit, then joins it into the parent.
    fn advance_child(&mut self) -> Result<(), FlowError> {
        loop {
            let finished = {
                let child = self
                    .running_child_mut()
                    .expect("advance_child is called only while a child is active");
                child.advance()?;
                child.is_finished()
            };
            if finished {
                self.updates = StateUpdates::default();
                return self.join_child();
            }
        }
    }

    /// Finalizes a completed child Flow Step and commits it once in the parent.
    fn join_child(&mut self) -> Result<(), FlowError> {
        let exit = match self.running_child().and_then(Self::finished_exit) {
            Some(Some(exit)) => exit.clone(),
            Some(None) => {
                return Err(FlowError::Execution(
                    "a child Flow cannot complete without a declared exit transition".to_owned(),
                ))
            }
            None => return Err(FlowError::Execution("cannot join an unfinished child Scope".to_owned())),
        };
        let mut proposal = TurnProposal::Advance {
            next: Some(exit),
            updates: StateUpdates::default(),
        };
        let step = self.current_step_cloned()?;
        let summary = step.finalize(self, &mut proposal)?;

        self.commit_proposal(proposal, summary)
    }

    /// Evaluates the current Step's model template with Step-scoped context.
    fn process_model_template(&mut self, step: Arc<dyn Step>) -> Result<(), FlowError> {
        let proposal = match step.model_template(self) {
            TemplateSpec::Template(template) => {
                let next_options = self.flow.next_options(self.requires_exit);
                let request = prompt::build_request(
                    self.model()?,
                    template,
                    prompt::PromptContext {
                        flow_description: self.flow.description(),
                        scope: self,
                        next_options,
                    },
                )?;
                let output = self.call_model(request)?;
                prompt::parse_response(self.state(), &output)?
            }
            TemplateSpec::Skip(proposal) => proposal,
        };
        self.run_finalize(step.as_ref(), proposal)
    }

    /// Finalizes an ordinary Step, or starts a child Flow that will be finalized when it exits.
    fn run_finalize(&mut self, step: &dyn Step, mut proposal: TurnProposal) -> Result<(), FlowError> {
        if let Some(child_flow) = self.flow.child_flow(self.current_step()) {
            let TurnProposal::Advance { next, mut updates } = proposal else {
                return Err(FlowError::Execution(
                    "a child Flow Step must advance to its entry Step before it can run".to_owned(),
                ));
            };
            updates.merge(std::mem::take(&mut self.updates));
            self.state().validate_updates(&updates)?;
            if next.as_ref() != Some(child_flow.entry()) {
                return Err(FlowError::Execution(format!(
                    "child Flow Step must start at its entry Step {}",
                    child_flow.entry()
                )));
            }
            self.updates = updates;
            return self.start_child(child_flow);
        }

        let summary = step.finalize(self, &mut proposal)?;
        self.commit_proposal(proposal, summary)
    }

    /// Validates and commits one finalized proposal.
    fn commit_proposal(&mut self, proposal: TurnProposal, summary: TraceSummary) -> Result<(), FlowError> {
        match proposal {
            TurnProposal::Advance { next, mut updates } => {
                updates.merge(std::mem::take(&mut self.updates));
                self.state().validate_updates(&updates)?;
                let next = self.resolve_next(&next)?;
                self.updates = updates;
                self.commit_state_transition(next, summary)?;
                self.auto_checkpoint();
                Ok(())
            }
            TurnProposal::Restore { scope: checkpoint } => self.restore(&checkpoint),
        }
    }

    fn resolve_next(&self, next: &Option<StepId>) -> Result<ResolvedTarget, String> {
        let Some(next) = next else {
            if self.requires_exit {
                return Err("a child Flow must complete through a declared exit transition".to_owned());
            }
            return Ok(ResolvedTarget::Finished(None));
        };
        if self.flow.exits().contains(next) {
            Ok(ResolvedTarget::Finished(Some(next.clone())))
        } else if self.flow.step(next).is_some() {
            Ok(ResolvedTarget::Step(next.clone()))
        } else {
            Err(format!("unknown next Step {next}"))
        }
    }

    fn current_step_cloned(&self) -> Result<Arc<dyn Step>, String> {
        self.flow
            .step_cloned(&self.current_step)
            .ok_or_else(|| format!("unknown current Step {}", self.current_step))
    }

    /// Saves the current execution point as a Flow-local checkpoint and returns its ID.
    ///
    /// The checkpoint ID is qualified by this Scope's Flow and execution IDs plus a monotonic local
    /// sequence. The saved Scope is an independent clone with its own execution ID.
    pub fn checkpoint(&mut self) -> ScopeId {
        let sequence = self.next_checkpoint_sequence;
        self.next_checkpoint_sequence = sequence.checked_add(1).expect("Scope checkpoint ID sequence exhausted");
        let id = ScopeId(format!(
            "{}-{}-checkpoint-{sequence}",
            self.flow.id(),
            self.execution_id
        ));
        let checkpoint = self.clone();
        let previous = self.checkpoints.insert(id.clone(), checkpoint);
        debug_assert!(previous.is_none(), "a monotonic Scope checkpoint ID must be unique");
        id
    }

    /// Saves an automatic checkpoint and applies this execution's configured retention.
    fn auto_checkpoint(&mut self) {
        if self.is_finished() {
            return;
        }
        let retain = match self.auto_checkpoint_config {
            AutoCheckpointConfig::Disabled => return,
            AutoCheckpointConfig::Recent(retain) => Some(retain.get()),
            AutoCheckpointConfig::Unbounded => None,
        };
        let id = self.checkpoint();
        self.auto_checkpoints.push_back(id);

        if let Some(retain) = retain {
            while self.auto_checkpoints.len() > retain {
                let expired = self
                    .auto_checkpoints
                    .pop_front()
                    .expect("an oversized auto-checkpoint queue cannot be empty");
                self.checkpoints.remove(&expired);
            }
        }
    }

    /// Restores one checkpoint belonging to this Flow execution.
    ///
    /// Restoring rewinds this execution and therefore preserves its execution ID. It does not adopt
    /// the independent ID allocated to the saved checkpoint Scope.
    pub fn restore(&mut self, id: &ScopeId) -> Result<(), FlowError> {
        let input_handle = self.input_handle.clone();
        let execution_id = self.execution_id.clone();
        let checkpoint = self
            .checkpoints
            .get(id)
            .ok_or_else(|| FlowError::Execution(format!("unknown Scope checkpoint {id}")))?;
        let mut restored = checkpoint.clone();
        restored.execution_id = execution_id;
        restored.rebind_input_handle(input_handle);
        restored.checkpoints = std::mem::take(&mut self.checkpoints);
        restored.auto_checkpoints = std::mem::take(&mut self.auto_checkpoints);
        restored.next_checkpoint_sequence = self.next_checkpoint_sequence;
        *self = restored;
        Ok(())
    }

    /// Rebinds this complete active execution tree to one input endpoint.
    fn rebind_input_handle(&mut self, input_handle: InputHandle) {
        self.input_handle = input_handle.clone();
        if let RunPhase::RunningChild(child) = &mut self.phase {
            child.rebind_input_handle(input_handle);
        }
    }

    /// Returns the checkpoints available to Steps in this Flow execution.
    pub fn checkpoint_ids(&self) -> impl Iterator<Item = &ScopeId> {
        self.checkpoints.keys()
    }

    pub(super) fn running_child(&self) -> Option<&Self> {
        match &self.phase {
            RunPhase::RunningChild(child) => Some(child.as_ref()),
            RunPhase::Start | RunPhase::Finished(_) => None,
        }
    }

    fn running_child_mut(&mut self) -> Option<&mut Self> {
        match &mut self.phase {
            RunPhase::RunningChild(child) => Some(child.as_mut()),
            RunPhase::Start | RunPhase::Finished(_) => None,
        }
    }

    fn finished_exit(&self) -> Option<Option<&StepId>> {
        match &self.phase {
            RunPhase::Finished(exit) => Some(exit.as_ref()),
            RunPhase::Start | RunPhase::RunningChild(_) => None,
        }
    }

    /// Creates a nested execution without cloning the parent's cursor or lifecycle state.
    fn fork_child(&self, flow: Arc<Flow>, updates: StateUpdates) -> Self {
        let parent = ScopeSnapshot {
            parent: self.parent.clone().map(Arc::new),
            state: Arc::clone(&self.state),
            trace: Arc::clone(&self.trace),
        };
        let mut state = self.state.as_ref().clone();
        state.apply_updates(&updates);
        let current_step = flow.entry().clone();
        let mut child = Self {
            flow,
            execution_id: new_execution_id(),
            parent: Some(parent),
            state: Arc::new(state),
            trace: Arc::new(Trace::default()),
            updates: StateUpdates::default(),
            accumulated_updates: updates,
            current_step,
            model_config: self.model_config.clone(),
            input_handle: self.input_handle.clone(),
            requires_exit: true,
            auto_checkpoint_config: self.auto_checkpoint_config,
            checkpoints: new_hashmap(),
            auto_checkpoints: VecDeque::new(),
            next_checkpoint_sequence: 0,
            phase: RunPhase::Start,
        };
        child.auto_checkpoint();
        child
    }

    fn model(&self) -> Result<&str, FlowError> {
        self.model_config
            .as_ref()
            .map(|config| config.model.as_str())
            .ok_or_else(|| {
                FlowError::Execution("Scope model configuration is missing for a template-backed Step".to_owned())
            })
    }

    fn call_model(&self, request: ModelRequest) -> Result<String, FlowError> {
        let model_config = self.model_config.as_ref().ok_or_else(|| {
            FlowError::Execution("Scope model configuration is missing for a template-backed Step".to_owned())
        })?;
        let request = match model_config.max_output_tokens {
            Some(max_output_tokens) => request.max_output_tokens(max_output_tokens),
            None => request,
        };
        let request = request.body_fields(model_config.request_body_fields.clone());
        let response = lyquid_llm::call_model(model_config.backend.as_ref(), &request).map_err(FlowError::Model)?;
        if response.finish_reason == Some(FinishReason::Length) {
            return Err(FlowError::Execution(
                "model output exceeded the configured output-token budget".to_owned(),
            ));
        }
        response
            .text
            .ok_or_else(|| FlowError::Execution("model returned no text".to_owned()))
    }

    fn wait_for_input(&self, spec: InputSpec) -> Result<Input, FlowError> {
        self.input_handle.wait(spec).map_err(FlowError::Execution)
    }

    /// Atomically commits the active Step's staged replacements, resolved target, and Trace entry.
    fn commit_state_transition(&mut self, next: ResolvedTarget, summary: TraceSummary) -> Result<(), FlowError> {
        self.state.validate_updates(&self.updates)?;
        let mut next_state = self.state.as_ref().clone();
        next_state.apply_updates(&self.updates);
        let next_state = Arc::new(next_state);
        let updates = std::mem::take(&mut self.updates);
        let completed_step = self.current_step.clone();
        let mut next_trace = self.trace.as_ref().clone();
        next_trace.entries.push(TraceEntry {
            step: completed_step,
            state: Arc::clone(&next_state),
            summary,
        });

        self.state = next_state;
        self.trace = Arc::new(next_trace);
        self.accumulated_updates.merge(updates);
        match next {
            ResolvedTarget::Step(step) => {
                self.current_step = step;
                self.phase = RunPhase::Start;
            }
            ResolvedTarget::Finished(exit) => {
                if let Some(exit) = &exit {
                    self.current_step = exit.clone();
                }
                self.phase = RunPhase::Finished(exit);
            }
        }
        Ok(())
    }

    pub(super) fn accumulated_updates(&self) -> StateUpdates {
        self.accumulated_updates.clone()
    }
}

/// Model selection and provider adapter shared by one Flow execution tree.
#[derive(Clone)]
pub struct ModelConfig {
    model: String,
    backend: Arc<dyn Backend>,
    max_output_tokens: Option<u16>,
    request_body_fields: JsonMap<String, JsonValue>,
}

impl ModelConfig {
    /// Selects the model and backend used by template-backed Steps in one execution tree.
    pub fn new<B>(model: impl Into<String>, backend: B) -> Self
    where
        B: Backend + 'static,
    {
        Self {
            model: model.into(),
            backend: Arc::new(backend),
            max_output_tokens: None,
            request_body_fields: JsonMap::new(),
        }
    }

    /// Sets the maximum output-token budget for each model-backed Step.
    pub fn max_output_tokens(mut self, max_output_tokens: u16) -> Self {
        self.max_output_tokens = Some(max_output_tokens);
        self
    }

    /// Adds a provider-specific JSON field to each model request in this execution tree.
    pub fn request_body_field(mut self, key: impl Into<String>, value: JsonValue) -> Self {
        self.request_body_fields.insert(key.into(), value);
        self
    }
}

/// Runner position for one Flow execution.
enum RunPhase {
    /// The current Step will begin on the next [`Scope::advance`] call.
    Start,
    /// The parent cursor remains on a composite Step while this child owns the internal cursor.
    RunningChild(Box<Scope>),
    /// This Scope has committed its final State and optional declared exit.
    Finished(Option<StepId>),
}
