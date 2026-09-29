use std::collections::VecDeque;
use std::fmt::{self, Write as _};
use std::num::NonZeroUsize;
use std::sync::Arc;

use lyquid::prelude::{HashMap, Mutex, new_hashmap, new_hashset};
use lyquid_llm::{FinishReason, ModelConfig, ModelRequest, ModelResponse, Usage};
use serde::{Deserialize, Serialize};

use crate::flow::Flow;
use crate::input::DecodedInput;
use crate::prompt;
use crate::state::{State, StateNamespace, StateUpdates};
use crate::step::{ModelTemplate, Step, StepId, TemplateSpec};
use crate::trace::{Trace, TraceEntry, TraceSummary};
use crate::{InputSpec, TurnProposal};

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

/// Errors produced while submitting input or advancing a Scope.
#[derive(Debug, thiserror::Error)]
pub enum FlowError {
    /// Input failed schema validation or field decoding.
    #[error("invalid input: {0}")]
    InputInvalid(String),
    /// No Step is currently waiting for input.
    #[error("there is no pending input request")]
    NoPendingInput,
    /// The captured input delivery endpoint closed or was already consumed.
    #[error("the waiting execution closed before input could be delivered")]
    InputClosed,
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
/// Dropping a handle only releases that owner; use [`Self::request_stop`] to stop input waits.
#[derive(Clone)]
pub struct InputHandle {
    shared: Arc<Mutex<InputHandleState>>,
}

#[derive(Default)]
struct InputHandleState {
    pending: Option<PendingInput>,
    state_snapshot: Option<Arc<State>>,
    stop_requested: bool,
}

/// One active Step input request and the endpoint that delivers its accepted input.
struct PendingInput {
    /// Contract used to type-check values offered while the Step is waiting.
    spec: InputSpec,
    /// One-shot endpoint used to deliver the accepted value to the waiting Step.
    sender: Arc<Mutex<Option<lyquid::oneshot::Sender<DecodedInput>>>>,
}

impl PendingInput {
    fn close(self) {
        let sender = self.sender.lock().take();
        drop(sender);
    }
}

impl InputHandle {
    fn new() -> Self {
        Self {
            shared: Arc::new(Mutex::new(InputHandleState::default())),
        }
    }

    /// Returns the input contract currently published by this execution tree.
    ///
    /// The contract remains available until submission, in both execution modes and including
    /// requests made by nested child Flows.
    pub fn input_spec(&self) -> Option<InputSpec> {
        self.shared.lock().pending.as_ref().map(|pending| pending.spec.clone())
    }

    /// Returns the latest committed State published when a Step in this tree requested input.
    ///
    /// This includes nested child State before it is joined into the parent. Returns `None` before
    /// the first input request, and retains the last snapshot while execution resumes or stops.
    /// Restoring a checkpoint clears the snapshot until another request is published.
    /// It is a read-only snapshot, not a checkpoint or a live view of in-flight updates.
    pub fn state_snapshot(&self) -> Option<Arc<State>> {
        self.shared.lock().state_snapshot.clone()
    }

    /// Requests a cooperative stop throughout this Scope execution tree.
    ///
    /// Closes a pending input request so its blocked [`Scope::advance`] returns an error, and
    /// rejects future input requests, offers, and execution attempts between Steps. Returns `true`
    /// for the first request and `false` thereafter. This does not interrupt an in-flight model call
    /// or Step, roll back committed State, or drop the Scope; its owner remains responsible for
    /// ending execution and cleanup.
    pub fn request_stop(&self) -> bool {
        let pending = {
            let mut shared = self.shared.lock();
            if shared.stop_requested {
                return false;
            }
            shared.stop_requested = true;
            shared.pending.take()
        };
        if let Some(pending) = pending {
            pending.close();
        }
        true
    }

    /// Validates the complete field object against the waiting Step's retained schema and decoders.
    ///
    /// Invalid input leaves the contract available for correction. Decoding runs outside the
    /// endpoint lock; delivery uses the captured one-shot sender and cannot move to another Step.
    /// This API carries no client input-round identity. Form freshness and duplicate HTTP requests
    /// are the responsibility of the session or transport layer.
    /// Returns [`FlowError::InputInvalid`] for invalid values, [`FlowError::NoPendingInput`] when
    /// no Step is waiting, or [`FlowError::InputClosed`] if the captured delivery endpoint closes.
    pub fn submit_input(&self, encoded: &str) -> Result<(), FlowError> {
        let (spec, sender) = {
            let shared = self.shared.lock();
            let pending = shared.pending.as_ref().ok_or(FlowError::NoPendingInput)?;
            (pending.spec.clone(), Arc::clone(&pending.sender))
        };
        let input = spec.decode(encoded).map_err(FlowError::InputInvalid)?;
        let pending;
        let delivered = {
            let mut shared = self.shared.lock();
            if shared.pending.is_none() {
                return Err(FlowError::NoPendingInput);
            }
            let sender = sender.lock().take().ok_or(FlowError::InputClosed)?;
            pending = shared.pending.take();
            // Sending never waits. Once the cooperative runner observes no pending input,
            // its receiver is ready; decoded values and custom prototypes are dropped outside the lock.
            sender.send(input)
        };
        drop(pending);
        delivered.map_err(|_| FlowError::InputClosed)
    }

    fn request(&self, spec: InputSpec, state: Arc<State>) -> Result<lyquid::oneshot::Receiver<DecodedInput>, String> {
        let (sender, receiver) = lyquid::oneshot::channel();
        {
            let mut shared = self.shared.lock();
            if shared.stop_requested {
                return Err("the Flow execution was stopped".to_owned());
            }
            if shared.pending.is_some() {
                return Err("the Flow execution already has a pending input request".to_owned());
            }
            shared.state_snapshot = Some(state);
            shared.pending = Some(PendingInput {
                spec,
                sender: Arc::new(Mutex::new(Some(sender))),
            });
        }

        Ok(receiver)
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

type UsageObserver = dyn Fn(&Scope, Option<&Usage>);

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
    /// Usage observer shared with child Scopes and independent of checkpoint restoration.
    usage_observer: Option<Arc<UsageObserver>>,
    /// Input endpoint shared by the complete root-to-leaf execution tree.
    input_handle: InputHandle,
    /// Input contract retained for the current Step until its transition commits.
    pending_input_spec: Option<InputSpec>,
    /// Receiving endpoint for this Step's published request; never copied into checkpoints.
    input_receiver: Option<lyquid::oneshot::Receiver<DecodedInput>>,
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
            usage_observer: self.usage_observer.clone(),
            input_handle: InputHandle::new(),
            pending_input_spec: self.pending_input_spec.clone(),
            input_receiver: None,
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
            usage_observer: None,
            input_handle: InputHandle::new(),
            pending_input_spec: None,
            input_receiver: None,
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

    /// Observes provider-reported token usage after each template-backed model call.
    ///
    /// The Scope identifies the execution and current Step, including nested child Flows. The
    /// observer runs before output validation, so rejected output still reports its usage. `None`
    /// means the call failed or the provider omitted usage.
    ///
    /// Cloned Scopes and child Scopes share this observer. Restoring a checkpoint preserves the
    /// current observer and does not undo observations.
    ///
    /// ```no_run
    /// # fn example(scope: lyquid_flow::Scope) {
    /// let scope = scope.on_usage(|scope, usage| {
    ///     lyquid::println!("scope={} step={} usage={usage:?}", scope.execution_id(), scope.current_step());
    /// });
    /// # }
    /// ```
    pub fn on_usage(mut self, observer: impl Fn(&Self, Option<&Usage>) + 'static) -> Self {
        self.rebind_usage_observer(Some(Arc::new(observer)));
        self
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
    /// backend retained by this Scope. This is a blocking adapter over the same runner used by
    /// [`Self::run_until_input`]; input requests are fulfilled through [`InputHandle`].
    pub fn advance(&mut self) -> Result<(), FlowError> {
        self.advance_step(true).map(|_| ())
    }

    /// Runs until the next input request (including inside a mounted Flow), or root completion.
    ///
    /// Submit values through [`InputHandle::submit_input`], then call this method again to resume.
    /// The returned State is the committed State of the
    /// requesting Scope, which may be a nested child. `None`
    /// means the root finished. Model calls still run synchronously, but waiting for user input does
    /// not block: the caller owns a stable execution point and can use [`Self::checkpoint`] and
    /// [`Self::restore`] directly. Restoring an input boundary does not replay completed Steps.
    ///
    /// Both execution modes share the same request, validation, and delivery path. A stop requested
    /// through the handle is observed between Steps. Earlier committed Steps remain committed if
    /// a later Step fails; callers may restore their own checkpoint to retry a complete interaction.
    /// The input contract is retained through retries and checkpoints until its Step commits.
    pub fn run_until_input(&mut self) -> Result<Option<(InputSpec, Arc<State>)>, FlowError> {
        loop {
            if let Some(request) = self.advance_step(false)? {
                return Ok(Some(request));
            }
            if self.is_finished() {
                return Ok(None);
            }
        }
    }

    /// Advances one Flow-level Step, returning any input request before executing that Step.
    /// Waits for input only when called by the blocking adapter.
    fn advance_step(&mut self, wait_for_input: bool) -> Result<Option<(InputSpec, Arc<State>)>, FlowError> {
        if self.input_handle.shared.lock().stop_requested {
            return Err(FlowError::Execution("the Flow execution was stopped".to_owned()));
        }
        let previous_updates = self.updates.clone();
        let result = if self.running_child().is_some() {
            self.advance_child(wait_for_input)
        } else if self.is_finished() {
            Ok(None)
        } else {
            self.begin_step(wait_for_input)
        };
        if result.is_err() {
            // Roll back Step-scoped State changes from the failed execution attempt.
            self.updates = previous_updates;
        }
        result
    }

    /// Enters a fresh Step, returns missing input, or evaluates its model template.
    fn begin_step(&mut self, wait_for_input: bool) -> Result<Option<(InputSpec, Arc<State>)>, FlowError> {
        let step = self.current_step_cloned()?;
        if self.pending_input_spec.is_none() {
            self.pending_input_spec = step.input(self);
        }
        let spec = self.pending_input_spec.clone();
        // Input construction may request a stop through the shared handle.
        if self.input_handle.shared.lock().stop_requested {
            return Err(FlowError::Execution("the Flow execution was stopped".to_owned()));
        }
        if let Some(spec) = spec {
            if self.input_receiver.is_none() {
                self.input_receiver = Some(self.input_handle.request(spec, Arc::clone(&self.state))?);
            }
            if !wait_for_input {
                let shared = self.input_handle.shared.lock();
                if shared.stop_requested {
                    return Err(FlowError::Execution("the Flow execution was stopped".to_owned()));
                }
                if let Some(pending) = &shared.pending {
                    return Ok(Some((pending.spec.clone(), Arc::clone(&self.state))));
                }
            }
            let decoded = self
                .input_receiver
                .take()
                .expect("the request has a receiver")
                .recv()
                .map_err(|_| {
                    if self.input_handle.shared.lock().stop_requested {
                        "the Flow execution was stopped".to_owned()
                    } else {
                        "the pending input request closed before delivery".to_owned()
                    }
                })?;
            self.updates.ephemeral.remove(&StateNamespace::Input);
            for (key, value) in decoded {
                self.set(StateNamespace::Input, key, Some(value));
            }
        }
        self.process_model_template(step, wait_for_input)
    }

    /// Forks and starts a child Scope with inherited State and shared runtime configuration.
    fn start_child(
        &mut self, child_flow: Arc<Flow>, wait_for_input: bool,
    ) -> Result<Option<(InputSpec, Arc<State>)>, FlowError> {
        let updates = std::mem::take(&mut self.updates);
        let child = self.fork_child(child_flow, updates);
        self.phase = RunPhase::RunningChild(Box::new(child));
        self.advance_child(wait_for_input)
    }

    /// Runs the active child until input is needed or it exits and can join the parent.
    fn advance_child(&mut self, wait_for_input: bool) -> Result<Option<(InputSpec, Arc<State>)>, FlowError> {
        loop {
            let finished = {
                let child = self
                    .running_child_mut()
                    .expect("advance_child is called only while a child is active");
                if let Some(request) = child.advance_step(wait_for_input)? {
                    return Ok(Some(request));
                }
                child.is_finished()
            };
            if finished {
                self.updates = StateUpdates::default();
                self.join_child()?;
                return Ok(None);
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

    /// Validates declared model destinations and State fields against this Scope.
    fn validate_model_template(&self, template: &ModelTemplate) -> Result<(), String> {
        if template.next_step_criteria.is_empty() {
            return Err("a model template must declare at least one next-step criterion".to_owned());
        }

        let mut seen = new_hashset();
        for (next, _) in &template.next_step_criteria {
            if !seen.insert(next.clone()) {
                let target = next
                    .as_ref()
                    .map_or_else(|| "Flow completion".to_owned(), |step| format!("Step {step}"));
                return Err(format!("duplicate next-step criterion for {target}"));
            }
            let Some(next) = next else {
                if self.requires_exit {
                    return Err("a mounted Flow model template cannot declare root Flow completion".to_owned());
                }
                continue;
            };
            if self.flow.step(next).is_none() && !self.flow.exits().contains(next) {
                return Err(format!("model template declares unknown next Step {next}"));
            }
        }

        let mut seen_fields = new_hashset();
        for (field, _) in &template.state_update_criteria {
            if !seen_fields.insert(field) {
                return Err(format!("duplicate State update criterion for field {field}"));
            }
            if !self.state().fields.contains_key(field) {
                return Err(format!("model template declares unknown State field {field}"));
            }
        }
        Ok(())
    }

    /// Evaluates the current Step's model template with Step-scoped context.
    fn process_model_template(
        &mut self, step: Arc<dyn Step>, wait_for_input: bool,
    ) -> Result<Option<(InputSpec, Arc<State>)>, FlowError> {
        let proposal = match step.model_template(self) {
            TemplateSpec::Template(template) => {
                self.validate_model_template(&template)?;
                let request = prompt::build_request(self.model()?, &template, &self.flow, self)?;
                let output = self.call_model(request)?;
                prompt::parse_response(self.state(), &template, &output)?
            }
            TemplateSpec::Skip(proposal) => proposal,
        };
        self.run_finalize(step.as_ref(), proposal, wait_for_input)
    }

    /// Finalizes an ordinary Step, or starts a child Flow that will be finalized when it exits.
    fn run_finalize(
        &mut self, step: &dyn Step, mut proposal: TurnProposal, wait_for_input: bool,
    ) -> Result<Option<(InputSpec, Arc<State>)>, FlowError> {
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
            return self.start_child(child_flow, wait_for_input);
        }

        let summary = step.finalize(self, &mut proposal)?;
        self.commit_proposal(proposal, summary)?;
        Ok(None)
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
    /// the independent ID allocated to the saved checkpoint Scope. Pending requests and accepted
    /// but unconsumed input are discarded; advancing waits again using the saved input contract.
    pub fn restore(&mut self, id: &ScopeId) -> Result<(), FlowError> {
        let input_handle = self.input_handle.clone();
        let execution_id = self.execution_id.clone();
        let checkpoint = self
            .checkpoints
            .get(id)
            .ok_or_else(|| FlowError::Execution(format!("unknown Scope checkpoint {id}")))?;
        let mut restored = checkpoint.clone();
        let pending = {
            let mut shared = input_handle.shared.lock();
            shared.state_snapshot = None;
            shared.pending.take()
        };
        if let Some(pending) = pending {
            pending.close();
        }
        restored.execution_id = execution_id;
        restored.rebind_input_handle(input_handle);
        restored.rebind_usage_observer(self.usage_observer.clone());
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

    fn rebind_usage_observer(&mut self, observer: Option<Arc<UsageObserver>>) {
        self.usage_observer = observer.clone();
        if let RunPhase::RunningChild(child) = &mut self.phase {
            child.rebind_usage_observer(observer);
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
            usage_observer: self.usage_observer.clone(),
            input_handle: self.input_handle.clone(),
            pending_input_spec: None,
            input_receiver: None,
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
        self.model_config.as_ref().map(ModelConfig::model).ok_or_else(|| {
            FlowError::Execution("Scope model configuration is missing for a template-backed Step".to_owned())
        })
    }

    fn call_model(&self, request: ModelRequest) -> Result<String, FlowError> {
        let model_config = self.model_config.as_ref().ok_or_else(|| {
            FlowError::Execution("Scope model configuration is missing for a template-backed Step".to_owned())
        })?;
        self.handle_model_response(lyquid_llm::call_model(model_config, &request))
    }

    fn handle_model_response(&self, response: lyquid_llm::LlmResult<ModelResponse>) -> Result<String, FlowError> {
        if let Some(observer) = self.usage_observer.as_ref() {
            observer(
                self,
                response.as_ref().ok().and_then(|response| response.usage.as_ref()),
            );
        }
        let response = response.map_err(FlowError::Model)?;
        if response.finish_reason == Some(FinishReason::Length) {
            return Err(FlowError::Execution(
                "model output exceeded the configured output-token budget".to_owned(),
            ));
        }
        response
            .text
            .ok_or_else(|| FlowError::Execution("model returned no text".to_owned()))
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
        self.pending_input_spec = None;
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

/// Runner position for one Flow execution.
enum RunPhase {
    /// The current Step will begin on the next [`Scope::advance`] call.
    Start,
    /// The parent cursor remains on a composite Step while this child owns the internal cursor.
    RunningChild(Box<Scope>),
    /// This Scope has committed its final State and optional declared exit.
    Finished(Option<StepId>),
}

#[cfg(test)]
mod tests {
    use std::any::Any;

    use lyquid_llm::{Backend, JsonApiResponse, LlmError, LlmResult, PreparedJsonApiRequest};
    use lyquid_test::test;
    use serde_json::Value as JsonValue;

    use super::*;
    use crate::Value;

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

    type Observations = Arc<Mutex<Vec<(String, String, Option<Usage>)>>>;

    struct FailingBackend;

    impl Backend for FailingBackend {
        fn prepare_request(&self, _request: &ModelRequest) -> LlmResult<PreparedJsonApiRequest> {
            Err(LlmError::Backend {
                provider: "test".to_owned(),
                message: "request preparation failed".to_owned(),
            })
        }

        fn parse_response(&self, _response: JsonApiResponse) -> LlmResult<ModelResponse> {
            unreachable!("the test backend never sends a request")
        }
    }

    fn usage_scope(observations: &Observations) -> Scope {
        let observations = Arc::clone(observations);
        let config = ModelConfig::new("test-model", FailingBackend);
        let flow = Flow::builder("usage-flow")
            .entry("start")
            .step("start", TestStep)
            .build()
            .unwrap();
        Scope::new(
            Arc::new(flow),
            State::builder().build().unwrap(),
            AutoCheckpointConfig::Unbounded,
            Some(config),
        )
        .on_usage(move |scope, usage| {
            observations.lock().push((
                scope.execution_id().to_string(),
                scope.current_step().to_string(),
                usage.cloned(),
            ));
        })
    }

    fn usage_response(usage: JsonValue) -> ModelResponse {
        let backend = lyquid_llm::backend::openai_compat::OpenAiCompatBackend::responses("test", "unused");
        backend
            .parse_response(JsonApiResponse {
                http: lyquid::http::Response {
                    status: 200,
                    headers: Vec::new(),
                    body: Vec::new(),
                },
                json: serde_json::json!({
                    "output_text": "model output",
                    "usage": usage,
                }),
            })
            .unwrap()
    }

    #[test]
    fn token_usage_reporting() {
        // Report token usage whenever the provider returns it, even if the output
        // is rejected; otherwise report None.
        let observations = Arc::new(Mutex::new(Vec::new()));
        let scope = usage_scope(&observations);
        let response = usage_response(serde_json::json!({
            "input_tokens": 20, "output_tokens": 10, "total_tokens": 35,
        }));
        assert_eq!(
            scope.handle_model_response(Ok(response.clone())).unwrap(),
            "model output"
        );

        let mut truncated = response.clone();
        truncated.finish_reason = Some(FinishReason::Length);
        assert!(scope.handle_model_response(Ok(truncated)).is_err());

        let mut empty = response.clone();
        empty.text = None;
        assert!(scope.handle_model_response(Ok(empty)).is_err());

        scope
            .handle_model_response(Ok(usage_response(JsonValue::Null)))
            .unwrap();
        scope
            .handle_model_response(Ok(usage_response(serde_json::json!({ "input_tokens": 20 }))))
            .unwrap();
        assert!(matches!(
            scope.call_model(ModelRequest::new("test-model", "test prompt")),
            Err(FlowError::Model(_))
        ));

        let observations = observations.lock();
        for (execution, step, _) in observations.iter() {
            assert_eq!(execution, &scope.execution_id().to_string());
            assert_eq!(step, "start");
        }
        let usages = observations
            .iter()
            .map(|(_, _, usage)| usage.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            usages,
            vec![
                response.usage.clone(),
                response.usage.clone(),
                response.usage,
                None,
                Some(Usage {
                    input_tokens: Some(20),
                    output_tokens: None,
                    total_tokens: None,
                }),
                None,
            ]
        );
        assert!(scope.trace().entries.is_empty());
    }

    #[test]
    fn token_usage_across_scopes() {
        // Collect token usage from both parent and child Scopes, and keep the records
        // when restoring a checkpoint.
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut scope = usage_scope(&observations);
        let checkpoint = scope.checkpoint();
        let child = scope.fork_child(Arc::clone(&scope.flow), StateUpdates::default());
        let response = usage_response(serde_json::json!({ "total_tokens": 12 }));
        child.handle_model_response(Ok(response.clone())).unwrap();
        scope.handle_model_response(Ok(response.clone())).unwrap();
        scope.advance().unwrap();
        assert_eq!(observations.lock().len(), 2);

        scope.restore(&checkpoint).unwrap();
        scope.handle_model_response(Ok(response)).unwrap();
        let observations = observations.lock();
        assert_eq!(observations.len(), 3);
        assert_eq!(observations[0].0, child.execution_id().to_string());
        assert_eq!(observations[1].0, scope.execution_id().to_string());
        assert_eq!(observations[2].0, scope.execution_id().to_string());
    }

    #[test]
    fn usage_after_restore_and_clone() {
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut scope = usage_scope(&observations);
        // Scope::new creates this checkpoint before on_usage installs the observer.
        let checkpoint = scope.checkpoint_ids().next().unwrap().clone();
        scope.restore(&checkpoint).unwrap();
        let cloned = scope.clone();
        let response = usage_response(serde_json::json!({ "total_tokens": 12 }));
        scope.handle_model_response(Ok(response.clone())).unwrap();
        cloned.handle_model_response(Ok(response)).unwrap();

        let observations = observations.lock();
        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].0, scope.execution_id().to_string());
        assert_eq!(observations[1].0, cloned.execution_id().to_string());
        assert!(
            observations
                .iter()
                .all(|(_, _, usage)| usage.as_ref().unwrap().total_tokens == Some(12))
        );
    }

    #[test]
    fn validates_model_template() {
        let flow = Arc::new(
            Flow::builder("test-flow")
                .entry("start")
                .exit("done")
                .step("start", TestStep)
                .step("review", TestStep)
                .build()
                .expect("test Flow should be valid"),
        );
        let state = State::builder()
            .field("title", "Current release title", "Draft".to_owned())
            .build()
            .expect("test State should be valid");
        let scope = Scope::new(Arc::clone(&flow), state, AutoCheckpointConfig::Disabled, None);

        let mut valid = ModelTemplate::new(
            "Review the work",
            vec![
                (Some("review".into()), "More review is required".to_owned()),
                (Some("done".into()), "The mounted Flow should exit".to_owned()),
                (None, "The root Flow is complete".to_owned()),
            ],
            Vec::new(),
        );
        assert!(scope.validate_model_template(&valid).is_ok());

        let empty = ModelTemplate::new("Review the work", Vec::new(), Vec::new());
        assert_eq!(
            scope.validate_model_template(&empty).err().as_deref(),
            Some("a model template must declare at least one next-step criterion")
        );

        let duplicate = ModelTemplate::new(
            "Review the work",
            vec![
                (Some("review".into()), "More review is required".to_owned()),
                (Some("review".into()), "A second description is not allowed".to_owned()),
            ],
            Vec::new(),
        );
        assert_eq!(
            scope.validate_model_template(&duplicate).err().as_deref(),
            Some("duplicate next-step criterion for Step review")
        );

        let unknown = ModelTemplate::new(
            "Review the work",
            vec![(Some("missing".into()), "Use an unknown destination".to_owned())],
            Vec::new(),
        );
        assert_eq!(
            scope.validate_model_template(&unknown).err().as_deref(),
            Some("model template declares unknown next Step missing")
        );

        let mounted = scope.fork_child(flow, StateUpdates::default());
        let mounted_completion = ModelTemplate::new(
            "Review the work",
            vec![(None, "Complete the parent Flow".to_owned())],
            Vec::new(),
        );
        assert_eq!(
            mounted.validate_model_template(&mounted_completion).err().as_deref(),
            Some("a mounted Flow model template cannot declare root Flow completion")
        );
        valid.next_step_criteria.pop();
        assert!(mounted.validate_model_template(&valid).is_ok());

        valid
            .state_update_criteria
            .push(("title".to_owned(), "Replace when the approved title changes".to_owned()));
        assert!(scope.validate_model_template(&valid).is_ok());

        let mut unknown_field = valid.clone();
        unknown_field.state_update_criteria[0].0 = "missing".to_owned();
        assert_eq!(
            scope.validate_model_template(&unknown_field).err().as_deref(),
            Some("model template declares unknown State field missing")
        );

        let mut duplicate_field = valid;
        duplicate_field
            .state_update_criteria
            .push(("title".to_owned(), "Replace when the editor changes it".to_owned()));
        assert_eq!(
            scope.validate_model_template(&duplicate_field).err().as_deref(),
            Some("duplicate State update criterion for field title")
        );
    }

    fn text_spec() -> InputSpec {
        let mut builder = InputSpec::builder();
        let field = builder.field("feedback", "Feedback", String::new()).text_input();
        builder.finish(field).unwrap()
    }

    #[test]
    fn retries_invalid_input() {
        let handle = InputHandle::new();
        let receiver = handle.request(text_spec(), Arc::new(State::default())).unwrap();
        let spec = handle.input_spec().unwrap();
        assert!(matches!(handle.submit_input("42"), Err(FlowError::InputInvalid(_))));
        assert_eq!(spec.schema(), handle.input_spec().unwrap().schema());
        handle.submit_input(r#"{"feedback":"more portable"}"#).unwrap();
        let decoded = receiver.recv().unwrap();
        let feedback: &dyn Any = decoded["feedback"].as_ref();
        assert_eq!(feedback.downcast_ref::<String>().unwrap(), "more portable");
        assert!(handle.input_spec().is_none());
        assert!(matches!(
            handle.submit_input(r#"{"feedback":"no waiting Step"}"#),
            Err(FlowError::NoPendingInput)
        ));
    }

    #[derive(Clone, schemars::JsonSchema)]
    #[schemars(with = "bool")]
    struct CustomValue {
        before_return: Arc<dyn Fn() + Send + Sync>,
        wrong_type: bool,
    }

    impl Value for CustomValue {
        fn encode(&self) -> String {
            "null".to_owned()
        }

        fn decode(&self, encoded: &str) -> Result<Box<dyn Value>, String> {
            if encoded != "true" && encoded != "false" {
                return Err("custom decoder rejected the response".to_owned());
            }
            if encoded == "true" {
                (self.before_return)();
            }
            if self.wrong_type {
                Ok(Box::new(true))
            } else {
                Ok(Box::new(self.clone()))
            }
        }

        fn clone_box(&self) -> Box<dyn Value> {
            Box::new(self.clone())
        }
    }

    #[test]
    fn rejects_invalid_decoders() {
        let handle = InputHandle::new();
        let receiver = handle
            .request(
                custom_spec(CustomValue {
                    before_return: Arc::new(|| {}),
                    wrong_type: true,
                }),
                Arc::new(State::default()),
            )
            .unwrap();
        for encoded in [r#"{"feedback":42}"#, r#"{"feedback":true}"#] {
            assert!(matches!(handle.submit_input(encoded), Err(FlowError::InputInvalid(_))));
            assert!(handle.input_spec().is_some());
        }
        drop(receiver);
    }

    #[test]
    fn isolates_concurrent_input() {
        let handle = InputHandle::new();
        let next_receiver = Arc::new(Mutex::new(None));
        let other_handle = handle.clone();
        let other_receiver = Arc::clone(&next_receiver);
        let prototype = CustomValue {
            wrong_type: false,
            before_return: Arc::new(move || {
                // Another caller delivers input while this decoder is running. The captured sender
                // must be consumed, even if the next Step starts waiting before decoding finishes.
                other_handle.submit_input(r#"{"feedback":false}"#).unwrap();
                *other_receiver.lock() = Some(other_handle.request(text_spec(), Arc::new(State::default())).unwrap());
            }),
        };
        let receiver = handle
            .request(custom_spec(prototype), Arc::new(State::default()))
            .unwrap();
        assert!(matches!(
            handle.submit_input(r#"{"feedback":true}"#),
            Err(FlowError::InputClosed)
        ));
        assert!(receiver.recv().is_ok());
        assert!(handle.input_spec().is_some());
        handle.submit_input(r#"{"feedback":"next"}"#).unwrap();
        let decoded = next_receiver.lock().take().unwrap().recv().unwrap();
        let feedback: &dyn Any = decoded["feedback"].as_ref();
        assert_eq!(feedback.downcast_ref::<String>().unwrap(), "next");
    }

    #[test]
    fn rejects_closed_receiver() {
        let handle = InputHandle::new();
        let receiver = handle.request(text_spec(), Arc::new(State::default())).unwrap();
        drop(receiver);
        assert!(matches!(
            handle.submit_input(r#"{"feedback":"feedback"}"#),
            Err(FlowError::InputClosed)
        ));
        assert!(handle.input_spec().is_none());
    }

    #[test]
    fn stop_during_decode() {
        let handle = InputHandle::new();
        let stopping_handle = handle.clone();
        let state = Arc::new(State::default());
        let receiver = handle
            .request(
                custom_spec(CustomValue {
                    before_return: Arc::new(move || {
                        assert!(stopping_handle.request_stop());
                    }),
                    wrong_type: false,
                }),
                Arc::clone(&state),
            )
            .unwrap();
        assert!(Arc::ptr_eq(&handle.state_snapshot().unwrap(), &state));
        assert!(matches!(
            handle.submit_input(r#"{"feedback":true}"#),
            Err(FlowError::NoPendingInput)
        ));
        assert!(receiver.recv().is_err());
        assert!(handle.input_spec().is_none());
        assert!(Arc::ptr_eq(&handle.state_snapshot().unwrap(), &state));
        assert!(!handle.request_stop());
        assert!(handle.request(text_spec(), Arc::new(State::default())).is_err());
    }

    fn custom_spec(value: CustomValue) -> InputSpec {
        let mut builder = InputSpec::builder();
        let field = builder.field("feedback", "Feedback", value).toggle();
        builder.finish(field).unwrap()
    }

    struct FeedbackStep;

    impl Step for FeedbackStep {
        fn description(&self, _: bool) -> String {
            "Save feedback".to_owned()
        }

        fn input(&self, _: &Scope) -> Option<InputSpec> {
            Some(text_spec())
        }

        fn model_template(&self, scope: &Scope) -> TemplateSpec {
            let mut updates = StateUpdates::default();
            updates.set(
                "feedback".to_owned(),
                Some(Box::new(
                    scope.get::<String>(StateNamespace::Input, "feedback").unwrap().clone(),
                )),
            );
            TemplateSpec::Skip(TurnProposal::Advance { next: None, updates })
        }

        fn finalize(&self, _: &Scope, _: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
            Ok(TraceSummary::Summary("Saved feedback".to_owned()))
        }
    }

    fn feedback_scope() -> Scope {
        Scope::new(
            Arc::new(
                Flow::builder("feedback")
                    .entry("input")
                    .step("input", FeedbackStep)
                    .build()
                    .unwrap(),
            ),
            State::builder()
                .field("feedback", "Feedback", String::new())
                .build()
                .unwrap(),
            AutoCheckpointConfig::Disabled,
            None,
        )
    }

    #[test]
    fn restore_discards_input() {
        let mut scope = feedback_scope();
        let handle = scope.input_handle();
        let (spec, _) = scope.run_until_input().unwrap().unwrap();
        let checkpoint = scope.checkpoint();
        assert!(scope.restore(&ScopeId("missing".into())).is_err());
        assert_eq!(handle.input_spec().unwrap().schema(), spec.schema());

        scope.restore(&checkpoint).unwrap();
        assert!(handle.input_spec().is_none());
        assert!(handle.state_snapshot().is_none());
        let (restored, _) = scope.run_until_input().unwrap().unwrap();
        assert_eq!(restored.schema(), spec.schema());
        handle.submit_input(r#"{"feedback":"discard me"}"#).unwrap();
        scope.restore(&checkpoint).unwrap();
        scope.run_until_input().unwrap().unwrap();
        assert!(scope.trace().entries.is_empty());
        assert_eq!(scope.state().get::<String>("feedback").unwrap(), "");
        handle.submit_input(r#"{"feedback":"after restore"}"#).unwrap();
        scope.advance().unwrap();
        assert!(scope.is_finished());
        assert_eq!(scope.state().get::<String>("feedback").unwrap(), "after restore");
        assert_eq!(scope.trace().entries.len(), 1);
    }

    #[test]
    fn clone_isolates_input() {
        let mut original = feedback_scope();
        let handle = original.input_handle();
        original.run_until_input().unwrap().unwrap();
        handle.submit_input(r#"{"feedback":"original"}"#).unwrap();
        let mut cloned = original.clone();
        cloned.run_until_input().unwrap().unwrap();
        cloned.input_handle().submit_input(r#"{"feedback":"clone"}"#).unwrap();
        assert!(cloned.run_until_input().unwrap().is_none());
        original.advance().unwrap();
        assert_eq!(original.state().get::<String>("feedback").unwrap(), "original");
        assert_eq!(cloned.state().get::<String>("feedback").unwrap(), "clone");
        assert_eq!(original.trace().entries.len(), 1);
        assert_eq!(cloned.trace().entries.len(), 1);
    }

    #[test]
    fn stop_and_drop_close_input() {
        let mut scope = feedback_scope();
        let handle = scope.input_handle();
        scope.run_until_input().unwrap().unwrap();
        handle.submit_input(r#"{"feedback":"accepted"}"#).unwrap();
        assert!(handle.request_stop());
        assert!(scope.run_until_input().is_err());
        assert!(scope.trace().entries.is_empty());

        let mut scope = feedback_scope();
        let handle = scope.input_handle();
        scope.run_until_input().unwrap().unwrap();
        drop(scope);
        assert!(matches!(
            handle.submit_input(r#"{"feedback":"closed"}"#),
            Err(FlowError::InputClosed)
        ));
    }
}
