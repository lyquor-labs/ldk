use std::sync::Arc;

use crate::state::State;
use crate::step::StepId;

/// Ordered history of completed Steps.
// TODO: Arc-backed entries still retain full State snapshots. Consider
//       storing committed StateUpdates as deltas to avoid Trace growing
//       with the full State size. And we may compact and prune Trace entries.
#[derive(Clone, Default)]
pub struct Trace {
    /// Entries in completion order.
    pub entries: Vec<TraceEntry>,
}

/// One completed Step and its read-only committed State snapshot.
#[derive(Clone)]
pub struct TraceEntry {
    /// Step that produced this committed snapshot.
    pub step: StepId,
    /// Committed workflow State after this Step completed.
    pub state: Arc<State>,
    /// Concise Step result or the Trace produced by a nested Flow.
    pub summary: TraceSummary,
}

/// Summary of one completed Step.
#[derive(Clone)]
pub enum TraceSummary {
    /// Concise description of a regular Step's result.
    Summary(String),
    /// Complete Trace produced by a Flow used as a Step.
    SubFlow(Trace),
}
