//! Synchronous single-use channels for concurrent Lyquid instance calls.
//!
//! The public API intentionally mirrors the blocking core of `std::sync::oneshot`, while the
//! private backend parks through Lyquor's guest wait/notify host functions. This keeps guest code
//! independent from the backend and allows the implementation to be replaced.

use core::fmt;

use crate::runtime::sync;

/// Creates a channel that transfers exactly one value.
///
/// Sending never waits. Receiving blocks the current guest call until a value arrives or the
/// sender is dropped. This primitive is intended for short-lived coordination between concurrent
/// instance calls, not durable external-input waits or recovery across node restarts.
pub fn channel<T>() -> (Sender<T>, Receiver<T>) {
    let (sender, receiver) = sync::oneshot::channel();
    (Sender { inner: sender }, Receiver { inner: receiver })
}

/// The sending half of a Lyquid one-shot channel.
pub struct Sender<T> {
    inner: sync::oneshot::Sender<T>,
}

impl<T> Sender<T> {
    /// Sends the channel's value without waiting.
    ///
    /// Returns the original value when the receiver has already been dropped.
    pub fn send(self, value: T) -> Result<(), SendError<T>> {
        self.inner.send(value).map_err(SendError)
    }
}

impl<T> fmt::Debug for Sender<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Sender").finish_non_exhaustive()
    }
}

/// The receiving half of a Lyquid one-shot channel.
pub struct Receiver<T> {
    inner: sync::oneshot::Receiver<T>,
}

impl<T> Receiver<T> {
    /// Blocks until the sender publishes a value or closes.
    ///
    /// A host timeout or cancellation does not guarantee guest-side cleanup, so this operation
    /// must only be used for short-lived coordination between instance calls.
    pub fn recv(self) -> Result<T, RecvError> {
        self.inner.recv().map_err(|_| RecvError)
    }
}

impl<T> fmt::Debug for Receiver<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Receiver").finish_non_exhaustive()
    }
}

/// Error returned when a value cannot be sent because the receiver was dropped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendError<T>(pub T);

impl<T> SendError<T> {
    /// Returns the value that could not be sent.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Display for SendError<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("one-shot receiver dropped before the value was sent")
    }
}

impl<T: fmt::Debug> std::error::Error for SendError<T> {}

/// Error returned when the sender closes without publishing a value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecvError;

impl fmt::Display for RecvError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("one-shot sender dropped without sending a value")
    }
}

impl std::error::Error for RecvError {}
