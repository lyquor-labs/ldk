#![doc(html_no_source)]

//! Reusable Scope-backed Circle x402 payment Flow.
//!
//! The Flow validates one application request, accepts an externally signed
//! EIP-3009 authorization, and settles it from the local Lyquid instance.

mod eip3009;
mod flow;
mod payment;
mod types;

pub use flow::{FAILED_EXIT, PAYMENT_STATE_FIELD, SUCCEEDED_EXIT, flow, initial_state, payment_state};
pub use types::{
    Eip3009Authorization, PaymentConfig, PaymentReceipt, PaymentRequest, PaymentRequirements, PaymentState,
};
