use serde::{Deserialize, Serialize};

/// HTTP method values carried across Lyquid host HTTP calls.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Connect,
    Options,
    Trace,
    Patch,
    Other(String),
}

/// URL scheme values recognized by Lyquid host HTTP helpers.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
    Other(String),
}

/// Header name and raw byte value used by host HTTP requests and responses.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: Vec<u8>,
}

/// Serializable HTTP request passed from a Lyquid guest to the host runtime.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub method: Method,
    pub url: String,
    pub headers: Vec<Header>,
    pub body: Option<Vec<u8>>,
}

/// Per-request host HTTP options supplied by the Lyquid guest.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct RequestOptions {
    pub timeout_ms: Option<u64>,
}

/// Serializable HTTP response returned by the host runtime.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
}
