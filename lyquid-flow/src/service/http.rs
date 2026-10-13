use lyquid::http;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::value::RawValue;

use super::{ClientError, FlowClient, FlowClientId, FlowService, SubmitResponse};
use crate::{Scope, ScopeId};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Submission<'a> {
    request_id: String,
    #[serde(borrow)]
    values: &'a RawValue,
}

/// Shared request parsing/status mapping. A resolver returns only the active input-capable target.
/// `schedule` must enqueue an instance task; it must not execute a model inline.
pub fn handle_http(
    request: http::Request, resolve: impl FnOnce(&FlowClientId) -> Option<FlowClient>,
    schedule: impl FnOnce(FlowClientId) -> Result<(), String>,
) -> http::Response {
    let result = (|| {
        let path = request_path(&request.url);
        let suffix = path.strip_prefix("/api/flows/").ok_or(ClientError::NotFound)?;
        let (id, operation) = suffix.split_once('/').unwrap_or((suffix, ""));
        if id.is_empty() {
            return Err(ClientError::NotFound);
        }
        let id = FlowClientId(id.to_owned());
        let client = resolve(&id).ok_or(ClientError::NotFound)?;
        match (&request.method, operation) {
            (http::Method::Get, "") => Ok(json_response(200, &client.read()?)),
            (http::Method::Post, "input") => {
                let body: Submission<'_> = serde_json::from_slice(request.body.as_deref().unwrap_or_default())
                    .map_err(|error| ClientError::Malformed {
                        message: error.to_string(),
                    })?;
                let accepted = client.submit(&body.request_id, body.values.get())?;
                if let Err(error) = schedule(id) {
                    return Err(client.scheduling_failed(error));
                }
                Ok(json_response(202, &accepted))
            }
            (http::Method::Post, "restore") => {
                let body: Restore = decode_body(&request)?;
                client.restore(&body.revision_id)?;
                if let Err(error) = schedule(id) {
                    return Err(client.scheduling_failed(error));
                }
                Ok(json_response(202, &SubmitResponse::Accepted))
            }
            _ => Err(ClientError::NotFound),
        }
    })();
    result.unwrap_or_else(|error| json_response(error.status(), &error))
}

pub fn json_response(status: u16, value: &impl Serialize) -> http::Response {
    let (status, body) = match serde_json::to_vec(value) {
        Ok(body) => (status, body),
        Err(error) => (
            500,
            serde_json::to_vec(&ClientError::internal(error)).expect("error strings serialize"),
        ),
    };
    http::Response {
        status,
        headers: vec![
            http::Header {
                name: "content-type".to_owned(),
                value: b"application/json; charset=utf-8".to_vec(),
            },
            http::Header {
                name: "cache-control".to_owned(),
                value: b"no-store".to_vec(),
            },
        ],
        body,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Restore {
    revision_id: ScopeId,
}

#[derive(Serialize)]
struct Created {
    client_id: FlowClientId,
}

impl FlowService {
    /// Full service entry point used by serve_flow!: creation plus reads, input and restore.
    /// Business initialization runs only for POST /api/flows, before replacing any execution.
    pub fn serve(
        &self, request: http::Request, replace_existing: bool, create: impl FnOnce() -> Result<Scope, String>,
        schedule: impl FnOnce(FlowClientId) -> Result<(), String>,
    ) -> http::Response {
        if request_path(&request.url) != "/api/flows" || request.method != http::Method::Post {
            return self.handle_http(request, schedule);
        }
        let result = (|| {
            if request.body.as_ref().is_some_and(|body| !body.is_empty()) {
                return Err(ClientError::Malformed {
                    message: "Creation takes no body; submit business input to the first Step.".into(),
                });
            }
            let scope = create().map_err(|message| ClientError::Malformed { message })?;
            let client = self.insert(scope, replace_existing)?;
            let id = client.id.clone();
            if let Err(error) = schedule(id.clone()) {
                return Err(client.scheduling_failed(error));
            }
            Ok(json_response(202, &Created { client_id: id }))
        })();
        result.unwrap_or_else(|error: ClientError| json_response(error.status(), &error))
    }
}

fn decode_body<T: DeserializeOwned>(request: &http::Request) -> Result<T, ClientError> {
    serde_json::from_slice(request.body.as_deref().unwrap_or_default()).map_err(|error| ClientError::Malformed {
        message: error.to_string(),
    })
}

fn request_path(url: &str) -> &str {
    url.split_once("://")
        .map_or(url, |(_, rest)| rest.find('/').map_or("/", |offset| &rest[offset..]))
        .split(['?', '#'])
        .next()
        .unwrap_or("")
}
