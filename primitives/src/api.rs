use std::borrow::Cow;
use std::fmt;

use super::{Address, B256, Bytes, ConsoleSink, LyquidID, LyquidNumber, U64};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Debug, Clone)]
#[serde(untagged)]
pub enum Id {
    Num(i64),
    Str(Box<str>),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonRPCErrorObject {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Box<serde_json::value::RawValue>>,
}

impl fmt::Display for JsonRPCErrorObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Simply print the Debug representation
        write!(f, "{:?}", self)
    }
}

#[derive(Serialize, Debug)]
#[serde(untagged)]
pub enum JsonRPCResponse<'a> {
    Error {
        error: JsonRPCErrorObject,
        jsonrpc: Cow<'a, str>,
        id: Option<Id>,
    },
    Success {
        result: Box<serde_json::value::RawValue>,
        jsonrpc: Cow<'a, str>,
        id: Option<Id>,
    },
}

#[derive(Serialize, Debug)]
pub struct JsonRPCRequest<'a> {
    pub method: Cow<'a, str>,
    pub jsonrpc: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Id>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Box<serde_json::value::RawValue>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonRPCMsgGeneric<'a> {
    pub jsonrpc: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Id>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Box<serde_json::value::RawValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRPCErrorObject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Box<serde_json::value::RawValue>>,
}

impl<'a> JsonRPCMsgGeneric<'a> {
    // NOTE: #[serde(untagged)] does not support deserializing Box<RawValue> in variants (as I tried).
    // So we have to do this manually parsing.
    pub fn parse(self) -> Result<JsonRPCMsg<'a>, serde_json::Error> {
        let jsonrpc = self.jsonrpc;
        let params = self.params;
        let id = self.id;
        match self.method {
            Some(method) => Ok(JsonRPCMsg::Request(JsonRPCRequest {
                method,
                jsonrpc,
                id,
                params,
            })),
            None => {
                use serde::de::Error;
                match self.error {
                    Some(error) => {
                        if self.result.is_some() {
                            return Err(serde_json::Error::custom("result field exists"));
                        }
                        Ok(JsonRPCMsg::Response(JsonRPCResponse::Error { error, jsonrpc, id }))
                    }
                    None => {
                        let result = self
                            .result
                            .unwrap_or_else(|| serde_json::value::RawValue::NULL.to_owned());
                        Ok(JsonRPCMsg::Response(JsonRPCResponse::Success { result, jsonrpc, id }))
                    }
                }
            }
        }
    }
}

#[derive(Serialize, Debug)]
#[serde(untagged)]
pub enum JsonRPCMsg<'a> {
    Request(JsonRPCRequest<'a>),
    Response(JsonRPCResponse<'a>),
}

// https://www.jsonrpc.org/specification

impl<'a> JsonRPCMsg<'a> {
    pub fn new_request(
        id: Option<Id>, method: &'a str, params: Option<serde_json::Value>,
    ) -> Result<Self, serde_json::Error> {
        let params = match params {
            Some(p) => Some(serde_json::value::to_raw_value(&p)?),
            None => None,
        };
        Ok(Self::Request(JsonRPCRequest {
            id,
            jsonrpc: "2.0".into(),
            method: method.into(),
            params,
        }))
    }
}

/// JSON-RPC outbound message.
pub trait Sealable<'a> {
    fn seal(self, id: Option<Id>) -> Result<JsonRPCMsg<'a>, serde_json::Error>;
}

#[derive(Serialize, Debug)]
pub struct LyquorPushImage(pub Bytes);

#[derive(Deserialize, Debug)]
pub struct LyquorPushImageResp(pub B256);

impl Sealable<'static> for LyquorPushImage {
    fn seal(self, id: Option<Id>) -> Result<JsonRPCMsg<'static>, serde_json::Error> {
        JsonRPCMsg::new_request(
            id,
            "lyquor_pushImage",
            Some(serde_json::Value::Array(vec![serde_json::to_value(self)?])),
        )
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LyquidInfo {
    pub contract: Address,
    pub number: LyquidNumber,
}

#[derive(Serialize, Debug)]
pub struct LyquorGetLatestLyquidInfo<'a>(pub Option<&'a LyquidID>);

#[derive(Deserialize, Debug)]
pub struct LyquorGetLatestLyquidInfoResp(pub Option<LyquidInfo>);

impl Sealable<'static> for LyquorGetLatestLyquidInfo<'_> {
    fn seal(self, id: Option<Id>) -> Result<JsonRPCMsg<'static>, serde_json::Error> {
        JsonRPCMsg::new_request(
            id,
            "lyquor_getLatestLyquidInfo",
            Some(serde_json::Value::Array(vec![serde_json::to_value(self)?])),
        )
    }
}

#[derive(Serialize, Debug)]
pub struct LyquorGetIdByEthAddr<'a>(pub &'a Address);

#[derive(Deserialize, Debug)]
pub struct LyquorGetIdByEthAddrResp(pub Option<LyquidID>);

impl Sealable<'static> for LyquorGetIdByEthAddr<'_> {
    fn seal(self, id: Option<Id>) -> Result<JsonRPCMsg<'static>, serde_json::Error> {
        JsonRPCMsg::new_request(
            id,
            "lyquor_getIdByEthAddr",
            Some(serde_json::Value::Array(vec![serde_json::to_value(self)?])),
        )
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum LyquorSubscriptionKind {
    Console { id: LyquidID, sink: ConsoleSink },
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LyquorSubscribe {
    pub kind: LyquorSubscriptionKind,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LyquorSubscribeResp(pub U64);

impl Sealable<'static> for LyquorSubscribe {
    fn seal(self, id: Option<Id>) -> Result<JsonRPCMsg<'static>, serde_json::Error> {
        JsonRPCMsg::new_request(
            id,
            "lyquor_subscribe",
            Some(serde_json::Value::Array(vec![serde_json::to_value(self)?])),
        )
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LyquorSubscriptionUpdate {
    pub result: Box<serde_json::value::RawValue>,
    pub subscription: Bytes,
}

impl Sealable<'static> for LyquorSubscriptionUpdate {
    fn seal(self, id: Option<Id>) -> Result<JsonRPCMsg<'static>, serde_json::Error> {
        JsonRPCMsg::new_request(id, "lyquor_subscription", Some(serde_json::to_value(self)?))
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LyquorConsoleUpdate {
    pub sink: ConsoleSink,
    pub new_lines: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LyquorReadConsole {
    pub id: LyquidID,
    pub sink: ConsoleSink,
    pub from: Option<isize>,
    pub to: Option<isize>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LyquorReadConsoleResp(pub Option<String>);

impl Sealable<'static> for LyquorReadConsole {
    fn seal(self, id: Option<Id>) -> Result<JsonRPCMsg<'static>, serde_json::Error> {
        JsonRPCMsg::new_request(
            id,
            "lyquor_readConsole",
            Some(serde_json::Value::Array(vec![serde_json::to_value(self)?])),
        )
    }
}
