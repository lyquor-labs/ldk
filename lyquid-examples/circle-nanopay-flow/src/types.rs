use lyquid_flow::Value;
use serde::{Deserialize, Serialize};

/// Settlement and network configuration captured by one Circle payment Flow.
#[derive(Clone)]
pub struct PaymentConfig {
    pub facilitator_url: String,
    pub facilitator_bearer_token: String,
    pub settlement_rpc_url: String,
    pub network: String,
    pub chain_id: u64,
    pub asset_contract: String,
    pub asset_eip712_name: String,
    pub asset_eip712_version: String,
    pub allowed_resource_hosts: Vec<String>,
}

impl PaymentConfig {
    /// Configuration used by the existing Base Sepolia Circle nanopay example.
    pub fn base_sepolia() -> Self {
        Self {
            facilitator_url: "https://x402.org/facilitator".to_owned(),
            facilitator_bearer_token: String::new(),
            settlement_rpc_url: "https://sepolia.base.org".to_owned(),
            network: "eip155:84532".to_owned(),
            chain_id: 84_532,
            asset_contract: "0x036CbD53842c5426634e7929541eC2318f3dCF7e".to_owned(),
            asset_eip712_name: "USDC".to_owned(),
            asset_eip712_version: "2".to_owned(),
            allowed_resource_hosts: vec![
                "api.example.com".to_owned(),
                "paid.example.org".to_owned(),
                "127.0.0.1".to_owned(),
            ],
        }
    }
}

/// Application-supplied description of the payment to perform.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentRequest {
    pub resource_url: String,
    pub max_amount_base_units: String,
    pub network: String,
    pub correlation_id: String,
    pub buyer_address: String,
    pub recipient: String,
}

/// Exact EIP-3009 values a client must authorize for this payment Scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentRequirements {
    pub network: String,
    pub chain_id: u64,
    pub asset_contract: String,
    pub pay_to: String,
    pub amount_base_units: String,
    pub nonce: String,
    pub asset_eip712_name: String,
    pub asset_eip712_version: String,
}

/// User-signed EIP-3009 `TransferWithAuthorization`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Eip3009Authorization {
    pub from: String,
    pub to: String,
    pub value: String,
    pub valid_after: String,
    pub valid_before: String,
    pub nonce: String,
    pub signature: String,
}

/// Successful facilitator settlement retained in Flow state.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PaymentReceipt {
    pub request: PaymentRequest,
    pub authorization: Eip3009Authorization,
    pub transaction: String,
    pub payment_response: serde_json::Value,
}

/// Current state of a single payment Flow execution.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum PaymentState {
    Initialized {
        request: PaymentRequest,
    },
    AwaitingAuthorization {
        request: PaymentRequest,
        requirements: PaymentRequirements,
    },
    Authorized {
        request: PaymentRequest,
        requirements: PaymentRequirements,
        authorization: Eip3009Authorization,
    },
    Succeeded(PaymentReceipt),
    Failed {
        request: PaymentRequest,
        reason: String,
    },
}

macro_rules! impl_value {
    ($type:ty) => {
        impl Value for $type {
            fn encode(&self) -> String {
                serde_json::to_string(self).expect(concat!(stringify!($type), " serialization cannot fail"))
            }

            fn decode(&self, model_output: &str) -> Result<Box<dyn Value>, String> {
                serde_json::from_str::<Self>(model_output)
                    .map(|value| Box::new(value) as Box<dyn Value>)
                    .map_err(|error| error.to_string())
            }

            fn clone_box(&self) -> Box<dyn Value> {
                Box::new(self.clone())
            }
        }
    };
}

impl_value!(Eip3009Authorization);
impl_value!(PaymentState);
