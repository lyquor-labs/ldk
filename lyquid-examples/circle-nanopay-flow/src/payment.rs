use alloy_primitives::{Address, B256, U256, hex};
use lyquid::http::{Header, Method, Request, RequestOptions};
use lyquid::prelude::lyquor_api;
use lyquid_flow::ScopeId;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::eip3009::{self, UsdcDomain};
use crate::{Eip3009Authorization, PaymentConfig, PaymentReceipt, PaymentRequest, PaymentRequirements};

pub(crate) fn validate_config(config: &PaymentConfig) -> Result<(), String> {
    if config.facilitator_url.trim().is_empty() {
        return Err("x402 facilitator URL must not be empty".to_owned());
    }
    if config.settlement_rpc_url.trim().is_empty() {
        return Err("settlement RPC URL must not be empty".to_owned());
    }
    if config.network.trim().is_empty() {
        return Err("payment network must not be empty".to_owned());
    }
    if config.asset_eip712_name.is_empty() || config.asset_eip712_version.is_empty() {
        return Err("asset EIP-712 name and version must not be empty".to_owned());
    }
    config
        .asset_contract
        .parse::<Address>()
        .map_err(|error| format!("invalid asset contract {:?}: {error}", config.asset_contract))?;
    if config.allowed_resource_hosts.is_empty() {
        return Err("at least one resource host must be allowed".to_owned());
    }
    Ok(())
}

pub(crate) fn build_requirements(
    scope_id: &ScopeId, config: &PaymentConfig, request: &PaymentRequest,
) -> Result<PaymentRequirements, String> {
    let host = resource_host(&request.resource_url).ok_or_else(|| {
        format!(
            "resource URL must be https://<host>/<path> or http://127.0.0.1[:<port>]/<path>; got {:?}",
            request.resource_url
        )
    })?;
    if !config.allowed_resource_hosts.iter().any(|allowed| allowed == host) {
        return Err(format!("resource URL host {host:?} is not allowed"));
    }
    request
        .max_amount_base_units
        .parse::<u128>()
        .map_err(|error| format!("max_amount_base_units must be a decimal u128: {error}"))?;
    if request.network != config.network {
        return Err(format!(
            "payment network {:?} does not match configured network {:?}",
            request.network, config.network
        ));
    }
    if request.correlation_id.len() > 256 {
        return Err("correlation_id must be 256 bytes or shorter".to_owned());
    }
    request
        .buyer_address
        .parse::<Address>()
        .map_err(|error| format!("invalid buyer address {:?}: {error}", request.buyer_address))?;
    request
        .recipient
        .parse::<Address>()
        .map_err(|error| format!("invalid payment recipient {:?}: {error}", request.recipient))?;

    let seed = format!(
        "circle-nanopay:userpays:nonce:{scope_id}:{}:{}:{}:{}",
        request.correlation_id, request.resource_url, request.max_amount_base_units, request.recipient
    );
    let mut hasher = Sha256::new();
    hasher.update(b"WorkflowId:");
    hasher.update(seed.as_bytes());
    let nonce = format!("0x{}", hex::encode(hasher.finalize()));

    Ok(PaymentRequirements {
        network: config.network.clone(),
        chain_id: config.chain_id,
        asset_contract: config.asset_contract.clone(),
        pay_to: request.recipient.clone(),
        amount_base_units: request.max_amount_base_units.clone(),
        nonce,
        asset_eip712_name: config.asset_eip712_name.clone(),
        asset_eip712_version: config.asset_eip712_version.clone(),
    })
}

pub(crate) fn verify_authorization(
    config: &PaymentConfig, request: &PaymentRequest, requirements: &PaymentRequirements, wire: &Eip3009Authorization,
) -> Result<(), String> {
    let authorization = eip3009::parse_authorization(wire).map_err(|error| format!("decode authorization: {error}"))?;
    let buyer = request
        .buyer_address
        .parse::<Address>()
        .map_err(|error| format!("invalid buyer address {:?}: {error}", request.buyer_address))?;
    let asset = config
        .asset_contract
        .parse::<Address>()
        .map_err(|error| format!("invalid asset contract {:?}: {error}", config.asset_contract))?;
    let recipient = request
        .recipient
        .parse::<Address>()
        .map_err(|error| format!("invalid payment recipient {:?}: {error}", request.recipient))?;
    let domain = UsdcDomain {
        name: &config.asset_eip712_name,
        version: &config.asset_eip712_version,
        chain_id: config.chain_id,
        verifying_contract: asset,
    };
    let recovered = eip3009::recover_signer(&domain, &authorization)?;

    if recovered != buyer || authorization.from != buyer {
        return Err(format!("authorization is not signed by buyer {buyer}"));
    }
    if authorization.to != recipient {
        return Err(format!(
            "authorization recipient {} does not match {recipient}",
            authorization.to
        ));
    }
    let amount = U256::from_str_radix(&request.max_amount_base_units, 10)
        .map_err(|error| format!("invalid payment amount {:?}: {error}", request.max_amount_base_units))?;
    if authorization.value != amount {
        return Err(format!(
            "authorization value {} does not match {amount}",
            authorization.value
        ));
    }
    if authorization.valid_before <= authorization.valid_after {
        return Err("authorization valid_before must be greater than valid_after".to_owned());
    }
    if !wire.nonce.eq_ignore_ascii_case(&requirements.nonce) {
        return Err(format!(
            "authorization nonce {:?} does not match payment nonce {}",
            wire.nonce, requirements.nonce
        ));
    }
    Ok(())
}

pub(crate) fn settle_payment(
    config: &PaymentConfig, request: &PaymentRequest, authorization: &Eip3009Authorization,
) -> Result<PaymentReceipt, String> {
    match submit_payment(config, request, authorization) {
        Ok(receipt) => Ok(receipt),
        Err(settlement_error) => match recheck_settlement(config, request, authorization) {
            Ok(Some(transaction)) => Ok(PaymentReceipt {
                request: request.clone(),
                authorization: authorization.clone(),
                transaction: transaction.clone(),
                payment_response: json!({
                    "success": true,
                    "transaction": transaction,
                    "network": request.network,
                    "payer": request.buyer_address,
                    "amount": request.max_amount_base_units,
                    "recovered": true,
                    "recoveryReason": "matching USDC authorization and transfer observed after facilitator error",
                    "facilitatorError": settlement_error,
                }),
            }),
            Ok(None) => Err(format!(
                "{settlement_error}; automatic on-chain recheck found no matching USDC AuthorizationUsed event"
            )),
            Err(recheck_error) => Err(format!(
                "{settlement_error}; automatic on-chain recheck failed: {recheck_error}"
            )),
        },
    }
}

fn submit_payment(
    config: &PaymentConfig, request: &PaymentRequest, authorization: &Eip3009Authorization,
) -> Result<PaymentReceipt, String> {
    let requirement = json!({
        "scheme": "exact",
        "network": config.network,
        "amount": request.max_amount_base_units,
        "maxAmountRequired": request.max_amount_base_units,
        "payTo": request.recipient,
        "maxTimeoutSeconds": 60u64,
        "asset": config.asset_contract,
        "extra": {
            "name": config.asset_eip712_name,
            "version": config.asset_eip712_version,
        },
    });
    let body = json!({
        "x402Version": 2u32,
        "paymentPayload": {
            "x402Version": 2u32,
            "accepted": requirement,
            "payload": {
                "signature": authorization.signature,
                "authorization": {
                    "from": authorization.from,
                    "to": authorization.to,
                    "value": authorization.value,
                    "validAfter": authorization.valid_after,
                    "validBefore": authorization.valid_before,
                    "nonce": authorization.nonce,
                },
            },
            "resource": {
                "url": request.resource_url,
                "description": "Lyquor x402 nanopay resource",
                "mimeType": "application/json",
            },
        },
        "paymentRequirements": requirement,
    });
    let mut headers = vec![Header {
        name: "content-type".to_owned(),
        value: b"application/json".to_vec(),
    }];
    if !config.facilitator_bearer_token.trim().is_empty() {
        headers.push(Header {
            name: "authorization".to_owned(),
            value: format!("Bearer {}", config.facilitator_bearer_token.trim()).into_bytes(),
        });
    }
    let response = lyquor_api::http_request(
        Request {
            method: Method::Post,
            url: settle_url(&config.facilitator_url),
            headers,
            body: Some(serde_json::to_vec(&body).map_err(|error| format!("encode x402 request: {error}"))?),
        },
        Some(RequestOptions {
            timeout_ms: Some(30_000),
        }),
    )
    .map_err(|error| format!("x402 facilitator request failed: {error:?}"))?;
    let payment_response: Value = serde_json::from_slice(&response.body).map_err(|error| {
        format!(
            "decode x402 facilitator HTTP {} response: {error}: {}",
            response.status,
            String::from_utf8_lossy(&response.body)
        )
    })?;
    if !(200..300).contains(&response.status) || payment_response.get("success").and_then(Value::as_bool) != Some(true)
    {
        return Err(format!(
            "x402 facilitator rejected payment with HTTP {}: {payment_response}",
            response.status
        ));
    }
    let transaction = validate_facilitator_response(config, request, authorization, &payment_response)?;
    verify_settlement_transaction(config, request, authorization, &transaction)?;

    Ok(PaymentReceipt {
        request: request.clone(),
        authorization: authorization.clone(),
        transaction,
        payment_response,
    })
}

const AUTHORIZATION_USED_TOPIC: &str = "0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5";
const TRANSFER_TOPIC: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

fn validate_facilitator_response(
    config: &PaymentConfig, request: &PaymentRequest, authorization: &Eip3009Authorization, response: &Value,
) -> Result<String, String> {
    let transaction = response
        .get("transaction")
        .or_else(|| response.get("transactionHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| "x402 facilitator reported success without a transaction".to_owned())?;
    let transaction_hash = transaction
        .parse::<B256>()
        .map_err(|error| format!("x402 facilitator returned invalid transaction hash {transaction:?}: {error}"))?;
    if let Some(other) = response
        .get("transactionHash")
        .filter(|_| response.get("transaction").is_some())
        .and_then(Value::as_str)
    {
        let other_hash = other
            .parse::<B256>()
            .map_err(|error| format!("x402 facilitator returned invalid transactionHash {other:?}: {error}"))?;
        if other_hash != transaction_hash {
            return Err("x402 facilitator returned conflicting transaction hashes".to_owned());
        }
    }

    let network = response
        .get("network")
        .and_then(Value::as_str)
        .ok_or_else(|| "x402 facilitator success response is missing network".to_owned())?;
    if network != config.network {
        return Err(format!(
            "x402 facilitator response network {network:?} does not match {:?}",
            config.network
        ));
    }

    let payer = response
        .get("payer")
        .and_then(Value::as_str)
        .ok_or_else(|| "x402 facilitator success response is missing payer".to_owned())?;
    let payer = payer
        .parse::<Address>()
        .map_err(|error| format!("x402 facilitator returned invalid payer address {payer:?}: {error}"))?;
    let expected_payer = authorization
        .from
        .parse::<Address>()
        .map_err(|error| format!("invalid authorization sender {:?}: {error}", authorization.from))?;
    if payer != expected_payer {
        return Err(format!(
            "x402 facilitator response payer {payer} does not match {expected_payer}"
        ));
    }

    if let Some(amount) = response.get("amount") {
        let amount = amount
            .as_str()
            .ok_or_else(|| "x402 facilitator response amount must be a decimal string".to_owned())?;
        let amount = U256::from_str_radix(amount, 10)
            .map_err(|error| format!("x402 facilitator returned invalid amount {amount:?}: {error}"))?;
        let expected_amount = U256::from_str_radix(&request.max_amount_base_units, 10)
            .map_err(|error| format!("invalid payment amount {:?}: {error}", request.max_amount_base_units))?;
        if amount != expected_amount {
            return Err(format!(
                "x402 facilitator response amount {amount} does not match {expected_amount}"
            ));
        }
    }

    Ok(transaction.to_owned())
}

fn recheck_settlement(
    config: &PaymentConfig, request: &PaymentRequest, authorization: &Eip3009Authorization,
) -> Result<Option<String>, String> {
    let from_topic = address_topic(&authorization.from)?;
    let block_response = rpc_post_json(
        &config.settlement_rpc_url,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_blockNumber",
            "params": [],
        }),
    )?;
    let block_number = rpc_result(&block_response, "eth_blockNumber")?
        .and_then(Value::as_str)
        .and_then(parse_hex_u64)
        .ok_or_else(|| "settlement RPC returned an invalid block number".to_owned())?;
    let logs = rpc_post_json(
        &config.settlement_rpc_url,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getLogs",
            "params": [{
                "fromBlock": hex_u64(block_number.saturating_sub(1_900)),
                "toBlock": hex_u64(block_number),
                "address": config.asset_contract,
                "topics": [AUTHORIZATION_USED_TOPIC, from_topic, authorization.nonce],
            }],
        }),
    )?;
    let entries = rpc_result(&logs, "eth_getLogs")?
        .and_then(Value::as_array)
        .ok_or_else(|| format!("settlement RPC returned an invalid log response: {logs}"))?;
    let mut validation_error = None;
    for transaction in entries
        .iter()
        .rev()
        .filter_map(|entry| entry.get("transactionHash").and_then(Value::as_str))
    {
        match verify_settlement_transaction(config, request, authorization, transaction) {
            Ok(()) => return Ok(Some(transaction.to_owned())),
            Err(error) => validation_error = Some(error),
        }
    }
    match validation_error {
        Some(error) => Err(format!("no recovered settlement matched the payment: {error}")),
        None => Ok(None),
    }
}

fn verify_settlement_transaction(
    config: &PaymentConfig, request: &PaymentRequest, authorization: &Eip3009Authorization, transaction: &str,
) -> Result<(), String> {
    let transaction_hash = transaction
        .parse::<B256>()
        .map_err(|error| format!("invalid settlement transaction hash {transaction:?}: {error}"))?;
    let chain_response = rpc_post_json(
        &config.settlement_rpc_url,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_chainId",
            "params": [],
        }),
    )?;
    let chain_id = rpc_result(&chain_response, "eth_chainId")?
        .and_then(Value::as_str)
        .and_then(parse_hex_u64)
        .ok_or_else(|| "settlement RPC returned an invalid chain ID".to_owned())?;
    if chain_id != config.chain_id {
        return Err(format!(
            "settlement RPC chain ID {chain_id} does not match {}",
            config.chain_id
        ));
    }

    let receipt_response = rpc_post_json(
        &config.settlement_rpc_url,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getTransactionReceipt",
            "params": [transaction],
        }),
    )?;
    let receipt = rpc_result(&receipt_response, "eth_getTransactionReceipt")?
        .and_then(Value::as_object)
        .ok_or_else(|| format!("settlement transaction {transaction} does not have a receipt yet"))?;
    let receipt_hash = receipt
        .get("transactionHash")
        .and_then(Value::as_str)
        .ok_or_else(|| "settlement receipt is missing transactionHash".to_owned())?
        .parse::<B256>()
        .map_err(|error| format!("settlement receipt contains an invalid transactionHash: {error}"))?;
    if receipt_hash != transaction_hash {
        return Err("settlement receipt transaction hash does not match the facilitator response".to_owned());
    }
    if receipt.get("status").and_then(Value::as_str).and_then(parse_hex_u64) != Some(1) {
        return Err(format!("settlement transaction {transaction} did not succeed"));
    }

    let asset = config
        .asset_contract
        .parse::<Address>()
        .map_err(|error| format!("invalid asset contract {:?}: {error}", config.asset_contract))?;
    let authorization_topic = AUTHORIZATION_USED_TOPIC
        .parse::<B256>()
        .expect("the static AuthorizationUsed topic must be valid");
    let transfer_topic = TRANSFER_TOPIC
        .parse::<B256>()
        .expect("the static Transfer topic must be valid");
    let from_topic = address_topic(&authorization.from)?
        .parse::<B256>()
        .expect("address_topic must return a valid topic");
    let recipient_topic = address_topic(&request.recipient)?
        .parse::<B256>()
        .expect("address_topic must return a valid topic");
    let nonce = authorization
        .nonce
        .parse::<B256>()
        .map_err(|error| format!("invalid authorization nonce {:?}: {error}", authorization.nonce))?;
    let amount = U256::from_str_radix(&request.max_amount_base_units, 10)
        .map_err(|error| format!("invalid payment amount {:?}: {error}", request.max_amount_base_units))?;
    let logs = receipt
        .get("logs")
        .and_then(Value::as_array)
        .ok_or_else(|| "settlement receipt is missing logs".to_owned())?;
    let mut authorization_used = false;
    let mut transferred = false;
    for log in logs {
        if log.get("removed").and_then(Value::as_bool) == Some(true) ||
            log.get("address")
                .and_then(Value::as_str)
                .and_then(|address| address.parse::<Address>().ok()) !=
                Some(asset)
        {
            continue;
        }
        let Some(topics) = log.get("topics").and_then(Value::as_array) else {
            continue;
        };
        let topic = |index| {
            topics
                .get(index)
                .and_then(Value::as_str)
                .and_then(|topic| topic.parse::<B256>().ok())
        };
        authorization_used |=
            topic(0) == Some(authorization_topic) && topic(1) == Some(from_topic) && topic(2) == Some(nonce);
        transferred |= topic(0) == Some(transfer_topic) &&
            topic(1) == Some(from_topic) &&
            topic(2) == Some(recipient_topic) &&
            log.get("data").and_then(Value::as_str).and_then(parse_hex_u256) == Some(amount);
    }
    if !authorization_used {
        return Err("settlement receipt does not contain the expected USDC AuthorizationUsed event".to_owned());
    }
    if !transferred {
        return Err("settlement receipt does not contain the expected USDC Transfer event".to_owned());
    }
    Ok(())
}

fn rpc_post_json(url: &str, body: Value) -> Result<Value, String> {
    let response = lyquor_api::http_request(
        Request {
            method: Method::Post,
            url: url.to_owned(),
            headers: vec![Header {
                name: "content-type".to_owned(),
                value: b"application/json".to_vec(),
            }],
            body: Some(serde_json::to_vec(&body).map_err(|error| format!("encode settlement RPC request: {error}"))?),
        },
        Some(RequestOptions {
            timeout_ms: Some(10_000),
        }),
    )
    .map_err(|error| format!("settlement RPC request failed: {error:?}"))?;
    if !(200..300).contains(&response.status) {
        return Err(format!(
            "settlement RPC returned HTTP {}: {}",
            response.status,
            String::from_utf8_lossy(&response.body)
        ));
    }
    serde_json::from_slice(&response.body).map_err(|error| format!("decode settlement RPC response: {error}"))
}

fn rpc_result<'a>(response: &'a Value, method: &str) -> Result<Option<&'a Value>, String> {
    if let Some(error) = response.get("error") {
        return Err(format!("settlement RPC {method} failed: {error}"));
    }
    Ok(response.get("result"))
}

fn address_topic(address: &str) -> Result<String, String> {
    let address = address.trim_start_matches("0x");
    if address.len() != 40 || !address.chars().all(|character| character.is_ascii_hexdigit()) {
        return Err("payment authorization contains an invalid sender address".to_owned());
    }
    Ok(format!("0x{:0>64}", address.to_ascii_lowercase()))
}

fn parse_hex_u64(value: &str) -> Option<u64> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16).ok()
}

fn parse_hex_u256(value: &str) -> Option<U256> {
    let value = value.trim_start_matches("0x");
    (!value.is_empty())
        .then(|| U256::from_str_radix(value, 16).ok())
        .flatten()
}

fn hex_u64(value: u64) -> String {
    format!("0x{value:x}")
}

fn settle_url(base: &str) -> String {
    let base = base.trim().trim_end_matches('/');
    if base.ends_with("/settle") {
        base.to_owned()
    } else {
        format!("{base}/settle")
    }
}

fn resource_host(url: &str) -> Option<&str> {
    if let Some(rest) = url.strip_prefix("https://") {
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let host = &rest[..end];
        return (!host.is_empty() && !host.contains(['@', ':'])).then_some(host);
    }
    let rest = url.strip_prefix("http://127.0.0.1")?;
    match rest.chars().next() {
        None | Some('/' | '?' | '#') => Some("127.0.0.1"),
        Some(':') => {
            let port = &rest[1..];
            let end = port
                .find(|character: char| !character.is_ascii_digit())
                .unwrap_or(port.len());
            let suffix = &port[end..];
            (end > 0 && (suffix.is_empty() || suffix.starts_with(['/', '?', '#']))).then_some("127.0.0.1")
        }
        _ => None,
    }
}
