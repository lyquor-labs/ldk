use alloy_primitives::{Address, B256, Signature, U256, hex};
use alloy_sol_types::{SolStruct, eip712_domain, sol};

use crate::Eip3009Authorization;

sol! {
    struct TransferWithAuthorization {
        address from;
        address to;
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
    }
}

pub(crate) struct UsdcDomain<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub chain_id: u64,
    pub verifying_contract: Address,
}

pub(crate) struct Authorization {
    pub from: Address,
    pub to: Address,
    pub value: U256,
    pub valid_after: U256,
    pub valid_before: U256,
    pub nonce: B256,
    pub signature: [u8; 65],
}

pub(crate) fn parse_authorization(wire: &Eip3009Authorization) -> Result<Authorization, String> {
    let from = wire
        .from
        .parse()
        .map_err(|error| format!("from {:?}: {error}", wire.from))?;
    let to = wire.to.parse().map_err(|error| format!("to {:?}: {error}", wire.to))?;
    let value = U256::from_str_radix(&wire.value, 10).map_err(|error| format!("value {:?}: {error}", wire.value))?;
    let valid_after = U256::from_str_radix(&wire.valid_after, 10)
        .map_err(|error| format!("valid_after {:?}: {error}", wire.valid_after))?;
    let valid_before = U256::from_str_radix(&wire.valid_before, 10)
        .map_err(|error| format!("valid_before {:?}: {error}", wire.valid_before))?;
    let nonce = wire
        .nonce
        .parse()
        .map_err(|error| format!("nonce {:?}: {error}", wire.nonce))?;
    let signature = hex::decode(wire.signature.trim_start_matches("0x"))
        .map_err(|error| format!("signature hex {:?}: {error}", wire.signature))?;
    let signature = signature
        .as_slice()
        .try_into()
        .map_err(|_| format!("signature must be 65 bytes (r||s||v); got {}", signature.len()))?;

    Ok(Authorization {
        from,
        to,
        value,
        valid_after,
        valid_before,
        nonce,
        signature,
    })
}

pub(crate) fn recover_signer(domain: &UsdcDomain<'_>, authorization: &Authorization) -> Result<Address, String> {
    let domain = eip712_domain! {
        name: domain.name.to_owned(),
        version: domain.version.to_owned(),
        chain_id: domain.chain_id,
        verifying_contract: domain.verifying_contract,
    };
    let payload = TransferWithAuthorization {
        from: authorization.from,
        to: authorization.to,
        value: authorization.value,
        validAfter: authorization.valid_after,
        validBefore: authorization.valid_before,
        nonce: authorization.nonce,
    };
    let digest = payload.eip712_signing_hash(&domain);
    let signature = Signature::try_from(authorization.signature.as_slice())
        .map_err(|error| format!("bad signature bytes: {error}"))?;
    signature
        .recover_address_from_prehash(&digest)
        .map_err(|error| format!("recover EIP-3009 signer: {error}"))
}
