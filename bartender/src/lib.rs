//! Reference Lyquid registry contract.
//!
//! Bartender is itself a Lyquid: it stores deployment metadata, dependency lists, owner state, and
//! Ed25519-to-address mappings in network memory. Nodes and tools query it to resolve a Lyquid ID
//! and deployment into a contract address, image digest, optional repository hint, and dependency
//! set. The methods in this crate are the contract surface that hosting and tooling treat as the
//! registry authority.

use hashbrown::hash_map::Entry;
use lyquid::prelude::*;
use lyquor_primitives::{AvailabilityPendingEvent, B256, DeployStatus, RegisterEvent};
use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
struct DeployInfo {
    contract: Address,
    repo_hint: Option<String>,
    image_digest: B256,
    status: DeployStatus,
}

#[derive(Serialize, Clone, Debug)]
struct LyquidMetadata {
    owner: Address,
    deploy_history: Vec<DeployInfo>,
    dependencies: Vec<LyquidID>,
}

struct NodeMetadata {
    addr: Address,
}

state! {
    network lyquid_registry: HashMap<LyquidID, LyquidMetadata> = new_hashmap();
    network owner_nonce: HashMap<Address, u64> = new_hashmap();
    network lyquid_ids: HashMap<Address, LyquidID> = new_hashmap();
    network node_ids: HashMap<Address, NodeID> = new_hashmap();
    network node_registry: HashMap<NodeID, NodeMetadata> = new_hashmap();
    // Monotonic admission set keyed by content digest. Once the network
    // certifies a digest, the platform assumes custody and later deployments
    // reuse that admission instead of stalling in Pending. Epoch 0 and
    // bartender use the same compatibility bypass as deployment admission.
    network admitted_images: HashSet<B256> = new_hashset();
    // Committee-certified image-availability rail for deployment admission.
    network oracle availability;
    // Image digests this node has pulled and content-verified locally; written
    // by the node's availability worker, read by the certification validator.
    instance verified_images: HashMap<B256, bool> = new_hashmap();
}

fn availability_target(lyquid_id: LyquidID) -> LyquidResult<OracleTarget> {
    Ok(OracleTarget {
        seq_id: lyquor_api::sequence_backend_id()?,
        target: OracleServiceTarget::LVM(lyquid_id),
    })
}

/// Admission status assigned to a deployment referencing `image_digest`.
fn deployment_status_for_registration(
    ctx: &__lyquid::NetworkContext, id: LyquidID, image_digest: B256,
) -> LyquidResult<DeployStatus> {
    // Bartender is exempt by identity: the availability rail runs through
    // bartender, so its own deployments must never wait on it.
    if id == ctx.lyquid_id || ctx.network.admitted_images.contains(&image_digest) {
        return Ok(DeployStatus::Live);
    }
    // Epoch-0 rule: until an availability committee has finalized its first
    // epoch in bartender's own network state, the gate is inactive and
    // deployments go Live at registration (legacy behavior). This keeps
    // localnet and tests working with zero ceremony, and turns the gate on
    // deterministically once a committee activates.
    let target = availability_target(ctx.lyquid_id)?;
    Ok(if ctx.network.availability.get_epoch(ctx, target) == 0 {
        DeployStatus::Live
    } else {
        DeployStatus::Pending
    })
}

fn next_lyquid_id(
    ctx: &mut __lyquid::NetworkContext, owner: Address, contract: Address, repo_hint: Option<String>,
    image_digest: B256, deps: Vec<LyquidID>, status: DeployStatus,
) -> LyquidID {
    let id = {
        let nonce = ctx.network.owner_nonce.entry(owner).or_insert(0);
        let id = LyquidID::from_owner_nonce(&owner, *nonce);
        *nonce += 1;
        id
    };
    let metadata = ctx.network.lyquid_registry.entry(id).or_insert_with(|| LyquidMetadata {
        owner,
        deploy_history: Vec::new(),
        dependencies: Vec::new(),
    });
    metadata.deploy_history.push(DeployInfo {
        contract,
        repo_hint,
        image_digest,
        status,
    });
    // Store the dependencies for this lyquid
    for dep in deps {
        metadata.dependencies.push(dep);
    }
    id
}

fn update_eth_addr(
    ctx: &mut __lyquid::NetworkContext, owner: Address, old: Address, new: Address, repo_hint: Option<String>,
    image_digest: B256,
) -> LyquidResult<Option<(LyquidID, DeployStatus)>> {
    // otherwise we need to find the existing lyquid
    let Some(id) = ctx.network.lyquid_ids.get(&old).copied() else {
        return Ok(None);
    };
    let tail_status = {
        let Some(metadata) = ctx.network.lyquid_registry.get(&id) else {
            return Ok(None);
        };
        let Some(tail) = metadata.deploy_history.last() else {
            return Ok(None);
        };
        if metadata.owner != owner || tail.contract != old {
            return Ok(None);
        }
        tail.status
    };
    let admission = deployment_status_for_registration(ctx, id, image_digest)?;
    // A live Lyquid cannot wait at an unadmitted upgrade, and a voided Lyquid
    // is not recoverable. Never-hosted Pending tails may still be replaced.
    let status = match (tail_status, admission) {
        (DeployStatus::Void, _) | (DeployStatus::Live, DeployStatus::Pending) => DeployStatus::Void,
        (_, status) => status,
    };
    let Some(metadata) = ctx.network.lyquid_registry.get_mut(&id) else {
        return Ok(None);
    };
    if tail_status == DeployStatus::Pending {
        let Some(tail) = metadata.deploy_history.last_mut() else {
            return Ok(None);
        };
        tail.status = DeployStatus::Void;
    }
    metadata.deploy_history.push(DeployInfo {
        contract: new,
        repo_hint,
        image_digest,
        status,
    });
    // Dependencies belong to the Lyquid ID and remain the ones recorded by its first registration.
    Ok(Some((id, status)))
}

#[method::network(export = eth)]
fn constructor(ctx: &mut _) {
    // NOTE: it is specially treated (in contract generation) that the caller of bartender's
    // contract is the contract address itself
}

#[method::network(export = eth)]
fn register(
    ctx: &mut _, superseded: Address, deps: Vec<LyquidID>, image_digest: B256, repo_hint: String,
) -> LyquidResult<bool> {
    let owner = ctx.origin;
    let contract = ctx.caller;

    if deps.contains(&ctx.lyquid_id) {
        return Err(LyquidError::LyquidRuntime(
            "bartender cannot be a Lyquid dependency".into(),
        ));
    }
    if let Some(id) = deps.iter().find(|id| !ctx.network.lyquid_registry.contains_key(*id)) {
        return Err(LyquidError::LyquidRuntime(format!("unknown Lyquid dependency {id}")));
    }
    let repo_hint = if repo_hint.is_empty() { None } else { Some(repo_hint) };

    let (id, status) = if superseded == Address::ZERO {
        // Peek the ID this registration will be assigned so the availability
        // status (bartender exemption, epoch-0 rule) can be decided up front.
        let next_nonce = ctx.network.owner_nonce.get(&owner).copied().unwrap_or(0);
        let status =
            deployment_status_for_registration(&ctx, LyquidID::from_owner_nonce(&owner, next_nonce), image_digest)?;
        // create a new lyquid
        let id = next_lyquid_id(&mut ctx, owner, contract, repo_hint.clone(), image_digest, deps, status);
        (Some(id), status)
    } else {
        // Upgrade path; an unadmitted image voids a live Lyquid instead of
        // leaving its deployment Pending.
        match update_eth_addr(&mut ctx, owner, superseded, contract, repo_hint.clone(), image_digest)? {
            Some((id, status)) => (Some(id), status),
            None => (None, DeployStatus::Live),
        }
    };
    let id = id.ok_or(LyquidError::LyquidRuntime("invalid register call".into()))?;
    let deps = ctx
        .network
        .lyquid_registry
        .get(&id)
        .map(|metadata| metadata.dependencies.to_vec())
        .ok_or(LyquidError::LyquidRuntime(
            "registered Lyquid metadata is missing".into(),
        ))?;
    ctx.network.lyquid_ids.insert(contract, id);
    if status == DeployStatus::Live {
        // Images admitted while the gate is disabled (and bartender's image)
        // are grandfathered. Reusing identical content after the committee
        // activates cannot introduce code that was not already admitted.
        ctx.network.admitted_images.insert(image_digest);
    }
    lyquid::println!(
        "register {id} (owner={owner}, contract={contract}, deps={:?}, status={status:?})",
        deps
    );
    match status {
        // Hostable right away: announce as before.
        DeployStatus::Live => lyquid::log!(Register, &RegisterEvent { id, deps }),
        // Not hostable yet: prompt nodes to pull the image and certify its
        // availability. The Register log is emitted by `attest_available`
        // once the deployment flips Live.
        DeployStatus::Pending => {
            let nth = ctx
                .network
                .lyquid_registry
                .get(&id)
                .map_or(0, |m| m.deploy_history.len().saturating_sub(1)) as u32;
            lyquid::log!(
                AvailabilityPending,
                &AvailabilityPendingEvent {
                    id,
                    nth,
                    image_digest,
                    repo_hint,
                }
            )
        }
        // A void upgrade is terminal and produces no hosting work.
        DeployStatus::Void => {}
    }
    Ok(true)
}

// Committee-certified availability verdict for content `image_digest`.
// Every pending deployment referencing the digest becomes hostable.
// Certificate verification (committee signatures, epoch, nonce replay) is
// enforced by the generated `oracle::certified` wrapper before this body runs.
#[method::network(group = oracle::certified::availability)]
fn attest_available(ctx: &mut _, image_digest: B256) -> LyquidResult<bool> {
    if !ctx.network.admitted_images.insert(image_digest) {
        return Ok(true);
    }
    let mut activated = Vec::new();
    for (id, metadata) in ctx.network.lyquid_registry.iter_mut() {
        let Some(info) = metadata.deploy_history.last_mut() else {
            continue;
        };
        if info.image_digest == image_digest && info.status == DeployStatus::Pending {
            info.status = DeployStatus::Live;
            activated.push((*id, metadata.dependencies.to_vec()));
        }
    }
    activated.sort_by_key(|(id, _)| *id);
    lyquid::println!(
        "attest_available {image_digest} => Live ({} deployments)",
        activated.len()
    );
    for (id, deps) in activated {
        lyquid::log!(Register, &RegisterEvent { id, deps });
    }
    Ok(true)
}

// Committee validator for availability certificates: votes yea only when the
// proposed digest is not already admitted and this node has pulled and
// content-verified the corresponding image locally.
#[method::instance(group = oracle::single_phase::availability)]
fn validate(ctx: &mut _, params: CallParams, _extra: Bytes, target: OracleTarget) -> LyquidResult<bool> {
    if target.seq_id != lyquor_api::sequence_backend_id()? {
        return Ok(false);
    }
    if !matches!(target.target, OracleServiceTarget::LVM(dest) if dest == ctx.lyquid_id) {
        return Ok(false);
    }
    if params.method != "attest_available" {
        return Ok(false);
    }
    let Some(claim) = decode_by_fields!(&params.input, image_digest: B256) else {
        return Ok(false);
    };
    if ctx.network.admitted_images.contains(&claim.image_digest) {
        return Ok(false);
    }
    Ok(ctx.instance.verified_images.read().contains_key(&claim.image_digest))
}

// Record that this node has pulled and content-verified an image digest.
// Called by the node's availability worker after a successful pull; the
// flag is node-local (instance state) and feeds `validate`.
#[method::instance]
fn note_image_verified(ctx: &mut _, image_digest: B256) -> LyquidResult<bool> {
    ctx.instance.verified_images.write().insert(image_digest, true);
    Ok(true)
}

// Propose an availability certificate for content this node has verified
// locally. Runs the single-phase validate round across the availability
// committee and submits the certified `attest_available` call.
#[method::instance]
fn certify_availability(ctx: &mut _, image_digest: B256) -> LyquidResult<bool> {
    if ctx.network.admitted_images.contains(&image_digest) {
        return Ok(true);
    }
    if !ctx.instance.verified_images.read().contains_key(&image_digest) {
        return Ok(false);
    }
    let target = availability_target(ctx.lyquid_id)?;
    let o = ctx.network.availability.clone();
    let cert = o.certify(
        &mut ctx,
        CertifiedCallParams {
            origin: Address::ZERO,
            method: "attest_available".into(),
            input: encode_by_fields!(image_digest: B256 = image_digest).into(),
            target,
        },
        Bytes::new(),
        None,
        None,
    )?;
    match cert {
        Some(cert) => {
            let _ = submit_certified_call!(cert)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

// Whether content `image_digest` is admissible under the network's gate.
#[method::instance]
fn is_image_admitted(ctx: &_, image_digest: B256) -> LyquidResult<bool> {
    let target = availability_target(ctx.lyquid_id)?;
    Ok(ctx.network.availability.get_epoch(&ctx, target) == 0 || ctx.network.admitted_images.contains(&image_digest))
}

// List deployments still awaiting an availability verdict, for the node's
// availability worker to (re)try pulling and certifying.
#[method::instance]
fn get_pending_deployments(ctx: &_) -> LyquidResult<Vec<AvailabilityPendingEvent>> {
    Ok(ctx
        .network
        .lyquid_registry
        .iter()
        .filter_map(|(id, m)| {
            let nth = m.deploy_history.len().checked_sub(1)?;
            let info = &m.deploy_history[nth];
            (info.status == DeployStatus::Pending).then(|| AvailabilityPendingEvent {
                id: *id,
                nth: nth as u32,
                image_digest: info.image_digest,
                repo_hint: info.repo_hint.clone(),
            })
        })
        .collect())
}

// Availability status of the specific deployment made by `contract`, encoded
// for eth-ABI callers: 0 = Pending, 1 = Live, 2 = Void, 255 = unknown contract.
#[method::instance(export = eth)]
fn get_deployment_status(ctx: &_, contract: Address) -> LyquidResult<u8> {
    Ok(ctx
        .network
        .lyquid_ids
        .get(&contract)
        .and_then(|id| ctx.network.lyquid_registry.get(id))
        .and_then(|m| m.deploy_history.iter().rev().find(|info| info.contract == contract))
        .map_or(255, |info| match info.status {
            DeployStatus::Pending => 0,
            DeployStatus::Live => 1,
            DeployStatus::Void => 2,
        }))
}

#[method::network(export = eth)]
fn set_ed25519_address(ctx: &mut _, pubkey: B256, qx: U256, qy: U256, address: Address) -> LyquidResult<bool> {
    let pubkey_bytes: [u8; 32] = *pubkey.as_ref();
    let (expected_qx, expected_qy) = lyquor_api::get_ed25519_qxy(pubkey_bytes)?;
    if qx != expected_qx || qy != expected_qy {
        // Mismatching pubkey/qx/qy info.
        return Ok(false);
    }
    let id = NodeID::from(pubkey_bytes);
    let old_address = match ctx.network.node_registry.entry(id) {
        Entry::Occupied(mut entry) => {
            if entry.get().addr == address {
                return Ok(true);
            }
            let old_address = entry.get().addr;
            entry.get_mut().addr = address;
            Some(old_address)
        }
        Entry::Vacant(entry) => {
            entry.insert(NodeMetadata { addr: address });
            None
        }
    };
    lyquid::println!("set_ed25519_address {id} => {address}");
    if let Some(old_address) = old_address {
        ctx.network.node_ids.remove(&old_address);
    }
    if let Some(other_id) = ctx.network.node_ids.insert(address, id) &&
        other_id != id
    {
        ctx.network.node_registry.remove(&other_id);
    }
    Ok(true)
}

#[method::instance]
fn get_address_by_ed25519(ctx: &_, id: NodeID) -> LyquidResult<Option<Address>> {
    let ret = ctx.network.node_registry.get(&id).map(|r| r.addr);
    lyquid::println!("get_address_by_ed25519 {id} = {ret:?}");
    Ok(ret)
}

#[method::instance]
fn get_ed25519_by_address(ctx: &_, address: Address) -> LyquidResult<Option<NodeID>> {
    let ret = ctx.network.node_ids.get(&address).copied();
    lyquid::println!("get_ed25519_by_address {address} = {ret:?}");
    Ok(ret)
}

#[method::instance]
fn get_lyquid_info(ctx: &_, id: LyquidID) -> LyquidResult<Option<LyquidMetadata>> {
    Ok(ctx.network.lyquid_registry.get(&id).cloned())
}

#[method::instance]
fn get_lyquid_deployment_info(ctx: &_, id: LyquidID, nth: u32) -> LyquidResult<Option<DeployInfo>> {
    let nth = nth as usize;
    Ok(ctx.network.lyquid_registry.get(&id).and_then(|d| {
        if nth < d.deploy_history.len() {
            Some(d.deploy_history[nth].clone())
        } else {
            None
        }
    }))
}

// Index of the first `Live` deployment — where hosting starts. Any earlier
// entries were never executable, so a fresh host can skip them safely.
#[method::instance]
fn get_hosting_base(ctx: &_, id: LyquidID) -> LyquidResult<Option<u32>> {
    Ok(ctx.network.lyquid_registry.get(&id).and_then(|d| {
        d.deploy_history
            .iter()
            .position(|info| info.status == DeployStatus::Live)
            .map(|idx| idx as u32)
    }))
}

#[method::instance]
fn get_last_lyquid_deployment_info(ctx: &_, id: LyquidID) -> LyquidResult<Option<DeployInfo>> {
    Ok(ctx
        .network
        .lyquid_registry
        .get(&id)
        .and_then(|d| d.deploy_history.last())
        .cloned())
}

#[method::instance]
fn get_lyquid_id_by_eth_addr(ctx: &_, addr: Address) -> LyquidResult<Option<LyquidID>> {
    Ok(ctx.network.lyquid_ids.get(&addr).copied())
}

#[method::instance]
fn get_eth_addr(ctx: &_, id: LyquidID, ln_image: u32) -> LyquidResult<Option<Address>> {
    Ok(ctx.network.lyquid_registry.get(&id).and_then(|e| {
        if ln_image < 1 {
            return None;
        }
        // The instance's image counter starts at the hosting base (the first
        // Live deployment): a void prefix never loads an image, so the nth
        // loaded image corresponds to deploy_history[base + n - 1].
        let base = e
            .deploy_history
            .iter()
            .position(|info| info.status == DeployStatus::Live)?;
        let idx = base + (ln_image as usize - 1);
        if idx < e.deploy_history.len() {
            Some(e.deploy_history[idx].contract)
        } else {
            None
        }
    }))
}

#[method::instance]
fn get_lyquid_list(ctx: &_) -> LyquidResult<Vec<LyquidID>> {
    Ok(ctx.network.lyquid_registry.keys().copied().collect())
}

#[method::instance]
fn get_lyquid_list_with_deps(ctx: &_) -> LyquidResult<Vec<(LyquidID, Vec<LyquidID>)>> {
    Ok(ctx
        .network
        .lyquid_registry
        .iter()
        .map(|(id, metadata)| (*id, metadata.dependencies.to_vec()))
        .collect())
}
