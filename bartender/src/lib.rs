use lyquid::runtime::*;
use lyquor_primitives::{B256, RegisterEvent};
use serde::*;

#[derive(Serialize, Clone, Debug)]
struct DeployInfo {
    contract: Address,
}

struct LyquidMetadata {
    owner: Address,
    deploy_history: Vec<DeployInfo>,
    dependencies: Vec<LyquidID>,
}

struct NodeMetadata {
    addr: Address,
}

#[derive(Serialize)]
struct LyquidMetadataOutput {
    owner: Address,
    deploy_history: Vec<DeployInfo>,
    dependencies: Vec<LyquidID>,
}

lyquid::state! {
    network lyquid_registry: HashMap<LyquidID, LyquidMetadata> = new_hashmap();
    network owner_nonce: HashMap<Address, u64> = new_hashmap();
    network eth_addrs: HashMap<Address, LyquidID> = new_hashmap();
    network node_registry: HashMap<NodeID, NodeMetadata> = new_hashmap();
}

fn next_lyquid_id(
    ctx: &mut __lyquid::NetworkContext, owner: Address, contract: Address, deps: Vec<LyquidID>,
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
    metadata.deploy_history.push(DeployInfo { contract });
    // Store the dependencies for this lyquid
    for dep in deps {
        metadata.dependencies.push(dep);
    }
    id
}

fn update_eth_addr(
    ctx: &mut __lyquid::NetworkContext, owner: Address, old: Address, new: Address, deps: Vec<LyquidID>,
) -> Option<LyquidID> {
    // otherwise we need to find the existing lyquid
    let id = *ctx.network.eth_addrs.get(&old)?;
    let metadata = ctx.network.lyquid_registry.get_mut(&id)?;
    if metadata.owner == owner && metadata.deploy_history.last()?.contract == old {
        metadata.deploy_history.push(DeployInfo { contract: new });
        // Update dependencies for this deployment
        metadata.dependencies.clear();
        for dep in deps {
            metadata.dependencies.push(dep);
        }
        Some(id)
    } else {
        None
    }
}

#[lyquid::method::network(export = eth)]
fn constructor(ctx: &mut _) {
    // NOTE: it is specially treated (in contract generation) that the caller of bartender's
    // contract is the contract address itself
}

#[lyquid::method::network(export = eth)]
fn register(ctx: &mut _, superseded: Address, deps: Vec<Address>) -> LyquidResult<bool> {
    let owner = ctx.origin;
    let contract = ctx.caller;

    // Convert dependency addresses to LyquidIDs
    let deps: Vec<LyquidID> = deps
        .iter()
        .filter_map(|addr| ctx.network.eth_addrs.get(addr).copied())
        .collect();

    let id = if superseded == Address::ZERO {
        // create a new lyquid
        Some(next_lyquid_id(&mut ctx, owner, contract, deps.clone()))
    } else {
        update_eth_addr(&mut ctx, owner, superseded, contract, deps.clone())
    }
    .ok_or(LyquidError::LyquidRuntime("invalid register call".into()))?;

    lyquid::println!("register {id} (owner={owner}, contract={contract}, deps={:?})", deps);
    lyquid::log!(Register, &RegisterEvent { id, deps });
    ctx.network.eth_addrs.insert(contract, id);
    Ok(true)
}

#[lyquid::method::network(export = eth)]
fn set_ed25519_address(ctx: &mut _, pubkey: B256, qx: U256, qy: U256, addr: Address) -> LyquidResult<bool> {
    let pubkey_bytes: [u8; 32] = *pubkey.as_ref();
    if !lyquor_api::check_ed25519_pubkey(pubkey_bytes, qx, qy)? {
        // Mismatching pubkey/qx/qy info.
        return Ok(false)
    }
    let id = NodeID::from(pubkey_bytes);
    lyquid::println!("set_ed25519_address {id} => {addr}");
    ctx.network
        .node_registry
        .entry(id)
        .or_insert_with(|| NodeMetadata { addr: Address::ZERO })
        .addr = addr;
    Ok(true)
}

#[lyquid::method::instance]
fn get_ed25519_address(ctx: &_, id: NodeID) -> LyquidResult<Option<Address>> {
    let ret = ctx.network.node_registry.get(&id).map(|r| r.addr);
    lyquid::println!("get_ed25519_address {id} = {ret:?}");
    Ok(ret)
}

#[lyquid::method::instance]
fn get_lyquid_info(ctx: &_, id: LyquidID) -> LyquidResult<Option<LyquidMetadataOutput>> {
    Ok(ctx.network.lyquid_registry.get(&id).map(|d| LyquidMetadataOutput {
        owner: d.owner,
        deploy_history: d.deploy_history.to_vec(),
        dependencies: d.dependencies.to_vec(),
    }))
}

#[lyquid::method::instance]
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

#[lyquid::method::instance]
fn get_last_lyquid_deployment_info(ctx: &_, id: LyquidID) -> LyquidResult<Option<DeployInfo>> {
    Ok(ctx
        .network
        .lyquid_registry
        .get(&id)
        .and_then(|d| d.deploy_history.last())
        .cloned())
}

#[lyquid::method::instance]
fn get_lyquid_id_by_eth_addr(ctx: &_, addr: Address) -> LyquidResult<Option<LyquidID>> {
    Ok(ctx.network.eth_addrs.get(&addr).copied())
}

#[lyquid::method::instance]
fn get_eth_addr(ctx: &_, id: LyquidID, ln_image: u32) -> LyquidResult<Option<Address>> {
    Ok(ctx.network.lyquid_registry.get(&id).and_then(|e| {
        if ln_image < 1 {
            return None
        }
        let ln_image = ln_image as usize - 1;
        if ln_image < e.deploy_history.len() {
            Some(e.deploy_history[ln_image].contract)
        } else {
            None
        }
    }))
}

#[lyquid::method::instance]
fn get_lyquid_list(ctx: &_) -> LyquidResult<Vec<LyquidID>> {
    Ok(ctx.network.lyquid_registry.keys().copied().collect())
}

#[lyquid::method::instance]
fn get_lyquid_list_with_deps(ctx: &_) -> LyquidResult<Vec<(LyquidID, Vec<LyquidID>)>> {
    Ok(ctx
        .network
        .lyquid_registry
        .iter()
        .map(|(id, metadata)| (*id, metadata.dependencies.to_vec()))
        .collect())
}

#[lyquid::method::instance]
fn eth_abi_test1(ctx: &_, x: U256, y: Vec<String>, z: [Vec<u64>; 4]) -> LyquidResult<U256> {
    lyquid::println!("got x = {}, y = {:?}, z = {:?} from {}", x, y, z, ctx.caller);
    Ok(x + uint!(1_U256))
}
