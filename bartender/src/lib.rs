#![feature(allocator_api)]
use lyquid::runtime::*;
use serde::*;

#[derive(Serialize, Clone, Debug)]
struct DeployInfo {
    contract: Address,
}

struct LyquidMetadata {
    owner: Address,
    deploy_history: network::Vec<DeployInfo>,
}

#[derive(Serialize)]
struct LyquidMetadataOutput {
    owner: Address,
    deploy_history: Vec<DeployInfo>,
}

lyquid::state! {
    network lyquid_registry: network::HashMap<LyquidID, LyquidMetadata> = network::new_hashmap();
    network owner_nonce: network::HashMap<Address, u64> = network::new_hashmap();
    network eth_addrs: network::HashMap<Address, LyquidID> = network::new_hashmap();
}

fn next_lyquid_id(ctx: &mut __lyquid::NetworkContext, owner: Address, contract: Address) -> LyquidID {
    let id = {
        let nonce = ctx.network.owner_nonce.entry(owner).or_insert(0);
        let id = LyquidID::from_owner_nonce(&owner, *nonce);
        *nonce += 1;
        id
    };
    ctx.network
        .lyquid_registry
        .entry(id)
        .or_insert_with(|| LyquidMetadata {
            owner,
            deploy_history: network::new_vec(),
        })
        .deploy_history
        .push(DeployInfo { contract });
    id
}

fn update_eth_addr(ctx: &mut __lyquid::NetworkContext, owner: Address, old: Address, new: Address) -> Option<LyquidID> {
    // otherwise we need to find the existing lyquid
    let id = *ctx.network.eth_addrs.get(&old)?;
    let metadata = ctx.network.lyquid_registry.get_mut(&id)?;
    if metadata.owner == owner && metadata.deploy_history.last()?.contract == old {
        metadata.deploy_history.push(DeployInfo { contract: new });
        Some(id)
    } else {
        None
    }
}

lyquid::method! {
    constructor(&mut ctx) {
        // NOTE: it is specially treated (in contract generation) that the caller of bartender's
        // contract is the contract address itself
    }

    network fn register(&mut ctx, superseded: Address) -> LyquidResult<bool> {
        let owner = ctx.origin;
        let contract = ctx.caller;
        let id = if superseded == Address::ZERO {
            // create a new lyquid
            Some(next_lyquid_id(&mut ctx, owner, contract))
        } else {
            update_eth_addr(&mut ctx, owner, superseded, contract)
        }.ok_or(LyquidError::LyquidRuntime("invalid register call".into()))?;

        lyquid::println!("register {id} (owner={owner}, contract={contract})");
        lyquid::log!(Register, &id);
        ctx.network.eth_addrs.insert(contract, id);
        Ok(true)
    }

    instance fn get_lyquid_info(&ctx, id: LyquidID) -> LyquidResult<Option<LyquidMetadataOutput>> {
        Ok(ctx.network.lyquid_registry.get(&id).map(|d| {
            LyquidMetadataOutput {
                owner: d.owner,
                deploy_history: d.deploy_history.to_vec(),
            }
        }))
    }

    instance fn get_lyquid_deployment_info(&ctx, id: LyquidID, nth: u32) -> LyquidResult<Option<DeployInfo>> {
        let nth = nth as usize;
        Ok(ctx.network.lyquid_registry.get(&id).and_then(|d| {
            if nth < d.deploy_history.len() {
                Some(d.deploy_history[nth].clone())
            } else {
                None
            }
        }))
    }

    instance fn get_last_lyquid_deployment_info(&ctx, id: LyquidID) -> LyquidResult<Option<DeployInfo>> {
        Ok(ctx.network.lyquid_registry.get(&id).and_then(|d| d.deploy_history.last()).cloned())
    }

    instance fn get_lyquid_id_by_eth_addr(&ctx, addr: Address) -> LyquidResult<Option<LyquidID>> {
        Ok(ctx.network.eth_addrs.get(&addr).map(|v| v.clone()))
    }

    instance fn get_eth_addr(&ctx, id: LyquidID, ln_image: u32) -> LyquidResult<Option<Address>> {
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

    instance fn get_lyquid_list(&ctx) -> LyquidResult<Vec<LyquidID>> {
        Ok(ctx.network.lyquid_registry.keys().cloned().collect())
    }

    instance fn eth_abi_test1(&ctx, x: U256, y: Vec<String>, z: [Vec<u64>; 4]) -> LyquidResult<U256> {
        lyquid::println!("got x = {}, y = {:?}, z = {:?} from {}", x, y, z, ctx.caller);
        Ok(x + uint!(1_U256))
    }
}
