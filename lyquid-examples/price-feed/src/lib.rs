//! Oracle-backed price-feed Lyquid.
//!
//! Nodes join the `price_feed` oracle topic through a network method, then instance methods choose
//! a price source, fetch Binance, Coinbase, or mock ticker data through the host HTTP API, cache
//! per-instance observations, and submit proposals to the oracle two-phase group. Certified
//! network callbacks store finalized price records with candidate data, source, and signer lists.

use lyquid::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

const BINANCE_API_BASE_URL: &str = "https://data-api.binance.vision";
const COINBASE_API_BASE_URL: &str = "https://api.exchange.coinbase.com";
const ASSETS: [(&str, &str, &str); 4] = [
    ("BTC", "BTCUSDT", "BTC-USDT"),
    ("ETH", "ETHUSDT", "ETH-USDT"),
    ("SOL", "SOLUSDT", "SOL-USDT"),
    ("AVAX", "AVAXUSDT", "AVAX-USDT"),
];

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum PriceSource {
    #[default]
    Binance,
    Coinbase,
    Mock,
}

impl PriceSource {
    fn from_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "binance" => Some(Self::Binance),
            "coinbase" => Some(Self::Coinbase),
            "mock" => Some(Self::Mock),
            _ => None,
        }
    }
}

fn fetch_price(source: PriceSource, symbol: &str, mock_base_url: Option<&str>) -> LyquidResult<u64> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct BinanceTicker {
        bid_price: String,
        ask_price: String,
    }

    #[derive(Deserialize)]
    struct CoinbaseTicker {
        bid: String,
        ask: String,
    }

    use lyquid::http::{Method, Request};
    let url = match source {
        PriceSource::Binance => format!("{BINANCE_API_BASE_URL}/api/v3/ticker/bookTicker?symbol={symbol}"),
        PriceSource::Coinbase => format!("{COINBASE_API_BASE_URL}/products/{symbol}/ticker"),
        PriceSource::Mock => {
            let base = mock_base_url.unwrap_or_default();
            format!("{base}/api/v3/ticker/bookTicker?symbol={symbol}")
        }
    };
    let req = Request {
        method: Method::Get,
        url,
        headers: vec![],
        body: None,
    };

    let resp = lyquor_api::http_request(req, Some(http::RequestOptions { timeout_ms: Some(1000) }))?;

    if resp.status != 200 {
        return Err(LyquidError::LyquorRuntime(format!(
            "HTTP Error for {}: {}",
            symbol, resp.status
        )));
    }

    let (bid_raw, ask_raw) = match source {
        PriceSource::Binance | PriceSource::Mock => {
            let ticker: BinanceTicker = serde_json::from_slice(&resp.body)
                .map_err(|e| LyquidError::LyquorRuntime(format!("JSON Parse Error: {}", e)))?;
            (ticker.bid_price, ticker.ask_price)
        }
        PriceSource::Coinbase => {
            let ticker: CoinbaseTicker = serde_json::from_slice(&resp.body)
                .map_err(|e| LyquidError::LyquorRuntime(format!("JSON Parse Error: {}", e)))?;
            (ticker.bid, ticker.ask)
        }
    };

    let bid: f64 = bid_raw
        .parse()
        .map_err(|_| LyquidError::LyquorRuntime("Invalid bid price".into()))?;
    let ask: f64 = ask_raw
        .parse()
        .map_err(|_| LyquidError::LyquorRuntime("Invalid ask price".into()))?;
    let mid = (bid + ask) / 2.0;

    // Store with 8 decimals (price * 1e8)
    Ok((mid * 100_000_000.0) as u64)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PriceData {
    asset: String,
    price: u64,
    source: PriceSource,
    timestamp: u64,
}

/// Price bundle proposed by a node.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PriceProposal(Vec<PriceData>);

/// The finalized price record of an asset.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PriceRecord {
    price: u64,                           // Finalized price.
    candidates: Vec<(NodeID, PriceData)>, // All price candidates for autopsy/governance.
    source: PriceSource,                  // Source of the finalized price candidate.
    signers: Vec<NodeID>,                 // Oracle signers that certified this finalized update.
}

/// On-chain price update data.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
struct PriceUpdate(HashMap<String, PriceRecord>);

state! {
    network oracle price_feed;
    network prices: HashMap<String, PriceRecord> = new_hashmap(); // "On-chain" current prices.
    instance local_price_source: PriceSource = PriceSource::Binance;
    // Per-node latest known prices by asset.
    instance local_price: HashMap<String, u64> = new_hashmap();
    // Per-node local cache of `prices` network variable history
    // (a rolling buffer of (id, timestamp, chain_pos, update)).
    instance price_history_cache: VecDeque<(u64, u64, ChainPos, PriceUpdate)> = VecDeque::new();
    instance price_history_id: u64 = 0;

    // Used for mock tests.
    instance mock_api_base_url: String = String::new();
}

// Invoked when a node joins.
#[method::network(export = eth, group = node)]
fn join(ctx: &mut _, id: NodeID) -> LyquidResult<bool> {
    let o = ctx.network.price_feed.clone();
    let target = OracleTarget {
        seq_id: lyquor_api::sequence_backend_id()?,
        target: OracleServiceTarget::LVM(ctx.lyquid_id),
    };
    o.add_node(&mut ctx, target, id);
    let threshold = (o.config_staging(&ctx, target).committee.len() / 2 + 1) as u16;
    o.set_threshold(&mut ctx, target, threshold); // Update the threshold to majority.
    Ok(true)
}

#[method::instance(export = eth)]
fn set_price_source(ctx: &mut _, source: String) -> LyquidResult<bool> {
    let source = PriceSource::from_str(&source).ok_or(LyquidError::LyquorRuntime(
        "source must be \"binance\", \"coinbase\", or \"mock\"".into(),
    ))?;
    *ctx.instance.local_price_source.write() = source;
    lyquid::println!("price-feed: local fetch source set to {:?}", source);
    Ok(true)
}

// Customized off-chain proposal and aggregation logic that is automatically triggered as part of
// `propose_and_certify` in `report_prices()`.
//
// `price_feed` in the group prefix matches the network state variable: `price_feed`.
#[method::instance(group = oracle::two_phase::price_feed)]
fn propose(ctx: &mut _, _avg_num: u16, _target: OracleTarget) -> LyquidResult<PriceProposal> {
    let source = *ctx.instance.local_price_source.read();
    let mock_base_url = ctx.instance.mock_api_base_url.read().clone();
    let mut local_price = ctx.instance.local_price.write();

    let mut prices = Vec::with_capacity(ASSETS.len());
    for &(name, binance_sym, coinbase_sym) in &ASSETS {
        let symbol = match source {
            PriceSource::Binance => binance_sym,
            PriceSource::Coinbase => coinbase_sym,
            PriceSource::Mock => binance_sym,
        };
        let mock_url = if matches!(source, PriceSource::Mock) {
            Some(mock_base_url.as_str())
        } else {
            None
        };

        let price = match fetch_price(source, symbol, mock_url) {
            Ok(price) => {
                local_price.insert(name.to_string(), price);
                lyquid::println!("fetch_price: {:?} {} = {:?}.", source, symbol, price);
                price
            }
            Err(err) => {
                let cached = local_price.get(name).copied().unwrap_or(0);
                lyquid::println!(
                    "fetch_price: {:?} {} failed ({:?}); using last known (or 0 if unavailable) {}.",
                    source,
                    symbol,
                    err,
                    cached
                );
                cached
            }
        };
        prices.push(PriceData {
            asset: name.to_string(),
            price,
            source,
            timestamp: lyquor_api::systime()?,
        });
    }
    lyquid::println!("propose: prices = {:?}", prices);
    Ok(PriceProposal(prices))
}
//
#[method::instance(group = oracle::two_phase::price_feed)]
fn aggregate(ctx: &_) -> LyquidResult<Option<CertifiedCallParams>> {
    let init = decode_by_fields!(ctx.init, avg_num: u16, target: OracleTarget)
        .ok_or(LyquidError::LyquorRuntime("Failed to decode init params".into()))?;
    if init.target.seq_id != lyquor_api::sequence_backend_id()? {
        return Ok(None)
    }

    // Not enough of price candidates.
    if ctx.inputs.len() < init.avg_num as usize {
        return Ok(None);
    }

    // Collect all prices by asset.
    let mut all_prices: HashMap<String, Vec<(NodeID, PriceData)>> = new_hashmap();
    let mut full_proposals = 0usize;
    for i in ctx.inputs {
        if let Some(prices) = lyquor_primitives::decode_object::<PriceProposal>(&i.input) {
            if prices.0.len() != ASSETS.len() {
                continue;
            }
            full_proposals += 1;
            for price in prices.0 {
                all_prices.entry(price.asset.clone()).or_default().push((i.from, price));
            }
        }
    }

    if full_proposals < init.avg_num as usize {
        return Ok(None);
    }

    lyquid::println!("aggregate: all_prices = {:?}", all_prices);

    let mut update = new_hashmap();
    for &(asset, _, _) in &ASSETS {
        let mut candidates = match all_prices.remove(asset) {
            Some(c) => c,
            None => return Ok(None),
        };
        if candidates.len() < init.avg_num as usize {
            return Ok(None);
        }
        // Sort by price to find median
        candidates.sort_by_key(|(_, data)| data.price);
        let median_idx = candidates.len() / 2;
        let price = candidates[median_idx].1.price;
        let source = candidates[median_idx].1.source;
        update.insert(
            asset.to_string(),
            PriceRecord {
                price,
                candidates,
                source,
                signers: Vec::new(),
            },
        );
    }

    let method = "update".into();
    let input = encode_by_fields!(new_prices: PriceUpdate = PriceUpdate(update)).into();

    Ok(Some(CertifiedCallParams {
        origin: Address::ZERO,
        method,
        input,
        target: init.target, // LVM (i.e., `update` network fn in this Lyquid code).
    }))
}
//-- end --

// Mantain a per-node, local cache of the price history, following the network updates.
#[method::instance]
fn update_history(ctx: &mut _) -> LyquidResult<()> {
    // Max historical updates to keep.
    const HISTORY_MAX: usize = 600;

    let network_prices = &ctx.network.prices;
    let mut history = ctx.instance.price_history_cache.write();
    let mut id = ctx.instance.price_history_id.write();
    *id += 1;

    let update = network_prices
        .iter()
        .map(|(name, record)| (name.clone(), record.clone()))
        .collect();

    history.push_back((
        *id,
        lyquor_api::systime()?,
        lyquor_api::chain_pos()?,
        PriceUpdate(update),
    ));
    if history.len() > HISTORY_MAX {
        history.pop_front();
    }
    Ok(())
}

// Update the price (on chain). This will be invoked once the certified call payload returned by
// `propose_and_certify` gets submitted to be sequenced by the chain.
#[method::network(group = oracle::certified::price_feed::two_phase)]
fn update(ctx: &mut _, new_prices: PriceUpdate) -> LyquidResult<bool> {
    let signer_ids = ctx.cert.signers.clone();
    let signers: Vec<NodeID> = signer_ids
        .into_iter()
        .filter_map(|signer_id| ctx.signer_node_id(signer_id as u64))
        .collect();

    let prices = &mut ctx.network.prices;
    prices.clear();
    for (asset, mut record) in new_prices.0 {
        record.signers = signers.clone();
        prices.insert(asset, record);
    }
    lyquid::println!("On-chain prices are updated to: {:?}", prices);
    trigger!(update_history(), TriggerMode::Commit);
    Ok(true)
}

// Query historical prices.
#[method::instance(export = eth)]
fn get_prices(ctx: &_, start: u64, end: u64, use_id: bool) -> LyquidResult<String> {
    let history = ctx.instance.price_history_cache.read();
    let n = history.len();

    let (mut s, mut e) = if use_id {
        let f = history.front().map(|(id, _, _, _)| *id).unwrap_or(0);
        (start.saturating_sub(f) as usize, end.saturating_sub(f) as usize)
    } else {
        (n.saturating_sub(end as usize), n.saturating_sub(start as usize))
    };
    s = s.min(n);
    e = e.clamp(s, n);

    let results: Vec<_> = history
        .range(s..e)
        .map(|(id, timestamp, chain_pos, data)| {
            serde_json::json!({
                "id": id,
                "timestamp": timestamp,
                "chainPos": chain_pos,
                "data": data
            })
        })
        .collect();

    serde_json::to_string(&serde_json::json!({ "results": results }))
        .map_err(|e| LyquidError::LyquorRuntime(format!("JSON Serialization Error: {}", e)))
}

// When invoked, this node will initiaite the reporting of prices to update the on-chain state.
#[method::instance(export = eth)]
fn report_prices(ctx: &mut _) -> LyquidResult<bool> {
    // Use off-chain instance functions to prepare a certified call of `update()` network function.
    let target = OracleTarget {
        target: OracleServiceTarget::LVM(ctx.lyquid_id),
        seq_id: lyquor_api::sequence_backend_id()?,
    };
    let o = ctx.network.price_feed.clone();
    let call = o.propose_and_certify(
        &mut ctx,
        target,
        lyquor_primitives::encode_by_fields!(avg_num: u16 = 3, target: OracleTarget = target).into(),
        None,
        None,
    )?;

    lyquid::println!("report_prices: call = {:?}", call);
    if let Some(call) = call {
        let _ = submit_certified_call!(call)?; // Submit price update to chain.
        Ok(true)
    } else {
        Ok(false)
    }
}

// Start automatic price reporting with the specified interval.
#[method::instance(export = eth)]
fn start_reporting(ctx: &mut _, interval_ms: u64) -> LyquidResult<bool> {
    trigger!(report_prices(), TriggerMode::Recurrent(interval_ms));
    lyquid::println!("Started price reporting with interval {}ms", interval_ms);
    Ok(true)
}

// Stop automatic price reporting.
#[method::instance(export = eth)]
fn stop_reporting(ctx: &mut _) -> LyquidResult<bool> {
    trigger!(report_prices(), TriggerMode::Stop);
    lyquid::println!("Stopped price reporting");
    Ok(true)
}

#[method::instance(export = eth)]
fn get_node_ids(ctx: &_) -> LyquidResult<Vec<String>> {
    let target = OracleTarget {
        seq_id: lyquor_api::sequence_backend_id()?,
        target: OracleServiceTarget::LVM(ctx.lyquid_id),
    };
    Ok(ctx
        .network
        .price_feed
        .config_current(&ctx, target)
        .committee
        .keys()
        .into_iter()
        .map(|node| node.to_string())
        .collect())
}

// Used for mock tests.
#[method::instance(export = eth)]
fn set_mock_api_base_url(ctx: &mut _, base_url: String) -> LyquidResult<bool> {
    fn normalize_base_url(base_url: &str) -> LyquidResult<String> {
        let normalized = base_url.trim().trim_end_matches('/').to_string();
        if normalized.is_empty() {
            return Err(LyquidError::LyquorRuntime("mock API base URL cannot be empty".into()));
        }
        Ok(normalized)
    }

    let base_url = normalize_base_url(&base_url)?;
    *ctx.instance.mock_api_base_url.write() = base_url.clone();
    lyquid::println!("price-feed: local mock API base URL set to {}", base_url);
    Ok(true)
}
