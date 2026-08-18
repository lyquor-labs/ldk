//! Oracle-backed price-feed Lyquid.
//!
//! The initializer configures the `price_feed` oracle committee, then instance methods choose a
//! price source, fetch Binance or Coinbase ticker data through the host HTTP API, cache per-instance
//! observations, and submit proposals to the oracle two-phase group. Certified network callbacks
//! store finalized price records with candidate data, source, and signer lists.

use lyquid::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

const BINANCE_API_BASE_URL: &str = "https://data-api.binance.vision";
const COINBASE_API_BASE_URL: &str = "https://api.exchange.coinbase.com";
// Keep direct browser navigation working on nodes that have not yet rolled out
// the hosting layer's static SPA fallback.
const SPA_INDEX_HTML: &[u8] = include_bytes!("../assets/index.html");
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
}

impl PriceSource {
    const ALL: [Self; 2] = [Self::Binance, Self::Coinbase];

    fn as_str(self) -> &'static str {
        match self {
            Self::Binance => "binance",
            Self::Coinbase => "coinbase",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "binance" => Some(Self::Binance),
            "coinbase" => Some(Self::Coinbase),
            _ => None,
        }
    }
}

fn fetch_price(source: PriceSource, symbol: &str) -> LyquidResult<u64> {
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

    use lyquid::http::{Header, Method, Request};
    let url = match source {
        PriceSource::Binance => format!("{BINANCE_API_BASE_URL}/api/v3/ticker/bookTicker?symbol={symbol}"),
        PriceSource::Coinbase => format!("{COINBASE_API_BASE_URL}/products/{symbol}/ticker"),
    };
    let req = Request {
        method: Method::Get,
        url,
        headers: vec![
            Header {
                name: "accept".into(),
                value: b"application/json".to_vec(),
            },
            Header {
                name: "user-agent".into(),
                value: concat!(
                    "Mozilla/5.0 (X11; Linux x86_64) ",
                    "AppleWebKit/537.36 (KHTML, like Gecko) ",
                    "Chrome/120.0.0.0 Safari/537.36"
                )
                .as_bytes()
                .to_vec(),
            },
        ],
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
        PriceSource::Binance => {
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
    network initializer: Address = Address::ZERO;
    network oracle price_feed;
    network prices: HashMap<String, PriceRecord> = new_hashmap(); // "On-chain" current prices.
    instance local_price_source: PriceSource = PriceSource::Binance;
    // Scheduler state is local to the node instance that owns the trigger.
    instance reporting_enabled: bool = false;
    instance reporting_interval_ms: u64 = 0;
    // Per-node latest known prices by asset.
    instance local_price: HashMap<String, u64> = new_hashmap();
    // Per-node local cache of `prices` network variable history
    // (a rolling buffer of (id, timestamp, chain_pos, update)).
    instance price_history_cache: VecDeque<(u64, u64, ChainPos, PriceUpdate)> = VecDeque::new();
    instance price_history_id: u64 = 0;
}

#[method::network(export = eth)]
fn constructor(ctx: &mut _) {
    *ctx.network.initializer = ctx.caller;
}

fn spa_response() -> http::Response {
    http::Response {
        status: 200,
        headers: vec![
            http::Header {
                name: "content-type".into(),
                value: b"text/html; charset=utf-8".to_vec(),
            },
            http::Header {
                name: "cache-control".into(),
                value: b"no-cache".to_vec(),
            },
        ],
        body: SPA_INDEX_HTML.to_vec(),
    }
}

// The hosted node serves HTTP exports before static assets. These routes keep
// deep links working until every hosted node provides static SPA fallback.
#[method::instance(export = http, method = "GET", path_prefix = "/feeds")]
fn feeds_spa(_ctx: &_, _req: http::Request) -> LyquidResult<http::Response> {
    Ok(spa_response())
}

#[method::instance(export = http, method = "GET", path_prefix = "/explorer")]
fn explorer_spa(_ctx: &_, _req: http::Request) -> LyquidResult<http::Response> {
    Ok(spa_response())
}

#[method::instance(export = http, method = "GET", path_prefix = "/setup")]
fn setup_spa(_ctx: &_, _req: http::Request) -> LyquidResult<http::Response> {
    Ok(spa_response())
}

#[method::network(export = eth)]
fn configure_committee(ctx: &mut _, node_ids: Vec<NodeID>) -> LyquidResult<bool> {
    if ctx.caller != *ctx.network.initializer {
        return Err(LyquidError::LyquorRuntime(
            "only initializer can configure committee".into(),
        ));
    }
    if node_ids.is_empty() {
        return Err(LyquidError::LyquorRuntime("committee cannot be empty".into()));
    }

    let target = OracleTarget {
        seq_id: lyquor_api::sequence_backend_id()?,
        target: OracleServiceTarget::LVM(ctx.lyquid_id),
    };
    let threshold = u16::try_from(node_ids.len() / 2 + 1)
        .map_err(|_| LyquidError::LyquorRuntime("price-feed committee threshold overflow".into()))?;

    if !ctx
        .network
        .price_feed
        .clone()
        .initialize(&mut ctx, target, node_ids, threshold)
    {
        return Err(LyquidError::LyquorRuntime(
            "price-feed oracle committee initialization failed".into(),
        ));
    }

    Ok(true)
}

#[method::instance(export = eth)]
fn set_price_source(ctx: &mut _, source: String) -> LyquidResult<bool> {
    let source = PriceSource::from_str(&source).ok_or(LyquidError::LyquorRuntime(
        "source must be \"binance\" or \"coinbase\"".into(),
    ))?;
    *ctx.instance.local_price_source.write() = source;
    lyquid::println!("price-feed: local fetch source set to {:?}", source);
    Ok(true)
}

// Returns this node instance's configured market-data source.
#[method::instance(export = eth)]
fn get_price_source(ctx: &_) -> LyquidResult<String> {
    Ok(ctx.instance.local_price_source.read().as_str().to_string())
}

// Customized off-chain proposal and aggregation logic that is automatically triggered as part of
// `propose_and_certify` in `report_prices()`.
//
// `price_feed` in the group prefix matches the network state variable: `price_feed`.
#[method::instance(group = oracle::two_phase::price_feed)]
fn propose(ctx: &mut _, _avg_num: u16, _target: OracleTarget) -> LyquidResult<PriceProposal> {
    let source = *ctx.instance.local_price_source.read();
    let mut local_price = ctx.instance.local_price.write();

    let mut prices = Vec::with_capacity(ASSETS.len());
    for &(name, binance_sym, coinbase_sym) in &ASSETS {
        let symbol = match source {
            PriceSource::Binance => binance_sym,
            PriceSource::Coinbase => coinbase_sym,
        };

        let price = match fetch_price(source, symbol) {
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
    if interval_ms == 0 {
        return Err(LyquidError::LyquorRuntime(
            "reporting interval must be greater than zero".into(),
        ));
    }
    trigger!(report_prices(), TriggerMode::Recurrent(interval_ms));
    *ctx.instance.reporting_enabled.write() = true;
    *ctx.instance.reporting_interval_ms.write() = interval_ms;
    lyquid::println!("Started price reporting with interval {}ms", interval_ms);
    Ok(true)
}

// Stop automatic price reporting.
#[method::instance(export = eth)]
fn stop_reporting(ctx: &mut _) -> LyquidResult<bool> {
    trigger!(report_prices(), TriggerMode::Stop);
    *ctx.instance.reporting_enabled.write() = false;
    *ctx.instance.reporting_interval_ms.write() = 0;
    lyquid::println!("Stopped price reporting");
    Ok(true)
}

// Returns this node instance's reporting scheduler state.
#[method::instance(export = eth)]
fn get_reporting_status(ctx: &_) -> LyquidResult<(bool, u64)> {
    Ok((
        *ctx.instance.reporting_enabled.read(),
        *ctx.instance.reporting_interval_ms.read(),
    ))
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

#[method::instance(export = http, method = "GET", path_prefix = "/api/prices")]
fn http_prices(ctx: &_, req: http::Request) -> LyquidResult<http::Response> {
    let query = request_query(&req.url);
    let start = query_u64(query, "start")?.unwrap_or(0);
    let end = query_u64(query, "end")?.unwrap_or(1);
    let use_id = query_bool(query, "use_id")?.unwrap_or(false);

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
    let body = serde_json::to_vec(&serde_json::json!({ "results": results }))
        .map_err(|err| LyquidError::LyquorRuntime(format!("JSON Serialization Error: {err}")))?;

    Ok(json_response(200, body))
}

// Lightweight, cacheable latest-price endpoint for the browser's hot path.
// Historical data remains available through `/api/prices`; clients only need to
// request that heavier route after this endpoint reports a newer `id`.
#[method::instance(export = http, method = "GET", path_prefix = "/api/price-head")]
fn http_price_head(ctx: &_, _req: http::Request) -> LyquidResult<http::Response> {
    let history = ctx.instance.price_history_cache.read();
    let head = history.back().map(|(id, timestamp, chain_pos, data)| {
        serde_json::json!({
            "id": id,
            "timestamp": timestamp,
            "chainPos": chain_pos,
            "data": data,
        })
    });
    let body = serde_json::to_vec(&serde_json::json!({ "head": head }))
        .map_err(|err| LyquidError::LyquorRuntime(format!("price-head JSON serialization failed: {err}")))?;

    Ok(json_response_with_headers(
        200,
        body,
        vec![http::Header {
            name: "cache-control".into(),
            // The frontend controls cadence through its single-flight loop; never
            // satisfy a tick from an HTTP cache.
            value: b"no-store".to_vec(),
        }],
    ))
}

// Cursor-based recovery path for clients that observe a newer price-head id.
// This preserves every finalized chart point after a cache hit or a background-tab pause.
#[method::instance(export = http, method = "GET", path_prefix = "/api/price-updates")]
fn http_price_updates(ctx: &_, req: http::Request) -> LyquidResult<http::Response> {
    let after = query_u64(request_query(&req.url), "after")?.unwrap_or(0);
    let history = ctx.instance.price_history_cache.read();
    let oldest_id = history.front().map(|(id, _, _, _)| *id);
    let head_id = history.back().map(|(id, _, _, _)| *id);
    let cursor_expired = after > 0 &&
        oldest_id
            .map(|oldest| after.saturating_add(1) < oldest)
            .unwrap_or(false);
    let cursor_reset = after > 0 && head_id.map(|head| after > head).unwrap_or(false);
    let results: Vec<_> = history
        .iter()
        .filter(|(id, _, _, _)| *id > after)
        .map(|(id, timestamp, chain_pos, data)| {
            serde_json::json!({
                "id": id,
                "timestamp": timestamp,
                "chainPos": chain_pos,
                "data": data,
            })
        })
        .collect();
    let body = serde_json::to_vec(&serde_json::json!({
        "results": results,
        "oldestId": oldest_id,
        "headId": head_id,
        "cursorExpired": cursor_expired,
        "cursorReset": cursor_reset,
    }))
    .map_err(|err| LyquidError::LyquorRuntime(format!("price-updates JSON serialization failed: {err}")))?;
    Ok(json_response(200, body))
}

#[method::instance(export = http, method = "GET", path_prefix = "/api/committee")]
fn http_committee(ctx: &_, _req: http::Request) -> LyquidResult<http::Response> {
    let target = OracleTarget {
        seq_id: lyquor_api::sequence_backend_id()?,
        target: OracleServiceTarget::LVM(ctx.lyquid_id),
    };
    let node_ids = ctx
        .network
        .price_feed
        .config_current(&ctx, target)
        .committee
        .keys()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let body = serde_json::to_vec(&serde_json::json!({ "nodeIds": node_ids }))
        .map_err(|err| LyquidError::LyquorRuntime(format!("committee JSON serialization failed: {err}")))?;

    Ok(json_response(200, body))
}

#[method::instance(export = http, method = "GET", path_prefix = "/api/config")]
fn http_config(ctx: &_, _req: http::Request) -> LyquidResult<http::Response> {
    let target = OracleTarget {
        seq_id: lyquor_api::sequence_backend_id()?,
        target: OracleServiceTarget::LVM(ctx.lyquid_id),
    };
    let config = ctx.network.price_feed.config_current(&ctx, target);
    let node_ids = config.committee.keys().map(ToString::to_string).collect::<Vec<_>>();
    let body = serde_json::to_vec(&serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "assets": ASSETS.iter().map(|(asset, _, _)| *asset).collect::<Vec<_>>(),
        "sources": PriceSource::ALL.into_iter().map(PriceSource::as_str).collect::<Vec<_>>(),
        "committee": {
            "nodeIds": node_ids,
            "threshold": config.threshold,
        },
    }))
    .map_err(|err| LyquidError::LyquorRuntime(format!("config JSON serialization failed: {err}")))?;

    Ok(json_response(200, body))
}

// Optional public display metadata. Consumers must fall back to the Lyquid ID
// when this endpoint is unavailable or does not provide a usable name.
#[method::instance(export = http, method = "GET", path_prefix = "/api/info")]
fn http_info(_ctx: &_, _req: http::Request) -> LyquidResult<http::Response> {
    let body = serde_json::to_vec(&serde_json::json!({ "name": "Price Feed" }))
        .map_err(|err| LyquidError::LyquorRuntime(format!("info JSON serialization failed: {err}")))?;

    Ok(json_response_with_headers(
        200,
        body,
        vec![http::Header {
            name: "access-control-allow-origin".into(),
            value: b"*".to_vec(),
        }],
    ))
}

fn request_query(url: &str) -> &str {
    let path_and_query = if let Some((_, rest)) = url.split_once("://") {
        rest.find('/').map_or("", |index| &rest[index..])
    } else {
        url
    };
    path_and_query.split_once('?').map_or("", |(_, query)| query)
}

fn query_value<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|part| {
        let (candidate, value) = part.split_once('=').unwrap_or((part, ""));
        (candidate == key).then_some(value)
    })
}

fn query_u64(query: &str, key: &str) -> LyquidResult<Option<u64>> {
    query_value(query, key)
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| LyquidError::LyquorRuntime(format!("{key} must be an unsigned integer")))
        })
        .transpose()
}

fn query_bool(query: &str, key: &str) -> LyquidResult<Option<bool>> {
    query_value(query, key)
        .map(|value| match value {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(LyquidError::LyquorRuntime(format!("{key} must be true or false"))),
        })
        .transpose()
}

fn json_response(status: u16, body: Vec<u8>) -> http::Response {
    json_response_with_headers(
        status,
        body,
        vec![http::Header {
            name: "cache-control".into(),
            value: b"no-cache".to_vec(),
        }],
    )
}

fn json_response_with_headers(status: u16, body: Vec<u8>, mut headers: Vec<http::Header>) -> http::Response {
    headers.insert(
        0,
        http::Header {
            name: "content-type".into(),
            value: b"application/json; charset=utf-8".to_vec(),
        },
    );
    http::Response { status, headers, body }
}
