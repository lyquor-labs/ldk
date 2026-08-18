// ---------------------------------------------------------------------------
// Market / Oracle feed types (wire → tick → point → UI)
// ---------------------------------------------------------------------------

// ---- Base (type for aliases) ----
export type NodeId = string;
export type MarketAsset = string;
export const MARKET_ASSETS = ["BTC"] as const;

export type ChainPos = {
    blockIndex: `0x${string}`;
    blockNumber: `0x${string}`;
};

// ---- Raw (API / RPC response) ----
/** Payload of a single node submission (second element of CandidateRaw tuple). */
export interface CandidateRawPayload {
    asset: MarketAsset;
    price: number;
    source?: string;
    timestamp?: number;
}

/** Single node submission in current epoch: [nodeId, payload]. */
export type CandidateRaw = [NodeId, CandidateRawPayload];

export type CandidatesRaw = CandidateRaw[];

/** Per-asset entry in get_prices result data. */
export interface GetPricesAssetDataRaw {
    price: number;
    signers?: string[];
    candidates?: CandidatesRaw;
    source?: string;
}

/** Single result item in get_prices response (one timestamp/epoch). */
export interface GetPricesResultRaw {
    id: number;
    timestamp?: number;
    chainPos?: ChainPos;
    data: Record<string, GetPricesAssetDataRaw>;
}

/** Full get_prices RPC response. */
export interface GetPricesRaw {
    results?: GetPricesResultRaw[];
}

/** Cursor metadata for incremental history reads. */
export interface PriceUpdatesRaw extends GetPricesRaw {
    oldestId?: number | null;
    headId?: number | null;
    cursorExpired?: boolean;
    cursorReset?: boolean;
}

/** Latest finalized record, optimized for the 1 Hz browser refresh path. */
export interface PriceHeadRaw {
    head: GetPricesResultRaw | null;
}

/** Derived: one element of results (alias for usage). */
export type GetPricesResultItemRaw = NonNullable<GetPricesRaw["results"]>[number];

// ---- UI / Domain (interface for extensibility) ----
export interface MarketCandidate {
    nodeId: NodeId;
    price: number;
    t?: number;
    id?: number;
    source?: string;
    chainPos?: ChainPos;
}

/** One asset snapshot within a MarketTick (all assets at one time). */
export interface MarketAssetSnapshot {
    price: number;
    low: number;
    high: number;
    candidates: MarketCandidate[];
    source?: string;
}

/** Raw tick containing all assets at one time; parsed from one wire result. */
export interface MarketTick {
    t: number;
    id: number;
    assets: Record<string, MarketAssetSnapshot>;
    timestamp?: number;
    chainPos?: ChainPos;
}

/** Single trading pair point used across UI (chart/metrics/providers). */
export interface MarketAssetPoint {
    t: number;
    id: number;
    asset: string;
    price: number;
    low: number;
    high: number;
    candidates: MarketCandidate[];
    timestamp?: number;
    chainPos?: ChainPos;
    source?: string;
}

/** Current price ticker per asset (store / price-bar). */
export interface MarketTicker {
    price: number;
    low: number;
    high: number;
    candidates: { nodeId: NodeId; price: number }[];
    t: number;
    id: number;
    timestamp?: number;
    chainPos?: { blockIndex: string; blockNumber: string };
    source?: string;
}
