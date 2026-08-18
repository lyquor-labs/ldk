import type { GetPricesRaw, PriceHeadRaw, PriceUpdatesRaw } from "@/interface"
import { priceFeedHostedUrl } from "@/constants"

export type HostedLyquidInfo = {
  lyquid_id: string
  node_base_url: string
  backend_contract: string | null
  sequence_backend: string
}

export type HostedLyquidStatus = {
  lyquid_id: string
  image_digest: string | null
  sequence_backend: string
  backend_contract: string | null
  lyquid_number: number
}

export type HostedRuntimeContext = {
  info: HostedLyquidInfo
  status: HostedLyquidStatus | null
}

export type PriceFeedConfig = {
  version: string
  assets: string[]
  sources: string[]
  committee: {
    nodeIds: string[]
    threshold: number
  }
}

async function fetchJson<T>(path: string, options: RequestInit = {}): Promise<T> {
  const url = priceFeedHostedUrl(path)
  const response = await fetch(toPriceFeedFetchUrl(url), {
    cache: "no-store",
    headers: { accept: "application/json" },
    ...options,
  })
  if (!response.ok) {
    throw new Error(`${url} returned ${response.status}`)
  }
  return response.json() as Promise<T>
}

function toPriceFeedFetchUrl(url: string): string {
  if (!import.meta.env.DEV || typeof window === "undefined" || !["localhost", "127.0.0.1", "::1"].includes(window.location.hostname)) {
    return url
  }

  return `/__price_feed_hosted__?url=${encodeURIComponent(url)}`
}

export async function loadHostedRuntimeContext(): Promise<HostedRuntimeContext> {
  const info = await fetchJson<HostedLyquidInfo>("/lyquid/info")
  const status = await fetchJson<HostedLyquidStatus>("/lyquid/statusz").catch(() => null)
  return { info, status }
}

export function loadPriceHistory(start: number, end: number): Promise<GetPricesRaw> {
  const query = new URLSearchParams({
    start: String(start),
    end: String(end),
    use_id: "false",
  })
  return fetchJson<GetPricesRaw>(`/api/prices?${query}`)
}

export function loadPriceHead(signal?: AbortSignal): Promise<PriceHeadRaw> {
  return fetchJson<PriceHeadRaw>("/api/price-head", {
    // Poll cadence and overlap control live in the caller. Every tick must
    // reach the endpoint instead of reusing a browser cache entry.
    cache: "no-store",
    signal,
  })
}

export function loadPriceUpdates(after: number, signal?: AbortSignal): Promise<PriceUpdatesRaw> {
  const query = new URLSearchParams({ after: String(after) })
  return fetchJson<PriceUpdatesRaw>(`/api/price-updates?${query}`, { signal })
}

export function loadPriceFeedConfig(): Promise<PriceFeedConfig> {
  return fetchJson<PriceFeedConfig>("/api/config")
}
