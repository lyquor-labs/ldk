import type {
  GetPricesResultRaw,
  MarketAssetPoint,
  MarketAssetSnapshot,
  MarketCandidate,
  MarketTick,
} from "@/interface"
import {
  loadHostedRuntimeContext,
  loadPriceFeedConfig,
  loadPriceHead,
  loadPriceHistory,
  loadPriceUpdates,
  type HostedRuntimeContext,
  type PriceFeedConfig,
} from "@/lib/price-feed-api"
import { useMarketStore, type MarketTicker } from "@/stores/market-store"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"

const PRICE_SCALE = 100_000_000
const OBSERVED_INTERVAL_SAMPLE_SIZE = 10

class FixedRingBuffer<T> {
  private values: (T | undefined)[]
  private head = 0
  private size = 0

  constructor(private capacity: number) {
    this.capacity = Math.max(1, capacity)
    this.values = new Array(this.capacity)
  }

  setCapacity(capacity: number) {
    const nextCapacity = Math.max(1, capacity)
    if (nextCapacity === this.capacity) return
    const retained = this.toArray().slice(-nextCapacity)
    this.capacity = nextCapacity
    this.values = new Array(nextCapacity)
    this.head = 0
    this.size = 0
    this.pushMany(retained)
  }

  replace(values: T[]) {
    this.values = new Array(this.capacity)
    this.head = 0
    this.size = 0
    this.pushMany(values.slice(-this.capacity))
  }

  pushMany(values: T[]) {
    for (const value of values) {
      this.values[(this.head + this.size) % this.capacity] = value
      if (this.size < this.capacity) this.size += 1
      else this.head = (this.head + 1) % this.capacity
    }
  }

  toArray(): T[] {
    return Array.from({ length: this.size }, (_, index) => this.values[(this.head + index) % this.capacity] as T)
  }
}

function buildPoint(record: GetPricesResultRaw): MarketTick | null {
  const timestamp = Number(record.timestamp)
  if (!Number.isFinite(timestamp) || timestamp <= 0) return null

  const assets: Record<string, MarketAssetSnapshot> = {}
  for (const [asset, value] of Object.entries(record.data ?? {})) {
    const rawCandidates = value.candidates ?? []
    const price = Number(value.price) / PRICE_SCALE
    // Failed providers report zero. Keep those candidates visible for
    // operators, but do not let them expand a price range down to zero.
    const prices = rawCandidates
      .map(([, payload]) => Number(payload.price) / PRICE_SCALE)
      .filter((candidatePrice) => Number.isFinite(candidatePrice) && candidatePrice > 0)
    if (!prices.length && Number.isFinite(price) && price > 0) prices.push(price)
    const candidates: MarketCandidate[] = rawCandidates.map(([nodeId, payload]) => ({
      nodeId,
      price: Number(payload.price) / PRICE_SCALE,
      t: payload.timestamp,
      id: record.id,
      source: payload.source,
      chainPos: record.chainPos,
    }))
    assets[asset] = {
      price,
      low: Math.min(...prices),
      high: Math.max(...prices),
      candidates,
      source: value.source,
    }
  }

  return { t: timestamp, id: Number(record.id), assets, timestamp, chainPos: record.chainPos }
}

function pickAssetPoint(tick: MarketTick, asset: string): MarketAssetPoint | null {
  const snapshot = tick.assets[asset]
  if (!snapshot) return null
  return {
    t: tick.t,
    id: tick.id,
    asset,
    price: snapshot.price,
    low: snapshot.low,
    high: snapshot.high,
    candidates: snapshot.candidates,
    timestamp: tick.timestamp,
    chainPos: tick.chainPos,
    source: snapshot.source,
  }
}

function sortTicks(ticks: MarketTick[]) {
  return [...ticks].sort((a, b) => a.id - b.id || a.t - b.t)
}

function median(values: number[]) {
  if (!values.length) return null
  const sorted = [...values].sort((a, b) => a - b)
  const middle = Math.floor(sorted.length / 2)
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2
}

export function useMarketSentiment() {
  const { selectedAsset, pollIntervalMs, historyCount, maxTickSizeReserveLimit, setAssets, setTickers } = useMarketStore()
  const [ticks, setTicks] = useState<MarketTick[]>([])
  const [nodeIds, setNodeIds] = useState<string[]>([])
  const [config, setConfig] = useState<PriceFeedConfig | null>(null)
  const [runtime, setRuntime] = useState<HostedRuntimeContext | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isHistoryReady, setIsHistoryReady] = useState(false)
  const [error, setError] = useState<Error | null>(null)
  const lastSeenId = useRef(0)
  const tickBuffer = useRef(new FixedRingBuffer<MarketTick>(maxTickSizeReserveLimit))
  const refreshInFlight = useRef<Promise<void> | null>(null)

  const refreshHistory = useCallback(async () => {
    if (refreshInFlight.current) return refreshInFlight.current
    const refresh = (async () => {
      setIsLoading(true)
      setIsHistoryReady(false)
      try {
        const history = await loadPriceHistory(0, historyCount)
        tickBuffer.current.setCapacity(maxTickSizeReserveLimit)
        const nextTicks = sortTicks((history.results ?? []).map(buildPoint).filter((tick): tick is MarketTick => tick !== null))
        tickBuffer.current.replace(nextTicks)
        const snapshot = tickBuffer.current.toArray()
        const latest = snapshot.at(-1)
        lastSeenId.current = latest?.id ?? 0
        setTicks(snapshot)
        setAssets(Object.keys(latest?.assets ?? {}))
        setError(null)
      } catch (cause) {
        setError(cause instanceof Error ? cause : new Error("Unable to load Price Feed"))
      } finally {
        setIsLoading(false)
        setIsHistoryReady(true)
      }
    })()
    refreshInFlight.current = refresh
    try {
      await refresh
    } finally {
      refreshInFlight.current = null
    }
  }, [historyCount, maxTickSizeReserveLimit, setAssets])

  useEffect(() => { void refreshHistory() }, [refreshHistory])

  useEffect(() => {
    let cancelled = false

    const refreshMetadata = async () => {
      const [configResult, runtimeResult] = await Promise.allSettled([
        loadPriceFeedConfig(),
        loadHostedRuntimeContext(),
      ])
      if (cancelled) return
      if (configResult.status === "fulfilled") {
        setConfig(configResult.value)
        setNodeIds(configResult.value.committee.nodeIds)
      }
      if (runtimeResult.status === "fulfilled") setRuntime(runtimeResult.value)
    }

    void refreshMetadata()
    const timer = window.setInterval(() => { void refreshMetadata() }, 15_000)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [])

  useEffect(() => {
    if (!isHistoryReady) return
    let cancelled = false
    let timer: number | undefined
    let controller: AbortController | undefined

    const poll = async () => {
      const startedAt = Date.now()
      controller = new AbortController()
      try {
        const { head } = await loadPriceHead(controller.signal)
        if (!head || cancelled) return
        setError(null)
        const headId = Number(head.id)
        if (headId < lastSeenId.current) {
          await refreshHistory()
          return
        }
        if (headId <= lastSeenId.current) return

        const updates = await loadPriceUpdates(lastSeenId.current, controller.signal)
        if (cancelled) return
        if (updates.cursorExpired || updates.cursorReset || (updates.oldestId != null && updates.oldestId > lastSeenId.current + 1)) {
          await refreshHistory()
          return
        }

        const batch = sortTicks((updates.results ?? []).map(buildPoint).filter((tick): tick is MarketTick => tick !== null))
        if (!batch.length) throw new Error("Price Feed returned an update without a valid server timestamp")
        if (batch[0].id !== lastSeenId.current + 1) {
          await refreshHistory()
          return
        }

        const existing = new Map(tickBuffer.current.toArray().map((tick) => [tick.id, tick]))
        if (batch.some((tick) => existing.has(tick.id) && existing.get(tick.id)?.t !== tick.t)) {
          await refreshHistory()
          return
        }
        const unseen = batch.filter((tick) => !existing.has(tick.id))
        if (!unseen.length) return

        tickBuffer.current.setCapacity(maxTickSizeReserveLimit)
        tickBuffer.current.pushMany(unseen)
        const snapshot = tickBuffer.current.toArray()
        const latest = snapshot.at(-1)
        lastSeenId.current = latest?.id ?? lastSeenId.current
        setTicks(snapshot)
        setAssets(Object.keys(latest?.assets ?? {}))
      } catch (cause) {
        if (!cancelled && !(cause instanceof DOMException && cause.name === "AbortError")) {
          setError(cause instanceof Error ? cause : new Error("Unable to refresh Price Feed"))
        }
      } finally {
        if (!cancelled) timer = window.setTimeout(poll, Math.max(0, pollIntervalMs - (Date.now() - startedAt)))
      }
    }

    void poll()
    return () => {
      cancelled = true
      controller?.abort()
      if (timer !== undefined) window.clearTimeout(timer)
    }
  }, [isHistoryReady, maxTickSizeReserveLimit, pollIntervalMs, refreshHistory, setAssets])

  const history = useMemo(
    () => ticks.map((tick) => pickAssetPoint(tick, selectedAsset)).filter((point): point is MarketAssetPoint => point !== null),
    [selectedAsset, ticks],
  )
  const latest = history.at(-1)
  const observedUpdateIntervalMs = useMemo(() => {
    const recentTicks = ticks.slice(-(OBSERVED_INTERVAL_SAMPLE_SIZE + 1))
    const intervals = recentTicks.slice(1)
      .map((tick, index) => tick.t - recentTicks[index].t)
      .filter((interval) => Number.isFinite(interval) && interval > 0)
    return median(intervals)
  }, [ticks])

  useEffect(() => {
    const latestTick = ticks.at(-1)
    if (!latestTick) return
    const tickers = Object.entries(latestTick.assets).reduce((result, [asset, value]) => {
      result[asset] = { ...value, t: latestTick.t, id: latestTick.id, timestamp: latestTick.timestamp, chainPos: latestTick.chainPos }
      return result
    }, {} as Record<string, MarketTicker>)
    setTickers(tickers)
  }, [setTickers, ticks])

  return { runtime, config, nodeIds, history, latest, observedUpdateIntervalMs, pollIntervalMs, isLoading, error, refetchHistory: refreshHistory }
}
