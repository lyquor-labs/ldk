import { Column } from "@/components/composition"
import { CryptoIcons } from "@/components/crypto-icons"
import { JazzAvatar } from "@/components/jazzicon/jazzavatar"
import { dayjsFormat } from "@/constants"
import type { GetPricesResultRaw } from "@/interface"
import { loadHostedRuntimeContext, loadPriceFeedConfig, loadPriceHead, loadPriceHistory, loadPriceUpdates, type PriceFeedConfig } from "@/lib/price-feed-api"
import { useMarketStore } from "@/stores/market-store"
import { fmtUsd, shortStr } from "@/utils"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "lyquor-shadcn"
import dayjs from "dayjs"
import { AnimatePresence, motion } from "framer-motion"
import { ArrowUpRight, ChevronDown, ChevronRight, Loader2 } from "lucide-react"
import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react"
import { Link, useParams } from "react-router"

const PRICE_SCALE = 100_000_000
const HISTORY_SIZE = 100

type RpcLog = {
  blockNumber: string
  logIndex: string
  transactionHash: string
  transactionIndex: string
}

type RpcTransaction = {
  blockHash: string
  blockNumber: string
  from: string
  gas: string
  gasPrice: string
  hash: string
  input: string
  to: string | null
  transactionIndex: string
}

type RpcBlock = {
  hash: string
  number: string
  timestamp: string
  transactions: unknown[]
}

type MarketUpdateAsset = {
  asset: string
  candidateCount: number
  candidates: NonNullable<GetPricesResultRaw["data"][string]["candidates"]>
  price: number
  signers: string[]
  source: string | null
}

type MarketUpdate = {
  assets: MarketUpdateAsset[]
  blockIndex: string
  blockNumber: string
  id: number
  timestamp: number
  transactionHash: string | null
  transactionIndex: string | null
}

function chainPositionKey(blockNumber: string, blockIndex: string) {
  return `${blockNumber.toLowerCase()}:${blockIndex.toLowerCase()}`
}

function asNumber(value: string | number | undefined): number | null {
  if (value == null) return null
  const parsed = typeof value === "number" ? value : Number.parseInt(value, 16)
  return Number.isFinite(parsed) ? parsed : null
}

function formatBlockNumber(blockNumber: string) {
  return asNumber(blockNumber)?.toLocaleString() ?? blockNumber
}

function parseBlockNumber(blockNumber: string): number | null {
  const parsed = Number.parseInt(blockNumber, blockNumber.startsWith("0x") ? 16 : 10)
  return Number.isFinite(parsed) ? parsed : null
}

function blockNumberPath(blockNumber: string) {
  return parseBlockNumber(blockNumber)?.toString(10) ?? blockNumber
}

function rpcBlockNumber(blockNumber: string) {
  const parsed = parseBlockNumber(blockNumber)
  return parsed == null ? blockNumber : `0x${parsed.toString(16)}`
}

function updateFromSnapshot(snapshot: GetPricesResultRaw, logs: Map<string, RpcLog>): MarketUpdate | null {
  const blockNumber = snapshot.chainPos?.blockNumber
  const blockIndex = snapshot.chainPos?.blockIndex
  const timestamp = Number(snapshot.timestamp)
  if (!blockNumber || !blockIndex || !Number.isFinite(timestamp) || timestamp <= 0) return null

  const log = logs.get(chainPositionKey(blockNumber, blockIndex))
  return {
    id: snapshot.id,
    timestamp,
    blockNumber,
    blockIndex,
    transactionHash: log?.transactionHash ?? null,
    transactionIndex: log?.transactionIndex ?? null,
    assets: Object.entries(snapshot.data ?? {}).map(([asset, value]) => ({
      asset,
      price: Number(value.price) / PRICE_SCALE,
      source: value.source ?? null,
      signers: value.signers ?? [],
      candidates: value.candidates ?? [],
      candidateCount: value.candidates?.length ?? 0,
    })),
  }
}

let rpcRequestId = 1

function nodeRpcUrl(runtime: Awaited<ReturnType<typeof loadHostedRuntimeContext>>): string {
  return new URL("/api", runtime.info.node_base_url).href
}

async function callNodeRpc<T>(rpcUrl: string, method: string, params: unknown[]): Promise<T> {
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: rpcRequestId++, method, params }),
  })
  const body = await response.json() as { result?: T; error?: { message?: string } }
  if (!response.ok || body.error) {
    throw new Error(body.error?.message ?? `${method} returned ${response.status}`)
  }
  return body.result as T
}

async function resolveUpdates(snapshots: GetPricesResultRaw[], contractAddress: string | null, rpcUrl: string): Promise<MarketUpdate[]> {
  const positioned = snapshots.filter((snapshot) => snapshot.chainPos?.blockNumber && snapshot.chainPos?.blockIndex)
  if (!positioned.length || !contractAddress) {
    return positioned.map((snapshot) => updateFromSnapshot(snapshot, new Map())).filter(Boolean) as MarketUpdate[]
  }

  const blockNumbers = positioned
    .map((snapshot) => asNumber(snapshot.chainPos?.blockNumber))
    .filter((value): value is number => value != null)
  let logs: RpcLog[] = []
  try {
    logs = await callNodeRpc<RpcLog[]>(rpcUrl, "eth_getLogs", [{
      fromBlock: `0x${Math.min(...blockNumbers).toString(16)}`,
      toBlock: `0x${Math.max(...blockNumbers).toString(16)}`,
      address: contractAddress,
    }])
  } catch {
    // The history endpoint remains sufficient for the explorer list; logs only
    // enrich it with transaction links.
  }
  const logsByPosition = new Map(logs.map((log) => [chainPositionKey(log.blockNumber, log.logIndex), log]))
  return positioned
    .map((snapshot) => updateFromSnapshot(snapshot, logsByPosition))
    .filter(Boolean)
    .sort((left, right) => right.timestamp - left.timestamp) as MarketUpdate[]
}

function ConsensusFlow({ asset, committee }: { asset: MarketUpdateAsset; committee: PriceFeedConfig["committee"] | undefined }) {
  const signers = asset.signers
  const threshold = committee?.threshold
  const memberCount = committee?.nodeIds.length

  return (
    <div className="bg-muted/20 text-sm">
      <div className="grid grid-cols-[minmax(0,2fr)_minmax(220px,1fr)]">
        <div className="h-[100px] overflow-y-auto">
          {asset.candidates.length ? asset.candidates.map(([nodeId, candidate]) => (
            <div key={nodeId} className="flex h-[33px] items-center gap-2 px-4 text-xs">
              <div className="flex min-w-0 items-center gap-1.5">
                <span className="shrink-0 text-foreground/60">{candidate.source ?? "—"}</span>
                <JazzAvatar address={nodeId} size={16} className="shrink-0" />
                <span className="truncate font-mono">{shortStr(nodeId, 10)}</span>
                <span className="ml-auto shrink-0">{fmtUsd(Number(candidate.price) / PRICE_SCALE)}</span>
              </div>
            </div>
          )) : <div className="flex h-full items-center px-4 text-xs text-foreground/60">No candidate quotes.</div>}
        </div>
        <div className="flex flex-col justify-between border-l px-4 py-3 text-left">
          <div>
            <div className="text-xs text-foreground/60">Final price</div>
            <div className="mt-1 text-2xl font-semibold">{fmtUsd(asset.price)}</div>
          </div>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-foreground/60">
            <span>Source <span className="text-foreground">{asset.source ?? "—"}</span></span>
            <span>Certification <span className="text-foreground">{signers.length}{memberCount ? `/${memberCount}` : ""}{threshold ? ` · ${threshold} required` : ""}</span></span>
          </div>
        </div>
      </div>
    </div>
  )
}

function AssetConsensusPanel({ update, committee, selectedAsset, onSelectAsset }: {
  update: MarketUpdate
  committee: PriceFeedConfig["committee"] | undefined
  selectedAsset: string | undefined
  onSelectAsset: (asset: string) => void
}) {
  const activeAsset = update.assets.find((asset) => asset.asset === selectedAsset) ?? update.assets[0]
  if (!activeAsset) return null

  return (
    <div>
      <div className="flex overflow-x-auto border-b">
        {update.assets.map((asset) => {
          const active = asset.asset === activeAsset.asset
          return <button key={asset.asset} type="button" onClick={() => onSelectAsset(asset.asset)} className={`min-w-36 border-r px-3 py-2 text-left text-sm ${active ? "bg-foreground text-background" : "hover:bg-muted"}`}>
            <div className="font-medium">{asset.asset}</div>
            <div className={`mt-0.5 text-xs ${active ? "text-background/70" : "text-foreground/60"}`}>{fmtUsd(asset.price)} · {asset.candidateCount} quotes</div>
          </button>
        })}
      </div>
      <ConsensusFlow asset={activeAsset} committee={committee} />
    </div>
  )
}

export const ExplorerPage = () => {
  const pollIntervalMs = useMarketStore((state) => state.pollIntervalMs)
  const { txHash, blockNumber: requestedBlockNumber } = useParams()
  const [updates, setUpdates] = useState<MarketUpdate[]>([])
  const [config, setConfig] = useState<PriceFeedConfig | null>(null)
  const [contractAddress, setContractAddress] = useState<string | null>(null)
  const [rpcUrl, setRpcUrl] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [enteringUpdateIds, setEnteringUpdateIds] = useState<Set<number>>(() => new Set())
  const [selectedAssets, setSelectedAssets] = useState<Record<string, string>>({})
  const [transaction, setTransaction] = useState<RpcTransaction | null>(null)
  const [block, setBlock] = useState<RpcBlock | null>(null)
  const lastSeenId = useRef(0)

  const refresh = useCallback(async () => {
    setIsLoading(true)
    try {
      const [history, nextConfig, runtime] = await Promise.all([
        loadPriceHistory(0, HISTORY_SIZE),
        loadPriceFeedConfig(),
        loadHostedRuntimeContext(),
      ])
      const nextContract = runtime.info.backend_contract
      const nextRpcUrl = nodeRpcUrl(runtime)
      const nextUpdates = await resolveUpdates(history.results ?? [], nextContract, nextRpcUrl)
      lastSeenId.current = (history.results ?? []).at(-1)?.id ?? 0
      setUpdates(nextUpdates)
      setEnteringUpdateIds(new Set())
      setConfig(nextConfig)
      setContractAddress(nextContract)
      setRpcUrl(nextRpcUrl)
      setError(null)
    } catch (cause) {
      setError(cause instanceof Error ? cause : new Error("Unable to load market updates"))
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  useEffect(() => {
    let cancelled = false
    let timer: number | undefined
    let controller: AbortController | undefined

    const poll = async () => {
      const startedAt = Date.now()
      controller = new AbortController()
      try {
        const { head } = await loadPriceHead(controller.signal)
        if (!head || cancelled || !contractAddress || !rpcUrl) return
        setError(null)
        if (head.id < lastSeenId.current) {
          await refresh()
          return
        }
        if (head.id <= lastSeenId.current) return
        const history = await loadPriceUpdates(lastSeenId.current, controller.signal)
        if (history.cursorExpired || history.cursorReset || (history.oldestId != null && history.oldestId > lastSeenId.current + 1)) {
          await refresh()
          return
        }
        const firstUpdateId = history.results?.[0]?.id
        if (firstUpdateId != null && firstUpdateId !== lastSeenId.current + 1) {
          await refresh()
          return
        }
        const nextUpdates = await resolveUpdates(history.results ?? [], contractAddress, rpcUrl)
        if (cancelled || !nextUpdates.length) return
        lastSeenId.current = history.results?.at(-1)?.id ?? lastSeenId.current
        setEnteringUpdateIds((current) => new Set([...current, ...nextUpdates.map((update) => update.id)]))
        setUpdates((current) => {
          const knownIds = new Set(current.map((update) => update.id))
          const unseen = nextUpdates.filter((update) => !knownIds.has(update.id))
          return unseen.length ? [...unseen.reverse(), ...current].slice(0, HISTORY_SIZE) : current
        })
      } catch (cause) {
        if (!cancelled && !(cause instanceof DOMException && cause.name === "AbortError")) {
          setError(cause instanceof Error ? cause : new Error("Unable to refresh market updates"))
        }
      } finally {
        if (!cancelled) {
          timer = window.setTimeout(poll, Math.max(0, pollIntervalMs - (Date.now() - startedAt)))
        }
      }
    }

    void poll()
    return () => {
      cancelled = true
      controller?.abort()
      if (timer !== undefined) window.clearTimeout(timer)
    }
  }, [contractAddress, pollIntervalMs, refresh, rpcUrl])

  useEffect(() => {
    if (!enteringUpdateIds.size) return
    const timer = window.setTimeout(() => setEnteringUpdateIds(new Set()), 450)
    return () => window.clearTimeout(timer)
  }, [enteringUpdateIds])

  const selectedUpdate = useMemo(
    () => updates.find((update) => update.transactionHash?.toLowerCase() === txHash?.toLowerCase()),
    [txHash, updates],
  )
  const hasTransactionLinks = updates.some((update) => update.transactionHash)

  useEffect(() => {
    if (!txHash) {
      setTransaction(null)
      return
    }
    if (!rpcUrl) return
    void callNodeRpc<RpcTransaction | null>(rpcUrl, "eth_getTransactionByHash", [txHash]).then(setTransaction).catch((cause) => setError(cause instanceof Error ? cause : new Error("Unable to load transaction")))
  }, [rpcUrl, txHash])

  useEffect(() => {
    if (!requestedBlockNumber) {
      setBlock(null)
      return
    }
    if (!rpcUrl) return
    void callNodeRpc<RpcBlock>(rpcUrl, "eth_getBlockByNumber", [rpcBlockNumber(requestedBlockNumber), false]).then(setBlock).catch((cause) => setError(cause instanceof Error ? cause : new Error("Unable to load block")))
  }, [requestedBlockNumber, rpcUrl])

  const selectAsset = (key: string, asset: string) => setSelectedAssets((current) => ({ ...current, [key]: asset }))

  if (txHash || requestedBlockNumber) {
    const detailTitle = txHash ? "Transaction detail" : "Block detail"
    return (
      <div className="flex min-h-screen flex-col">
        <div className="border-b px-6 py-5">
          <div className="mx-auto max-w-[1400px]">
            <Link to="/explorer" className="text-sm text-foreground/60 hover:text-foreground">← Market Updates</Link>
            <h1 className="mt-3 text-2xl">{detailTitle}</h1>
          </div>
        </div>
        <Column className="mx-auto w-full max-w-[1400px] flex-1 gap-0 border-x">
          {txHash ? (
            transaction ? (
              <dl className="grid grid-cols-[120px_1fr] gap-y-2 px-6 py-5 break-all text-sm">
                <dt className="text-foreground/60">Hash</dt><dd className="font-mono">{transaction.hash}</dd>
                <dt className="text-foreground/60">From</dt><dd className="font-mono">{transaction.from}</dd>
                <dt className="text-foreground/60">To</dt><dd className="font-mono">{transaction.to ?? "Contract creation"}</dd>
                <dt className="text-foreground/60">Block</dt><dd>#{formatBlockNumber(transaction.blockNumber)} · tx #{asNumber(transaction.transactionIndex) ?? "—"}</dd>
                <dt className="text-foreground/60">Data</dt><dd className="font-mono">{transaction.input === "0x" ? "No call data" : transaction.input}</dd>
              </dl>
            ) : <div className="px-6 py-5 text-sm text-foreground/60">Loading transaction…</div>
          ) : block ? (
            <dl className="grid grid-cols-[120px_1fr] gap-y-2 border-b px-6 py-5 break-all text-sm">
              <dt className="text-foreground/60">Block</dt><dd>#{formatBlockNumber(block.number)}</dd>
              <dt className="text-foreground/60">Hash</dt><dd className="font-mono">{block.hash}</dd>
              <dt className="text-foreground/60">Timestamp</dt><dd>{(() => { const timestamp = asNumber(block.timestamp); return timestamp == null ? "—" : dayjs(timestamp * 1000).format(dayjsFormat) })()}</dd>
              <dt className="text-foreground/60">Transactions</dt><dd>{block.transactions.length}</dd>
            </dl>
          ) : <div className="px-6 py-5 text-sm text-foreground/60">Loading block…</div>}
          {txHash ? (
            selectedUpdate ? (
              <div className="border-b bg-muted/60">
                <div className="px-6 py-3 text-sm">Finalized {dayjs(selectedUpdate.timestamp).format(dayjsFormat)}</div>
                <AssetConsensusPanel update={selectedUpdate} committee={config?.committee} selectedAsset={selectedAssets[`detail:${selectedUpdate.id}`]} onSelectAsset={(asset) => selectAsset(`detail:${selectedUpdate.id}`, asset)} />
              </div>
            ) : null
          ) : block ? (
            <Table>
              <TableHeader>
                <TableRow className="[&>th]:font-normal [&>th]:text-sm [&>th:first-child]:px-6 [&>th:last-child]:px-6"><TableHead>Transaction</TableHead><TableHead className="text-right">Index</TableHead></TableRow>
              </TableHeader>
              <TableBody>
                {block.transactions.length ? block.transactions.map((transactionHash, index) => {
                  const hash = String(transactionHash)
                  return <TableRow key={hash} className="[&>td:first-child]:px-6 [&>td:last-child]:px-6">
                    <TableCell><Link className="inline-flex items-center gap-1 font-mono text-sm hover:underline" to={`/explorer/tx/${hash}`}>{shortStr(hash, 16)} <ArrowUpRight className="size-3" /></Link></TableCell>
                    <TableCell className="text-right text-sm text-foreground/60">#{index}</TableCell>
                  </TableRow>
                }) : <TableRow><TableCell colSpan={2} className="h-24 px-6 text-center text-sm text-foreground/60">No transactions in this block.</TableCell></TableRow>}
              </TableBody>
            </Table>
          ) : null}
        </Column>
      </div>
    )
  }

  return (
    <div className="flex min-h-screen flex-col">
      <div className="border-b px-6 py-5">
        <div className="mx-auto flex max-w-[1400px] items-end justify-between gap-4">
          <div>
            <h1 className="text-2xl">Market Updates</h1>
            <p className="mt-1 text-sm text-foreground/60">Finalized price updates grouped by their on-chain transaction.</p>
          </div>
          <button type="button" className="border px-3 py-1.5 text-sm hover:bg-foreground hover:text-background" onClick={() => void refresh()}>
            Refresh
          </button>
        </div>
      </div>

      <Column className="mx-auto w-full max-w-[1400px] flex-1 gap-0 border-x">
        <Table>
          <TableHeader>
            <TableRow className="[&>th]:font-normal [&>th]:text-sm">
              <TableHead className="w-10" />
              <TableHead>Finalized</TableHead>
              {hasTransactionLinks && <TableHead>Transaction</TableHead>}
              <TableHead>Block</TableHead>
              <TableHead>Committee</TableHead>
              <TableHead className="text-right">Assets updated</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {updates.map((update) => {
              const key = `${update.blockNumber}:${update.blockIndex}`
              const isExpanded = expanded === key
              const signerCount = Math.max(...update.assets.map((asset) => asset.signers.length), 0)
              return (
                <Fragment key={key}>
                  <motion.tr
                    layout="position"
                    initial={enteringUpdateIds.has(update.id) ? { opacity: 0, x: 64 } : false}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ default: { duration: 0.28, ease: "easeOut" }, layout: { duration: 0.28, ease: "easeOut" } }}
                    className="cursor-pointer border-b hover:bg-muted/30"
                    onClick={() => setExpanded(isExpanded ? null : key)}
                  >
                    <TableCell>{isExpanded ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />}</TableCell>
                    <TableCell className="whitespace-nowrap text-sm">{dayjs(update.timestamp).format(dayjsFormat)}</TableCell>
                    {hasTransactionLinks && <TableCell>
                      {update.transactionHash ? (
                        <Link className="inline-flex items-center gap-1 font-mono text-sm hover:underline" to={`/explorer/tx/${update.transactionHash}`} onClick={(event) => event.stopPropagation()}>
                          {shortStr(update.transactionHash, 12)} <ArrowUpRight className="size-3" />
                        </Link>
                      ) : <span className="text-sm text-foreground/60">Unavailable</span>}
                    </TableCell>}
                    <TableCell>
                      <Link className="inline-flex items-center gap-1 text-sm hover:underline" to={`/explorer/block/${blockNumberPath(update.blockNumber)}`} onClick={(event) => event.stopPropagation()}>
                        #{formatBlockNumber(update.blockNumber)} <ArrowUpRight className="size-3" />
                      </Link>
                    </TableCell>
                    <TableCell className="text-sm">{signerCount}{config ? `/${config.committee.nodeIds.length} · ${config.committee.threshold} required` : ""}</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap justify-end gap-x-3 gap-y-1 text-sm">
                        {update.assets.map((asset) => (
                          <div key={asset.asset} className="flex items-center gap-1.5">
                            <CryptoIcons token={asset.asset} size={16} />
                            <span>{asset.asset}</span>
                          </div>
                        ))}
                      </div>
                    </TableCell>
                  </motion.tr>
                  <AnimatePresence initial={false}>
                    {isExpanded && (
                      <motion.tr key={`${key}:assets`} layout="position" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ default: { duration: 0.2, ease: "easeOut" }, layout: { duration: 0.28, ease: "easeOut" } }} className="hover:bg-transparent">
                        <TableCell colSpan={hasTransactionLinks ? 6 : 5} className="p-0">
                          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.24, ease: "easeOut" }} className="overflow-hidden bg-muted/60">
                            <AssetConsensusPanel
                              update={update}
                              committee={config?.committee}
                              selectedAsset={selectedAssets[key]}
                              onSelectAsset={(asset) => selectAsset(key, asset)}
                            />
                          </motion.div>
                        </TableCell>
                      </motion.tr>
                    )}
                  </AnimatePresence>
                </Fragment>
              )
            })}
            {!isLoading && !updates.length ? (
              <TableRow><TableCell colSpan={hasTransactionLinks ? 6 : 5} className="h-28 text-center text-sm text-foreground/60">No finalized market updates yet.</TableCell></TableRow>
            ) : null}
          </TableBody>
        </Table>
        {isLoading ? <div className="flex items-center justify-center gap-2 py-10 text-sm text-foreground/60"><Loader2 className="size-4 animate-spin" /> Loading market updates…</div> : null}
        {error ? <div className="border-t px-4 py-3 text-sm text-foreground/70">Unable to load market updates: {error.message}</div> : null}
      </Column>

    </div>
  )
}
