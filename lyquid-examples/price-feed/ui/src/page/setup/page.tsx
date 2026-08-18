import { loadPriceFeedConfig, loadPriceHead } from "@/lib/price-feed-api"
import {
  discoverHostedCluster,
  executeOperatorInstanceCall,
  executeOperatorNetworkWrite,
  loadOperatorRuntime,
  readOperatorNodeState,
  type OperatorInstanceCall,
  type OperatorNode,
  type OperatorRuntime,
} from "@/lib/operator-console"
import { CheckCircle2, CircleAlert, Loader2, RefreshCw } from "lucide-react"
import { useCallback, useEffect, useRef, useState } from "react"
import { toast } from "sonner"
import { useAccount } from "wagmi"

type ActionState = { status: "idle" | "working"; message?: string }

const INITIAL_ACTIONS: Record<string, ActionState> = {}

function short(value: string | null | undefined, size = 11) {
  if (!value) return "—"
  return value.length <= size * 2 ? value : `${value.slice(0, size)}…${value.slice(-size)}`
}

function readableTime(timestamp: number | undefined) {
  if (!timestamp || !Number.isFinite(timestamp)) return "No finalized quote"
  const ms = timestamp < 10_000_000_000 ? timestamp * 1_000 : timestamp
  return new Date(ms).toLocaleString()
}

function sourceDefaults(nodes: OperatorNode[], availableSources: string[]) {
  const fallback = availableSources[0] ?? ""
  return Object.fromEntries(nodes.map((node) => [node.id, availableSources.includes(node.source ?? "") ? node.source ?? fallback : fallback]))
}

export function SetupPage() {
  const { address, isConnected } = useAccount()
  const [runtime, setRuntime] = useState<OperatorRuntime | null>(null)
  const [nodes, setNodes] = useState<OperatorNode[]>([])
  const [seed, setSeed] = useState("")
  const [committee, setCommittee] = useState<string[]>([])
  const [threshold, setThreshold] = useState(0)
  const [executor, setExecutor] = useState("")
  const [sources, setSources] = useState<Record<string, string>>({})
  const [availableSources, setAvailableSources] = useState<string[]>([])
  const [headTimestamp, setHeadTimestamp] = useState<number | undefined>()
  const [headReporters, setHeadReporters] = useState(0)
  const [interval, setInterval] = useState("10000")
  const [actions, setActions] = useState<Record<string, ActionState>>(INITIAL_ACTIONS)
  const [loading, setLoading] = useState(true)
  const [discovering, setDiscovering] = useState(false)
  const [nodesExpanded, setNodesExpanded] = useState(false)
  const [advancedExpanded, setAdvancedExpanded] = useState(true)
  const [issue, setIssue] = useState<string | null>(null)
  const runtimeRef = useRef<OperatorRuntime | null>(null)
  const nodesRef = useRef<OperatorNode[]>([])
  const executorRef = useRef("")

  useEffect(() => { runtimeRef.current = runtime }, [runtime])
  useEffect(() => { nodesRef.current = nodes }, [nodes])
  useEffect(() => { executorRef.current = executor }, [executor])

  const refreshState = useCallback(async (knownRuntime = runtimeRef.current, knownNodes = nodesRef.current, targetId = executorRef.current) => {
    if (!knownRuntime || !knownNodes.length) return
    const target = knownNodes.find((node) => node.id === targetId && node.reachable)
      ?? knownNodes.find((node) => node.reachable)
      ?? null
    const refreshedTarget = target ? await readOperatorNodeState(target, knownRuntime.contract) : null
    const refreshed = knownNodes.map((node) => node.id === refreshedTarget?.id ? refreshedTarget : node)
    setNodes(refreshed)
    const head = await loadPriceHead().catch(() => null)
    const latest = head?.head
    setHeadTimestamp(latest?.timestamp)
    setHeadReporters((Object.values(latest?.data ?? {}) as Array<{ candidates?: unknown[] }>).reduce((max, asset) => Math.max(max, asset.candidates?.length ?? 0), 0))
  }, [])

  const bootstrap = useCallback(async () => {
    setLoading(true)
    try {
      const nextRuntime = await loadOperatorRuntime()
      setRuntime(nextRuntime)
      const [discovered, config] = await Promise.all([
        discoverHostedCluster(nextRuntime.nodeBaseUrl, ""),
        loadPriceFeedConfig().catch(() => null),
      ])
      const hasConfiguredCommittee = Boolean(config?.committee.nodeIds.length)
      const nextSources = config?.sources.filter((source) => source.trim()) ?? []
      setNodes(discovered)
      setAvailableSources(nextSources)
      setNodesExpanded(hasConfiguredCommittee)
      setAdvancedExpanded(!hasConfiguredCommittee)
      const current = discovered.find((node) => node.reachable) ?? discovered[0]
      setSeed(current?.id ?? "")
      setExecutor(current?.id ?? "")
      const keys = discovered.flatMap((node) => node.committeeKey ? [node.committeeKey] : [])
      setCommittee(keys)
      setThreshold(Math.floor(keys.length / 2) + 1)
      setSources(sourceDefaults(discovered, nextSources))
      await refreshState(nextRuntime, discovered, current?.id ?? "")
    } catch (error) {
      setIssue(error instanceof Error ? error.message : "Could not load operator runtime")
    } finally {
      setLoading(false)
    }
  }, [refreshState])

  useEffect(() => { void bootstrap() }, [bootstrap])
  useEffect(() => {
    const timer = window.setInterval(() => { void refreshState() }, 12_000)
    return () => window.clearInterval(timer)
  }, [refreshState])

  const discover = async () => {
    if (!runtime) return
    setDiscovering(true)
    setIssue(null)
    try {
      const discovered = await discoverHostedCluster(runtime.nodeBaseUrl, seed)
      setNodes(discovered)
      const keys = discovered.flatMap((node) => node.committeeKey ? [node.committeeKey] : [])
      setCommittee(keys)
      setThreshold(Math.floor(keys.length / 2) + 1)
      const nextExecutor = discovered.some((node) => node.id === executorRef.current)
        ? executorRef.current
        : (discovered.find((node) => node.reachable)?.id ?? "")
      setExecutor(nextExecutor)
      setSources(sourceDefaults(discovered, availableSources))
      await refreshState(runtime, discovered, nextExecutor)
    } catch (error) {
      setIssue(error instanceof Error ? error.message : "Cluster discovery failed")
    } finally {
      setDiscovering(false)
    }
  }

  const selectedNode = nodes.find((node) => node.id === executor) ?? null
  const quorumMet = threshold > 0 && headReporters >= threshold
  const reachable = nodes.filter((node) => node.reachable).length
  const enabled = selectedNode?.reporting?.enabled ?? false

  const runNetworkAction = async (
    key: string,
    label: string,
    args: readonly unknown[] = [],
    node = selectedNode,
  ) => {
    if (!runtime || !node || !address) {
      toast.error("Wallet required", { description: "Connect the initializer wallet and select a reachable node." })
      return false
    }
    setActions((current) => ({ ...current, [key]: { status: "working", message: "Waiting for wallet confirmation…" } }))
    try {
      const result = await executeOperatorNetworkWrite({ node, contract: runtime.contract, functionName: "configure_committee", args, account: address })
      toast.success(`${label} confirmed`, { description: short(result.txHash, 8) })
      setNodesExpanded(true)
      setAdvancedExpanded(false)
      await refreshState()
      return true
    } catch (error) {
      toast.error(`${label} failed`, { description: error instanceof Error ? error.message : "Operation failed" })
      return false
    } finally {
      setActions((current) => ({ ...current, [key]: { status: "idle" } }))
    }
  }

  const runInstanceAction = async (
    key: string,
    label: string,
    functionName: OperatorInstanceCall,
    args: readonly unknown[] = [],
    node = selectedNode,
  ) => {
    if (!runtime || !node || !node.reachable) {
      toast.error(`${label} unavailable`, { description: "Select a reachable execution node." })
      return false
    }
    setActions((current) => ({ ...current, [key]: { status: "working", message: `${label}…` } }))
    try {
      await executeOperatorInstanceCall({ node, contract: runtime.contract, functionName, args })
      toast.success(label)
      await refreshState()
      return true
    } catch (error) {
      toast.error(`${label} failed`, { description: error instanceof Error ? error.message : "Operation failed" })
      return false
    } finally {
      setActions((current) => ({ ...current, [key]: { status: "idle" } }))
    }
  }

  const applyConfiguration = async () => {
    const validCommittee = committee.map((value) => value.trim()).filter((value) => /^0x[\da-fA-F]{64}$/.test(value))
    if (validCommittee.length !== committee.length || validCommittee.length < 1 || threshold < 1 || threshold > validCommittee.length) {
      setIssue("Committee keys and quorum must be valid before configuration")
      return
    }
    if (!runtime || !selectedNode || !address) {
      toast.error("Wallet required", { description: "Connect the initializer wallet and select a reachable node." })
      return
    }
    setActions((current) => ({ ...current, apply: { status: "working", message: "Waiting for wallet confirmation…" } }))
    try {
      const result = await executeOperatorNetworkWrite({ node: selectedNode, contract: runtime.contract, functionName: "configure_committee", args: [validCommittee], account: address })
      toast.success("Committee configuration confirmed", { description: short(result.txHash, 8) })
      setNodesExpanded(true)
      setAdvancedExpanded(false)
      setActions((current) => ({ ...current, apply: { status: "working", message: "Advancing oracle epoch…" } }))
      await executeOperatorInstanceCall({ node: selectedNode, contract: runtime.contract, functionName: "__lyquor_oracle_advance_epoch", args: ["price_feed", runtime.contract, false] })
      setActions((current) => ({ ...current, apply: { status: "working", message: "Finalizing oracle epoch…" } }))
      await executeOperatorInstanceCall({ node: selectedNode, contract: runtime.contract, functionName: "__lyquor_oracle_finalize_epoch", args: ["price_feed", runtime.contract, false] })
      toast.success("Configuration applied", { description: "Committee configured and Oracle epoch activated." })
      await refreshState()
    } catch (error) {
      toast.error("Configuration stopped", { description: error instanceof Error ? error.message : "Operation failed" })
    } finally {
      setActions((current) => ({ ...current, apply: { status: "idle" } }))
    }
  }

  const testOneQuote = async () => {
    const before = headTimestamp ?? 0
    if (!await runInstanceAction("report-once", "Quote report requested", "report_prices")) return
    for (let attempt = 0; attempt < 30; attempt += 1) {
      await new Promise((resolve) => window.setTimeout(resolve, 1_000))
      const head = await loadPriceHead().catch(() => null)
      const next = head?.head?.timestamp ?? 0
      if (next > before) {
        setHeadTimestamp(next)
        setHeadReporters((Object.values(head?.head?.data ?? {}) as Array<{ candidates?: unknown[] }>).reduce((max, asset) => Math.max(max, asset.candidates?.length ?? 0), 0))
        return
      }
    }
    toast.error("No finalized quote observed", { description: "The report request completed, but no new finalized quote appeared within 30 seconds." })
  }

  const actionContent = (key: string, idleLabel: string, pendingLabel: string) => actions[key]?.status === "working" ? <><Loader2 size={15} className="animate-spin" /> {actions[key]?.message ?? pendingLabel}</> : idleLabel

  const section = "border-x border-b border-border"
  const sectionHeader = "flex flex-wrap items-end justify-between gap-3 border-b border-border px-4 py-4 sm:px-5"
  const secondaryButton = "inline-flex items-center justify-center gap-2 border border-border bg-background px-3 py-2 text-sm transition-colors hover:bg-muted disabled:cursor-not-allowed disabled:opacity-40"
  const primaryButton = "inline-flex items-center justify-center gap-2 border border-foreground bg-foreground px-3 py-2 text-sm text-background transition-opacity hover:opacity-85 disabled:cursor-not-allowed disabled:opacity-40"
  const field = "border border-border bg-background px-3 py-2 text-sm outline-none transition-colors focus:border-foreground"

  if (loading) return <main className="grid h-[calc(100dvh-64px)] place-items-center border-x border-border"><Loader2 className="animate-spin" /></main>

  return (
    <main className="h-[calc(100dvh-64px)] overflow-y-auto bg-muted/30 text-foreground">
      <div className="mx-auto max-w-[1400px] px-4 pb-12 sm:px-6">
        <header className="border-x border-b border-border">
          <div className="px-4 py-7 sm:px-6 sm:py-9">
            <h1 className="max-w-3xl text-3xl font-semibold tracking-tight sm:text-4xl">Setup and maintain this hosted oracle</h1>
            <p className="mt-3 font-mono text-xs text-foreground/50">{runtime?.info.lyquid_id} · {short(runtime?.contract)}</p>
          </div>
        </header>

        {issue && <div className="flex items-start gap-2 border-x border-b border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm"><CircleAlert size={17} className="mt-0.5 shrink-0" />{issue}</div>}

        <section className={section}>
          <div className={sectionHeader}>
            <div>
              <p className="text-xs font-medium tracking-wider text-foreground/50">COMMITTEE HEALTH</p>
              <h2 className="mt-1 flex items-center gap-2 text-lg font-medium"><span className={`size-2 ${quorumMet ? "bg-emerald-500" : "bg-amber-500"}`} />{quorumMet ? "Quorum observed" : "Needs attention"}</h2>
            </div>
            <button className={secondaryButton} onClick={() => void refreshState()}><RefreshCw size={15} /> Refresh</button>
          </div>
          <div className="grid sm:grid-cols-2 lg:grid-cols-4">
            {[["Reachable nodes", `${reachable}/${nodes.length}`], ["Latest reporters", `${headReporters}/${threshold || "—"}`], ["Quorum", quorumMet ? "Met" : "Not met"], ["Last finalization", readableTime(headTimestamp)]].map(([label, value], index) => <div className={`min-h-24 p-4 sm:p-5 ${index < 3 ? "border-b border-border lg:border-b-0 lg:border-r" : ""} ${index === 1 ? "lg:border-r" : ""}`} key={label}><p className="text-xs text-foreground/50">{label}</p><p className="mt-3 text-sm font-medium">{value}</p></div>)}
          </div>
          {nodes.some((node) => !node.reachable) && <p className="border-t border-border px-4 py-3 text-xs text-amber-600">Unavailable: {nodes.filter((node) => !node.reachable).map((node) => short(node.id, 6)).join(", ")}</p>}
        </section>

        <section className={`${section} mt-6`}>
          <div className={sectionHeader}><div><p className="text-xs font-medium tracking-wider text-foreground/50">COMMITTEE</p><h2 className="mt-1 text-lg font-medium">Discover, review, then apply the lifecycle</h2></div></div>
          <div className="flex flex-col gap-2 border-b border-border p-4 sm:flex-row sm:p-5"><input value={seed} onChange={(event) => setSeed(event.target.value)} placeholder="Seed Node-…" className={`${field} min-w-0 flex-1 font-mono`} /><button className={secondaryButton} onClick={() => void discover()} disabled={discovering}>{discovering ? <Loader2 size={15} className="animate-spin" /> : <RefreshCw size={15} />} Discover cluster</button></div>
          <details open={nodesExpanded} onToggle={(event) => setNodesExpanded(event.currentTarget.open)} className="border-b border-border">
            <summary className="cursor-pointer px-4 py-3 text-sm sm:px-5">Nodes <span className="ml-1 text-foreground/50">({nodes.length})</span></summary>
            <div className="overflow-x-auto border-t border-border"><table className="w-full min-w-[760px] text-left text-sm"><thead className="border-b border-border bg-muted/30 text-xs text-foreground/50"><tr><th className="p-3 font-medium">Node</th><th className="p-3 font-medium">Reachability</th><th className="p-3 font-medium">Source</th><th className="p-3 font-medium">Reporting</th><th className="p-3 font-medium">Execution target</th></tr></thead><tbody>{nodes.map((node) => { const selectedSource = sources[node.id] ?? ""; const sourceActionKey = `source:${node.id}`; return <tr className="border-b border-border last:border-0 hover:bg-muted/20" key={node.id}><td className="p-3 font-mono text-xs">{node.id}</td><td className="p-3">{node.reachable ? <span className="inline-flex items-center gap-1 text-emerald-600"><CheckCircle2 size={14} /> Reachable</span> : <span className="text-red-500">Unavailable</span>}</td><td className="p-3"><div className="flex items-center gap-2"><select value={selectedSource} onChange={(event) => setSources((current) => ({ ...current, [node.id]: event.target.value }))} className="border border-border bg-background px-2 py-1 text-xs" disabled={!node.reachable || !availableSources.length}>{availableSources.length ? availableSources.map((source) => <option value={source} key={source}>{source}</option>) : <option value="">No source available</option>}</select><button className="border border-border px-2 py-1 text-xs hover:bg-muted disabled:cursor-not-allowed disabled:opacity-40" disabled={!node.reachable || !selectedSource || actions[sourceActionKey]?.status === "working"} onClick={() => void runInstanceAction(sourceActionKey, `Source applied on ${short(node.id, 7)}`, "set_price_source", [selectedSource], node)}>{actionContent(sourceActionKey, "Apply", "Applying source…")}</button></div></td><td className="p-3 text-xs">{node.reporting?.enabled ? `Running · ${node.reporting.intervalMs}ms` : "Stopped"}</td><td className="p-3"><input type="radio" name="executor" checked={executor === node.id} onChange={() => setExecutor(node.id)} disabled={!node.reachable} /></td></tr>})}</tbody></table></div>
          </details>
          <details open={advancedExpanded} onToggle={(event) => setAdvancedExpanded(event.currentTarget.open)} className="border-b border-border px-4 py-3 sm:px-5"><summary className="cursor-pointer text-sm">Advanced generated call</summary><div className="mt-3 grid gap-3"><label className="text-xs text-foreground/50">Committee bytes32[]<textarea value={committee.join("\n")} onChange={(event) => setCommittee(event.target.value.split("\n").map((value) => value.trim()).filter(Boolean))} className={`${field} mt-1 h-28 w-full font-mono text-xs text-foreground`} /></label><label className="text-xs text-foreground/50">Quorum threshold<input type="number" min="1" max={committee.length || 1} value={threshold} onChange={(event) => setThreshold(Number(event.target.value))} className={`${field} ml-2 w-20 py-1 text-foreground`} /></label></div></details>
          <div className="flex flex-wrap gap-2 border-b border-border p-4 sm:p-5"><button className={primaryButton} disabled={!isConnected || actions.apply?.status === "working"} onClick={() => void applyConfiguration()}>{actionContent("apply", "Apply configuration", "Applying configuration…")}</button><button className={secondaryButton} disabled={!isConnected || actions.configure?.status === "working"} onClick={() => void runNetworkAction("configure", "Committee configuration", [committee])}>{actionContent("configure", "Configure committee", "Configuring committee…")}</button><button className={secondaryButton} disabled={!selectedNode?.reachable || actions.advance?.status === "working"} onClick={() => void runInstanceAction("advance", "Oracle epoch advanced", "__lyquor_oracle_advance_epoch", ["price_feed", runtime?.contract, false])}>{actionContent("advance", "Advance epoch", "Advancing epoch…")}</button><button className={secondaryButton} disabled={!selectedNode?.reachable || actions.finalize?.status === "working"} onClick={() => void runInstanceAction("finalize", "Oracle epoch finalized", "__lyquor_oracle_finalize_epoch", ["price_feed", runtime?.contract, false])}>{actionContent("finalize", "Finalize epoch", "Finalizing epoch…")}</button></div>
        </section>

        <section className={`${section} mt-6`}>
          <div className={sectionHeader}><div><p className="text-xs font-medium tracking-wider text-foreground/50">REPORTING</p><h2 className="mt-1 text-lg font-medium">Run, observe, and stop node-local reporting</h2></div><span className={`flex items-center gap-2 text-xs ${enabled ? "text-emerald-600" : "text-foreground/50"}`}><span className={`size-2 ${enabled ? "bg-emerald-500" : "bg-foreground/25"}`} />{enabled ? "Running" : "Stopped"}</span></div>
          <div className="grid md:grid-cols-[minmax(0,1fr)_auto]"><div className="min-w-0 border-b border-border p-4 md:border-b-0 md:border-r sm:p-5"><p className="text-xs text-foreground/50">Selected execution node</p><p className="mt-2 truncate font-mono text-xs">{selectedNode?.id ?? "Select a reachable node"}</p><p className="mt-5 text-sm">{enabled ? `Reporting every ${selectedNode?.reporting?.intervalMs} ms` : "Reporting is stopped"}</p></div><div className="flex flex-wrap items-center gap-2 p-4 sm:p-5"><button className={secondaryButton} disabled={!selectedNode?.reachable || actions["report-once"]?.status === "working"} onClick={() => void testOneQuote()}>{actionContent("report-once", "Test one quote", "Requesting quote…")}</button>{enabled ? <button className="inline-flex items-center gap-2 border border-red-500 bg-background px-3 py-2 text-sm text-red-600 hover:bg-red-500/10 disabled:cursor-not-allowed disabled:opacity-40" disabled={!selectedNode?.reachable || actions.stop?.status === "working"} onClick={() => void runInstanceAction("stop", "Reporting stopped", "stop_reporting")}>{actionContent("stop", "Stop reporting", "Stopping reporting…")}</button> : <><input type="number" min="1" value={interval} onChange={(event) => setInterval(event.target.value)} className={`${field} w-28`} /><button className={primaryButton} disabled={!selectedNode?.reachable || actions.start?.status === "working"} onClick={() => void runInstanceAction("start", "Reporting started", "start_reporting", [BigInt(interval || "0")])}>{actionContent("start", "Start reporting", "Starting reporting…")}</button></>}</div></div>
          <p className="border-t border-border px-4 py-3 text-xs text-foreground/50 sm:px-5">“Start reporting” is persistent. The 10-second test uses 10000 ms and continues until an operator uses Stop reporting; it does not remove committee state or price history.</p>
        </section>
      </div>
    </main>
  )
}
