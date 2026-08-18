import { decodeFunctionResult, encodeFunctionData, parseAbi, type Address, type Hex } from "viem"
import { loadHostedRuntimeContext, type HostedRuntimeContext } from "@/lib/price-feed-api"

const PRICE_FEED_OPERATOR_ABI = parseAbi([
  "function configure_committee(bytes32[] nodeIds) returns (bool)",
  "function __lyquor_oracle_advance_epoch(string topic, address target, bool dryRun) returns (bool)",
  "function __lyquor_oracle_finalize_epoch(string topic, address target, bool dryRun) returns (bool)",
  "function set_price_source(string source) returns (bool)",
  "function report_prices() returns (bool)",
  "function start_reporting(uint64 intervalMs) returns (bool)",
  "function stop_reporting() returns (bool)",
  "function get_price_source() view returns (string)",
  "function get_reporting_status() view returns (bool enabled, uint64 intervalMs)",
] as const)

export type OperatorNode = {
  id: string
  rpcUrl: string
  wsUrl: string
  committeeKey: Hex | null
  reachable: boolean
  issue: string | null
  source: string | null
  reporting: { enabled: boolean; intervalMs: number } | null
}

export type OperatorRuntime = HostedRuntimeContext & {
  contract: Address
  nodeBaseUrl: string
}

export type OperatorNetworkWrite = "configure_committee"

export type OperatorInstanceCall =
  | "__lyquor_oracle_advance_epoch"
  | "__lyquor_oracle_finalize_epoch"
  | "set_price_source"
  | "report_prices"
  | "start_reporting"
  | "stop_reporting"

type NodeInfoResponse = {
  nodeId?: { value?: unknown } | unknown
  node_id?: { value?: unknown } | unknown
}

type PeersResponse = {
  peers?: Array<{ id?: { value?: unknown } | unknown }>
}

type LyquidInfoResponse = {
  lyquidInfo?: { contract?: { value?: unknown } | unknown } | unknown
  lyquid_info?: { contract?: { value?: unknown } | unknown } | unknown
}

type EthereumProvider = {
  request: (request: { method: string; params?: unknown[] }) => Promise<unknown>
}

let rpcRequestId = 1

function nonEmptyString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null
}

function unwrapValue(value: unknown): string | null {
  if (typeof value === "object" && value !== null && "value" in value) {
    return nonEmptyString((value as { value?: unknown }).value)
  }
  return nonEmptyString(value)
}

function nodeId(value: unknown): string | null {
  const raw = unwrapValue(value)
  if (!raw) return null
  return raw.startsWith("Node-") ? raw : `Node-${raw}`
}

function nodeLabel(value: string): string {
  return value.replace(/^Node-/, "").trim().toLowerCase()
}

function nodeBaseToRpcUrl(nodeBaseUrl: string) {
  const url = new URL(nodeBaseUrl)
  url.protocol = url.protocol === "wss:" ? "https:" : url.protocol === "ws:" ? "http:" : url.protocol
  url.pathname = "/api"
  url.search = ""
  url.hash = ""
  return url.toString().replace(/\/$/, "")
}

function nodeBaseToWsUrl(nodeBaseUrl: string) {
  const url = new URL(nodeBaseUrl)
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:"
  url.pathname = "/ws"
  url.search = ""
  url.hash = ""
  return url.toString().replace(/\/$/, "")
}

function buildPeerBaseUrl(currentNodeBaseUrl: string, peerId: string) {
  const current = new URL(currentNodeBaseUrl)
  const [, ...suffix] = current.hostname.split(".")
  if (!suffix.length) throw new Error("The hosted node URL has no DNS suffix")
  current.hostname = `${nodeLabel(peerId)}.${suffix.join(".")}`
  current.pathname = "/"
  current.search = ""
  current.hash = ""
  return current.toString().replace(/\/$/, "")
}

async function serviceRequest<T>(nodeBaseUrl: string, method: "GetNodeInfo" | "GetPeers"): Promise<T> {
  const url = new URL(`/lyquor.node.v1.NodeService/${method}`, nodeBaseUrl)
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: "{}",
  })
  if (!response.ok) throw new Error(`${method} returned ${response.status}`)
  return response.json() as Promise<T>
}

async function ethRpc<T>(rpcUrl: string, method: string, params: unknown[]): Promise<T> {
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: rpcRequestId++, method, params }),
  })
  const body = await response.json() as { result?: T; error?: { message?: string } }
  if (!response.ok || body.error) throw new Error(body.error?.message ?? `${method} returned ${response.status}`)
  return body.result as T
}

async function ethCall(rpcUrl: string, contract: Address, data: Hex) {
  const blockTag = await ethRpc<Hex>(rpcUrl, "eth_blockNumber", [])
  if (!/^0x[\da-fA-F]+$/.test(blockTag)) throw new Error("eth_blockNumber returned an invalid block tag")
  return ethRpc<Hex>(rpcUrl, "eth_call", [{ to: contract, data }, blockTag])
}

function nodeIdToCommitteeKey(value: string): Hex {
  const input = value.replace(/^Node-/, "").trim().replace(/=+$/, "").toUpperCase()
  if (!input) throw new Error("Node ID is required")

  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  let bits = 0
  let bitCount = 0
  const bytes: number[] = []
  for (const character of input) {
    const decoded = alphabet.indexOf(character)
    if (decoded < 0) throw new Error("Node ID is not RFC 4648 Base32")
    bits = (bits << 5) | decoded
    bitCount += 5
    while (bitCount >= 8) {
      bitCount -= 8
      bytes.push((bits >> bitCount) & 0xff)
    }
  }
  if (bytes.length !== 35) throw new Error("Node ID must decode to exactly 35 bytes")
  return `0x${bytes.slice(0, 32).map((byte) => byte.toString(16).padStart(2, "0")).join("")}` as Hex
}

export async function loadOperatorRuntime(): Promise<OperatorRuntime> {
  const runtime = await loadHostedRuntimeContext()
  const response = await fetch(new URL("/lyquor.lyquid.v1.LyquidService/GetLyquidInfo", runtime.info.node_base_url), {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ lyquidId: { value: runtime.info.lyquid_id } }),
  })
  if (!response.ok) throw new Error(`GetLyquidInfo returned ${response.status}`)
  const payload = await response.json() as LyquidInfoResponse
  const info = payload.lyquidInfo ?? payload.lyquid_info
  const contract = unwrapValue(typeof info === "object" && info !== null && "contract" in info ? info.contract : null)
  if (!contract || !/^0x[\da-fA-F]{40}$/.test(contract)) throw new Error("GetLyquidInfo returned no active contract")
  return { ...runtime, contract: contract as Address, nodeBaseUrl: runtime.info.node_base_url }
}

export async function discoverHostedCluster(nodeBaseUrl: string, seedNodeId: string): Promise<OperatorNode[]> {
  const currentInfo = await serviceRequest<NodeInfoResponse>(nodeBaseUrl, "GetNodeInfo")
  const currentNodeId = nodeId(currentInfo.nodeId ?? currentInfo.node_id)
  if (!currentNodeId) throw new Error("GetNodeInfo returned no Node ID")
  const peers = await serviceRequest<PeersResponse>(nodeBaseUrl, "GetPeers")
  const requestedSeed = seedNodeId.trim() ? nodeId(seedNodeId) : currentNodeId
  if (!requestedSeed) throw new Error("Enter a valid Node ID")

  const ids = [...new Set([currentNodeId, requestedSeed, ...(peers.peers ?? []).flatMap((peer) => {
    const id = nodeId(peer.id)
    return id ? [id] : []
  })])]

  return Promise.all(ids.map(async (id): Promise<OperatorNode> => {
    const baseUrl = id.toLowerCase() === currentNodeId.toLowerCase() ? nodeBaseUrl : buildPeerBaseUrl(nodeBaseUrl, id)
    const rpcUrl = nodeBaseToRpcUrl(baseUrl)
    const wsUrl = nodeBaseToWsUrl(baseUrl)
    try {
      const info = await serviceRequest<NodeInfoResponse>(baseUrl, "GetNodeInfo")
      const authoritativeId = nodeId(info.nodeId ?? info.node_id)
      if (!authoritativeId) throw new Error("GetNodeInfo returned no Node ID")
      return { id: authoritativeId, rpcUrl, wsUrl, committeeKey: nodeIdToCommitteeKey(authoritativeId), reachable: true, issue: null, source: null, reporting: null }
    } catch (error) {
      return { id, rpcUrl, wsUrl, committeeKey: null, reachable: false, issue: error instanceof Error ? error.message : "Node unavailable", source: null, reporting: null }
    }
  }))
}

export async function readOperatorNodeState(node: OperatorNode, contract: Address): Promise<OperatorNode> {
  if (!node.reachable) return node
  try {
    const [sourceData, statusData] = await Promise.all([
      ethCall(node.rpcUrl, contract, encodeFunctionData({ abi: PRICE_FEED_OPERATOR_ABI, functionName: "get_price_source" })),
      ethCall(node.rpcUrl, contract, encodeFunctionData({ abi: PRICE_FEED_OPERATOR_ABI, functionName: "get_reporting_status" })),
    ])
    const source = decodeFunctionResult({ abi: PRICE_FEED_OPERATOR_ABI, functionName: "get_price_source", data: sourceData })
    const status = decodeFunctionResult({ abi: PRICE_FEED_OPERATOR_ABI, functionName: "get_reporting_status", data: statusData })
    return { ...node, source, reporting: { enabled: status[0], intervalMs: Number(status[1]) } }
  } catch (error) {
    return { ...node, source: null, reporting: null, issue: error instanceof Error ? error.message : "Contract state unavailable" }
  }
}

function getEthereumProvider(): EthereumProvider | null {
  const ethereum = (window as Window & { ethereum?: EthereumProvider }).ethereum
  return ethereum ?? null
}

export async function executeOperatorNetworkWrite({
  node,
  contract,
  functionName,
  args,
  account,
}: {
  node: OperatorNode
  contract: Address
  functionName: OperatorNetworkWrite
  args?: readonly unknown[]
  account: Address
}) {
  const provider = getEthereumProvider()
  if (!provider) throw new Error("Connect a browser wallet before submitting an operation")
  const data = encodeFunctionData({ abi: PRICE_FEED_OPERATOR_ABI, functionName, args: args as never })
  const txHash = await provider.request({ method: "eth_sendTransaction", params: [{ from: account, to: contract, data }] })
  if (typeof txHash !== "string" || !txHash.startsWith("0x")) throw new Error("Wallet did not return a transaction hash")
  const receipt = await waitForReceipt(node.rpcUrl, txHash as Hex)
  return { txHash: txHash as Hex, receipt }
}

export async function executeOperatorInstanceCall({
  node,
  contract,
  functionName,
  args,
}: {
  node: OperatorNode
  contract: Address
  functionName: OperatorInstanceCall
  args?: readonly unknown[]
}) {
  const data = encodeFunctionData({ abi: PRICE_FEED_OPERATOR_ABI, functionName, args: args as never })
  const result = await ethCall(node.rpcUrl, contract, data)
  const returned = decodeFunctionResult({ abi: PRICE_FEED_OPERATOR_ABI, functionName, data: result })
  if (returned !== true) throw new Error(`${functionName} returned false`)
  return returned
}

async function waitForReceipt(rpcUrl: string, hash: Hex) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const receipt = await ethRpc<Record<string, unknown> | null>(rpcUrl, "eth_getTransactionReceipt", [hash])
    if (receipt) {
      if (receipt.status === "0x0") throw new Error("Transaction reverted")
      return receipt
    }
    await new Promise((resolve) => window.setTimeout(resolve, 1_000))
  }
  throw new Error("Transaction receipt was not available from the selected node")
}
