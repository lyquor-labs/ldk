import { Freshness } from "@/components/freshness"
import type { MarketCandidate } from "@/interface"
import { shortStr } from "@/utils"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow, Tooltip, TooltipContent, TooltipTrigger } from "lyquor-shadcn"
import { ArrowUpRight, Info } from "lucide-react"
import { Link } from "react-router"
import { useEffect, useMemo, useState } from "react"
import { LatestQuoteCell } from "./latest-quote-cell"
import { JazzAvatar } from "@/components/jazzicon/jazzavatar"

const W_NAME = 0.4
const W_FRESH = 0.6

function nameScore(nodeId: string): number {
    let h = 0;
    for (let i = 0; i < nodeId.length; i++) {
        h = ((h << 5) - h) + nodeId.charCodeAt(i) | 0;
    }
    const unsignedH = h >>> 0;
    return (unsignedH % 10000) / 10000;
}
function freshnessScore(t?: number): number {
    return 0;
    if (t == null) return 0
    const timeDuration = Date.now() - t
    const raw = 100 - Math.min(100, timeDuration / 1000)
    return raw / 100
}

function scoreCandidate(c: MarketCandidate): number {
    return W_NAME * nameScore(c.nodeId) + W_FRESH * freshnessScore(c.t)
}

type TopProviderProps = {
    candidates: MarketCandidate[];
};

export const TopProvider = ({ candidates }: TopProviderProps) => {
    const [localByNodeId, setLocalByNodeId] = useState<Record<string, MarketCandidate>>({})

    useEffect(() => {
        setLocalByNodeId((prev) => {
            const next = { ...prev }
            for (const c of candidates) {
                next[c.nodeId] = c
            }
            return next
        })
    }, [candidates])

    const mergedCandidates = useMemo(() => Object.values(localByNodeId), [localByNodeId])
    const sortedCandidates = useMemo(
        () => [...mergedCandidates].sort((a, b) => scoreCandidate(b) - scoreCandidate(a)),
        [mergedCandidates],
    )

    return (
        <div className="h-[420px] min-h-[420px] overflow-y-auto">
            <Table>
                <TableHeader className="sticky top-0 z-10 bg-background">
                    <TableRow className="[&>th]:font-normal [&>th]:text-sm">
                        <TableHead>Name</TableHead>
                        <TableHead>Latest Quote</TableHead>
                        <TableHead>
                            <Tooltip>
                                <TooltipTrigger asChild>
                                    <div className="flex items-center gap-1">
                                        <span className="">Freshness</span>
                                        <Info className="size-3" />
                                    </div>
                                </TooltipTrigger>
                                <TooltipContent side="top" align="center" className="animate-none! max-w-[200px]" children={<span>
                                    Freshness of the latest provider quote decreases every second.
                                </span>} />
                            </Tooltip>
                        </TableHead>
                        <TableHead>Source</TableHead>
                        <TableHead className="text-right">Block</TableHead>
                    </TableRow>
                </TableHeader>
                <TableBody>
                    {sortedCandidates.length ? (
                        sortedCandidates.map((c) => {
                            return (
                                <TableRow key={c.nodeId}>
                                    <TableCell className="flex items-center gap-1 text-xs">
                                        <JazzAvatar
                                            address={c.nodeId}
                                            size={20}
                                            className="shrink-0"
                                        />
                                        {shortStr(c.nodeId, 6)}</TableCell>
                                    <TableCell>
                                        <LatestQuoteCell value={c.price} />
                                    </TableCell>
                                    <TableCell>
                                        <Freshness length={9} data={c} />
                                    </TableCell>
                                    <TableCell className="text-foreground/60 text-sm">{c.source ?? "—"}</TableCell>
                                    <TableCell>
                                        <Link className="flex items-center gap-1 justify-end text-foreground/60" to={c.chainPos?.blockNumber ? `/explorer/block/${parseInt(c.chainPos.blockNumber)}` : "#"}>
                                            <div>{parseInt(c.chainPos?.blockNumber) ?? "-"}</div>
                                            <ArrowUpRight className="size-4" strokeWidth={1.5} />
                                        </Link>
                                    </TableCell>
                                </TableRow>
                            );
                        })
                    ) : (
                        <TableRow>
                            <TableCell colSpan={5} className="text-sm text-foreground/60">
                                No candidates yet.
                            </TableCell>
                        </TableRow>
                    )}
                </TableBody>
            </Table>
        </div>
    )
}
