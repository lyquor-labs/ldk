import { Freshness } from "@/components/freshness";
import { JazzAvatar } from "@/components/jazzicon/jazzavatar";
import { getNodeColor } from "@/components/jazzicon/utils";
import type { MarketAssetPoint, MarketCandidate } from "@/interface";
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "lyquor-shadcn";
import { fmtUsd, shortStr } from "@/utils";
import { ArrowUpRight, ChevronRight } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router";
import { NumberWithPrefix } from "@/components/number-with-prefix";
import { Bar, BarChart, Cell, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

const PAGE_SIZE = 5;
const MAX_PAGINATION_BUTTONS = 5;

type SnapshotDetailDialogProps = {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    payload: MarketAssetPoint | null;
};

function DeviationChartTooltip({ active, payload }: { active?: boolean; payload?: Array<{ payload: { nodeId: string; price: number; deviation: number; name: string } }> }) {
    if (!active || !payload?.length) return null;
    const p = payload[0].payload;
    return (
        <div className="rounded-md border bg-card px-3 py-2 text-sm shadow-md">
            <div className="font-mono">{p.name}</div>
            <div>Price: {fmtUsd(p.price)}</div>
            <div>Deviation:
            <NumberWithPrefix latter={0} former={p?.deviation}/></div>
        </div>
    );
}

function DeviationChart({
    candidates,
    matchedPrice,
}: {
    candidates: MarketCandidate[];
    matchedPrice: number;
}) {
    const chartData = useMemo(() => {
        const raw = candidates
            .filter((c) => c.price != null && typeof (c.price - matchedPrice) === "number")
            .map((c) => {
                const deviation = c.price - matchedPrice;
                return {
                    nodeId: c.nodeId,
                    price: c.price,
                    deviation,
                    color: getNodeColor(c.nodeId),
                    name: shortStr(c.nodeId, 6),
                };
            });
        const maxAbs = Math.max(...raw.map((d) => Math.abs(d.deviation)), 0.5);
        const minBarHeight = Math.min(maxAbs * 0.03, 0.5);
        const rawWithBar = raw.map((d) => ({
            ...d,
            barValue: d.deviation === 0 ? minBarHeight : d.deviation,
        }));
        const sorted = [...rawWithBar].sort((a, b) => Math.abs(a.deviation) - Math.abs(b.deviation));
        const left = sorted.filter((_, i) => i >= 1 && i % 2 === 1);
        const right = sorted.filter((_, i) => i >= 2 && i % 2 === 0);
        return [...left, sorted[0], ...right].filter(Boolean);
    }, [candidates, matchedPrice]);

    const yDomain = useMemo(() => {
        if (!chartData.length) return [-1, 1];
        const maxAbs = Math.max(
            ...chartData.map((d) => Math.abs(d.deviation)),
            0.5,
        );
        const pad = Math.max(maxAbs * 0.1, 0.5);
        const bound = maxAbs + pad;
        return [-bound, bound];
    }, [chartData]);

    return (
        <div className="w-full h-[220px]">
            <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} margin={{ top: 8, right: 8, bottom: 8, left: 8 }}>
                    <XAxis dataKey="name" hide height={0} />
                    <YAxis type="number" dataKey="barValue" domain={yDomain} hide width={0} />
                    <Tooltip content={<DeviationChartTooltip />} cursor={false} />
                    <ReferenceLine y={0} stroke="var(--border)" strokeWidth={1} />
                    <Bar dataKey="barValue" radius={[2, 2, 0, 0]} barSize={24}>
                        {chartData.map((entry) => (
                            <Cell key={entry.nodeId} fill={entry.color} />
                        ))}
                    </Bar>
                </BarChart>
            </ResponsiveContainer>
        </div>
    );
}

export function SnapshotDetailDialog({
    open,
    onOpenChange,
    payload,
}: SnapshotDetailDialogProps) {
    const [page, setPage] = useState(0);
    const candidates = useMemo(() => payload?.candidates ?? [], [payload]);
    const totalPages = Math.max(1, Math.ceil(candidates.length / PAGE_SIZE));
    const pageCandidates = useMemo(
        () =>
            candidates.slice(page * PAGE_SIZE, page * PAGE_SIZE + PAGE_SIZE),
        [candidates, page],
    );
    const matchedPrice = payload?.price ?? 0;

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="max-h-[90vh] overflow-y-auto !max-w-3xl px-0! py-3">
                <DialogHeader className="px-3">
                    <DialogTitle>Detail</DialogTitle>
                </DialogHeader>
                {payload ? (
                    <div className="space-y-4">
                        <div className="relative border-t border-b">
                            <DeviationChart
                                candidates={candidates}
                                matchedPrice={matchedPrice}
                            />
                        </div>
                        <div className="flex flex-col">

                            <div className="flex items-center justify-between ">
                                <div className="text-base ml-2 px-3">
                                    Price {fmtUsd(matchedPrice)}
                                </div>
                                {totalPages > 1 ? (
                                    <div className="flex items-center gap-1">
                                        {Array.from({ length: Math.min(MAX_PAGINATION_BUTTONS, totalPages) }, (_, i) => {
                                            const base = totalPages <= MAX_PAGINATION_BUTTONS
                                                ? 0
                                                : Math.max(0, Math.min(page, totalPages - MAX_PAGINATION_BUTTONS));
                                            const pageIndex = base + i;
                                            if (pageIndex >= totalPages) return null;
                                            const isActive = pageIndex === page;
                                            return (
                                                <button
                                                    key={pageIndex}
                                                    type="button"
                                                    className={`min-w-[28px] h-7 rounded text-sm ${isActive
                                                        ? "bg-foreground text-background"
                                                        : "hover:bg-muted"}`}
                                                    onClick={() => setPage(pageIndex)}
                                                >
                                                    {pageIndex + 1}
                                                </button>
                                            );
                                        })}
                                        <button
                                            type="button"
                                            className="p-1 rounded hover:bg-muted disabled:opacity-50"
                                            disabled={page >= totalPages - 1}
                                            onClick={() =>
                                                setPage((p) =>
                                                    Math.min(totalPages - 1, p + 1),
                                                )
                                            }
                                            aria-label="Next page"
                                        >
                                            <ChevronRight className="size-4" />
                                        </button>
                                    </div>
                                ) : null}
                            </div>
                            <div className="px-3">
                                <Table>
                                    <TableHeader>
                                        <TableRow className="[&>th]:font-normal [&>th]:text-sm">
                                            <TableHead>Name</TableHead>
                                            <TableHead>Quote</TableHead>
                                            <TableHead>Freshness</TableHead>
                                            <TableHead>Margin</TableHead>
                                            <TableHead>Source</TableHead>
                                            <TableHead className="text-right">Block</TableHead>
                                        </TableRow>
                                    </TableHeader>
                                    <TableBody>
                                        {pageCandidates.map((c) => {
                                            const blockNumber = c.chainPos?.blockNumber;
                                            return (
                                                <TableRow key={c.nodeId}>
                                                    <TableCell>
                                                        <div className="flex items-center gap-1">
                                                            <JazzAvatar
                                                                address={c.nodeId}
                                                                size={20}
                                                                className="shrink-0"
                                                            />
                                                            <span className="">
                                                                {shortStr(c.nodeId, 14)}
                                                            </span>
                                                        </div>
                                                    </TableCell>
                                                    <TableCell>
                                                        {fmtUsd(c.price)}
                                                    </TableCell>
                                                    <TableCell>
                                                        <Freshness
                                                            depData={payload}
                                                            length={8}
                                                            data={c}
                                                        />
                                                    </TableCell>
                                                    <TableCell className="">
                                                        <NumberWithPrefix
                                                            former={c.price}
                                                            latter={matchedPrice}
                                                        />
                                                    </TableCell>
                                                    <TableCell className="">
                                                        {c.source || '-'}
                                                    </TableCell>
                                                    <TableCell className="text-muted-foreground text-right">

                                                        <Link
                                                            className="inline-flex items-center gap-0.5 hover:underline"
                                                            to={blockNumber ? `/explorer/block/${parseInt(blockNumber)}` : "#"}
                                                        >
                                                            {parseInt(blockNumber) || '-'}
                                                            <ArrowUpRight className="size-3 shrink-0" />
                                                        </Link>

                                                    </TableCell>
                                                </TableRow>
                                            );
                                        })}
                                    </TableBody>
                                </Table>
                            </div>
                        </div>
                    </div>
                ) : (
                    <p className="text-sm text-muted-foreground">
                        No snapshot data.
                    </p>
                )}
            </DialogContent>
        </Dialog>
    );
}
