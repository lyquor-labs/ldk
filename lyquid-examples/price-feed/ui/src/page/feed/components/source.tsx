import { Between, Column } from "@/components/composition"
import type { MarketCandidate } from "@/interface"
import { Check } from "lucide-react"

type SourceProps = {
    sources: string[];
    candidates: MarketCandidate[];
};

function sourceLabel(source: string): string {
    return source.replace(/(^|[-_])(.)/g, (_, __, character: string) => character.toUpperCase())
}

export const Source = ({ sources, candidates }: SourceProps) => {
    // The oracle candidates are still trustworthy source metadata when the
    // configuration endpoint is briefly unavailable.
    const displayedSources = sources.length
        ? sources
        : [...new Set(candidates.map((candidate) => candidate.source).filter((source): source is string => Boolean(source)))];

    return (
        <Column className="gap-3">
            {displayedSources.length ? displayedSources.map((source) => {
                const providerCount = candidates.filter((candidate) => candidate.source === source).length
                return (
                    <Between key={source}>
                        <div className="flex items-center gap-2">
                            <Check className="size-4 text-green-500"/>
                            <span>{sourceLabel(source)}</span>
                        </div>
                        <div>{providerCount} provider{providerCount === 1 ? "" : "s"}</div>
                    </Between>
                )
            }) : (
                <div className="text-sm text-foreground/60">No source data yet.</div>
            )}
        </Column>
    )
}
