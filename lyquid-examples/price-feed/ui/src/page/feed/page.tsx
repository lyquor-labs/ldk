import { Column } from "@/components/composition";
import { ConfidenceChart } from "@/page/feed/components/composed-chart";
import { Metrics } from "@/page/feed/components/metrics";
import { PriceBar } from "@/page/feed/components/price-bar";
import { Source } from "@/page/feed/components/source";
import { TopProvider } from "@/page/feed/components/top-provider";
import { useMarketSentiment } from "@/hooks/use-market-sentiment";
import { useMarketStore } from "@/stores/market-store";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "lyquor-shadcn";

const formatObservedInterval = (intervalMs: number | null) => {
  if (intervalMs == null) return null
  if (intervalMs < 1_000) return `${Math.round(intervalMs)}ms`
  return `${(intervalMs / 1_000).toFixed(intervalMs < 10_000 ? 1 : 0)}s`
}

export const FeedPage = () => {
  const { selectedAsset, setSelectedAsset, assets } = useMarketStore();
  const { config, error, history, latest, nodeIds, runtime, observedUpdateIntervalMs, pollIntervalMs } = useMarketSentiment();

  const latestAsset = latest;
  const confidence =
    latestAsset && nodeIds.length
      ? latestAsset.candidates.length / nodeIds.length
      : null;

  return (
    <div className="flex h-[calc(100dvh-64px)] flex-col overflow-hidden">
      <div className="shrink-0 border-b">
        <PriceBar
          asset={selectedAsset}
          assets={[...assets]}
          onSelectAsset={setSelectedAsset}
          price={latestAsset?.price ?? null}
          confidence={confidence}
          lastUpdatedMs={latest?.t ?? null}
        />
      </div>

      <div className="flex min-h-0 flex-1 overflow-hidden">
        <Column className="min-h-0 flex-16 border-b gap-0">
          <div className="relative h-full [&>div]:h-full">
            <ConfidenceChart data={history} totalNodeCount={nodeIds.length} pollIntervalMs={pollIntervalMs} key={selectedAsset}/>
            {error ? (
              <div className="absolute bottom-4 left-6 text-sm text-foreground/70">
                Unable to load the hosted Price Feed context: {error.message}
              </div>
            ) : null}
          </div>
        </Column>
        <Column className="min-h-0 flex-9 overflow-y-auto border-l gap-0">
          <Accordion type="multiple" defaultValue={["top-providers"]} className="w-full">
            <AccordionItem value="source" className="shrink-0 px-3">
              <AccordionTrigger className="py-5 text-foreground/60 hover:no-underline">Source</AccordionTrigger>
              <AccordionContent className="max-h-[144px] overflow-y-auto pb-5"><Source sources={config?.sources ?? []} candidates={latestAsset?.candidates ?? []} /></AccordionContent>
            </AccordionItem>
            <AccordionItem value="metrics" className="shrink-0 px-3">
              <AccordionTrigger className="py-5 text-foreground/60 hover:no-underline">Metrics</AccordionTrigger>
              <AccordionContent className="max-h-[176px] overflow-y-auto pb-5"><Metrics contractAddress={runtime?.info.backend_contract ?? null} version={config?.version} providersOnline={latestAsset?.candidates?.length ?? null} providersTotal={nodeIds.length || null} minimumProviders={config?.committee.threshold} observedUpdateInterval={formatObservedInterval(observedUpdateIntervalMs)} /></AccordionContent>
            </AccordionItem>
            <AccordionItem value="top-providers" className="shrink-0 px-3">
              <AccordionTrigger className="py-5 text-foreground/60 hover:no-underline">Top Providers</AccordionTrigger>
              <AccordionContent className="pb-5"><TopProvider candidates={latestAsset?.candidates ?? []} /></AccordionContent>
            </AccordionItem>
          </Accordion>
        </Column>
      </div>
    </div>
  );
};
