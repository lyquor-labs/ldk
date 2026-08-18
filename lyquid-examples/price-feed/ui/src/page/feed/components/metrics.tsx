import { Between, Column } from "@/components/composition"
import { shortStr } from "@/utils"

type MetricsProps = {
    contractAddress?: string | null;
    version?: string | null;
    providersOnline?: number | null;
    providersTotal?: number | null;
    minimumProviders?: number | null;
    observedUpdateInterval?: string | null;
};

export const Metrics = ({
    contractAddress,
    version,
    providersOnline,
    providersTotal,
    minimumProviders,
    observedUpdateInterval,
}: MetricsProps) => {
    return (
        <Column className="gap-3">
            <Between>
                <div className="flex items-center gap-2">
                    <span className="">Contract</span>
                </div>
                <div className="font-mono text-sm">{contractAddress ? shortStr(contractAddress, 12) : "-"}</div>
            </Between>

            <Between>
                <div className="flex items-center gap-2">
                    <span className="">Version</span>
                </div>
                <div>{version ? `v${version}` : "-"}</div>
            </Between>

            <Between>
                <div className="flex items-center gap-2">
                    <span className="">Providers</span>
                </div>
                <div>
                    {providersOnline == null || providersTotal == null ? "-" : `${providersOnline}/${providersTotal}`}
                </div>
            </Between>

            <Between>
                <div className="flex items-center gap-2">
                    <span className="">Minimum Providers</span>
                </div>
                <div>{minimumProviders ?? "-"}</div>
            </Between>

            <Between>
                <div className="flex items-center gap-2">
                    <span className="">Observed update interval</span>
                </div>
                <div>{observedUpdateInterval ?? "-"}</div>
            </Between>
        </Column>
    )
}
