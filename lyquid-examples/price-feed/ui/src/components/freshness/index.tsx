import { Progress } from "@/components/progress";
import { Tooltip, TooltipTrigger, TooltipContent } from "lyquor-shadcn";
import { useInterval } from "ahooks";
import dayjs from "dayjs";
import { useEffect, useMemo, useState } from "react";


function calcFreshness(timeDuration: number, n = 1_000) {
    return 100 - Math.min(100, timeDuration / n);
}

const interval = 1000;
type FreshnessData = {
    timestamp?: number;
    t?: number;
};

const BaseFreshness = ({
    data,
    depData,
    length = 9,
}: {
    data: FreshnessData;
    depData?: FreshnessData;
    length?: number;
}) => {
    const [timeDuration, setTimeDuration] = useState(0);

    const clear = useInterval(() => {
        const t = data?.timestamp ?? data?.t;
        if (t) {
            const depT = depData?.timestamp || depData?.t || Date.now();
            setTimeDuration(depT - t);
        } else {
            setTimeDuration(Infinity);
        }
    }, interval);

    const percentage = useMemo(() => {
        return calcFreshness(timeDuration, interval);
    }, [timeDuration]);

    useEffect(() => {
        return () => {
            clear();
        };
    }, [clear]);

    return <Progress length={length} percentage={percentage} />;
};

export const Freshness = ({
    depData,
    data,
    length = 9,
}: {
    data: FreshnessData;
    depData?: FreshnessData;
    length?: number;
}) => {
    return (
        <Tooltip>
            <TooltipTrigger asChild>
                <div className="h-5 flex flex-col justify-center w-fit">
                    <BaseFreshness length={length} data={data} depData={depData} />
                </div>
            </TooltipTrigger>
            <TooltipContent
                side="top"
                align="center"
                className="animate-none!"
                updatePositionStrategy="optimized"
                children={
                    <span>
                        Last updated:
                        <br /> {dayjs(data?.timestamp ?? data?.t).format("YYYY-MM-DD HH:mm:ss")}
                    </span>
                }
            />
        </Tooltip>
    );
};
