import { useMemo, useState } from "react"
import { fmtUsd } from "@/utils"

export function LatestQuoteCell({ value }: { value: number }) {
    const [prevValue, setPrevValue] = useState(0)

    const ifShouldFlash = useMemo(() => {
        return prevValue != value
    }, [prevValue, value])

    const handleAnimationEnd = async () => {
        // await sleep(400)
        setPrevValue(value)
    }

    return (
        <div onAnimationEnd={handleAnimationEnd}
            style={{
                animationName: ifShouldFlash ? "flash" : "none",
                animationDuration: "400ms",
                animationFillMode: "forwards",
                animationTimingFunction: "linear",
            }}
        >
            {fmtUsd(value)}
        </div>
    )
}
