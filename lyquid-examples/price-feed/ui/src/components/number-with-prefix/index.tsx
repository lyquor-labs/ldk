import { cn } from "@/lib/utils";
import { BigNumber } from "bignumber.js";

export const NumberWithPrefix = ({ former, latter, className }: { former: number, latter: number, className?: string }) => {
  const prefix = former >= latter ? "+" : "-";
  const value = BigNumber(former).minus(latter).abs().toFixed(2, BigNumber.ROUND_DOWN);
  return (
    <div className={cn("whitespace-nowrap", former >= latter ? "text-green-500" : "text-red-500", className)}>
      {prefix}{(!!Number(value) || Number(value) == 0) ? value : ""}
    </div>
  );
};