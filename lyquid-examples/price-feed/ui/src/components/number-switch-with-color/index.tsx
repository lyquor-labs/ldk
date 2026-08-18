import { cn } from "lyquor-shadcn";
import { usePrevious } from "ahooks";
import { BigNumber } from "bignumber.js";

export const NumberSwitchWithColor = ({
  value,
  children,
  className,
}: {
  value: number;
  children: React.ReactNode;
  className?: string;
}) => {
  const prev = usePrevious(value);
  const trendingUp = BigNumber(value).gte(prev);
  return (
    <div
      className={cn(
        "whitespace-nowrap",
        (!!value && !!prev) ? trendingUp ? "text-green-500" : "text-red-500" : "",
        className,
      )}
    >
      {children}
    </div>
  );
};
