import { ColumnField } from "@/components/composition";
import { CryptoIcons } from "@/components/crypto-icons";
import { TrendIcon } from "@/components/icons";
import { NumberWithPrefix } from "@/components/number-with-prefix";
import { useMarketStore } from "@/stores/market-store";
import {
  cn,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuTrigger,
} from "lyquor-shadcn";
import dayjs from "dayjs";
import { ChevronRight } from "lucide-react";
import { useState } from "react";
import { fmtUsd } from "@/utils";
import { BigNumber } from "bignumber.js";
import { NumberSwitchWithColor } from "@/components/number-switch-with-color";
import { usePrevious } from "ahooks";

type PriceBarProps = {
  asset: string;
  assets?: string[];
  onSelectAsset?: (asset: string) => void;
  price?: number | null;
  confidence?: number | null; // 0..1
  lastUpdatedMs?: number | null;
};

export const PriceBar = ({
  asset,
  assets,
  onSelectAsset,
  price,
  confidence,
  lastUpdatedMs,
}: PriceBarProps) => {
  const prevPrice = usePrevious(price);
  const trendingUp = BigNumber(price).gte(prevPrice);

  const [dropdownOpen, setDropdownOpen] = useState(false);
  const { tickers } = useMarketStore();
  return (
    <div className="flex items-center gap-12 py-4 px-6">
      <DropdownMenu open={dropdownOpen} onOpenChange={setDropdownOpen}>
        <DropdownMenuTrigger asChild>
          <div className="flex items-center gap-3 group">
            <CryptoIcons token={asset} size={24} />
            <ColumnField
              className="gap-0"
              title={<div className="flex items-center gap-1">
                <span className="text-sm">{asset}/USD</span>
                <div className={cn("group-hover:bg-foreground group-hover:text-background text-foreground/60", dropdownOpen ? 'bg-foreground text-background' : '')}>
                  <ChevronRight
                    className={cn("size-3.5", dropdownOpen ? "rotate-270" : "rotate-90")}
                  />
                </div>
              </div>}
            >
              <div className="flex items-center gap-1">
                <span className="text-lg">{fmtUsd(price)}</span>
                {!!price && !!prevPrice && (
                  <TrendIcon className="size-4" trendingUp={trendingUp} />
                )}
              </div>
            </ColumnField>
            {/* <div className={cn("bg-muted-foreground/60 group-hover:bg-foreground p-1 text-background", dropdownOpen ? 'bg-foreground' : '')}>
              <ArrowRight
                className={cn("size-3.5", dropdownOpen ? "rotate-270" : "rotate-90")}
              />
            </div> */}
          </div>
        </DropdownMenuTrigger>

        <DropdownMenuContent
          disablePortal
          sideOffset={20}
          alignOffset={-20}
          align="start"
          className="w-[400px]"
        >
          <>
            {assets?.length ? (
              <DropdownMenuGroup className="flex flex-col items-center gap-0 px-0 py-1">
                <DropdownMenuLabel className="w-full">
                  <div className="flex items-center justify-center gap-3 w-full text-sm text-muted-foreground">
                    <div className="w-full max-w-[60px] flex items-center gap-1">
                      Asset
                    </div>
                    <div className="w-full max-w-[90px]">Price</div>
                    <div className="flex-1">Range</div>
                    <div className="flex-2 text-right whitespace-nowrap">
                      Last Updated
                    </div>
                  </div>
                </DropdownMenuLabel>
                {assets.map((a) => (
                  <DropdownMenuItem
                    key={a}
                    onClick={() => onSelectAsset?.(a)}
                    className="w-full h-[42px]"
                  >
                    <div className="flex items-center justify-center gap-3 w-full text-sm">
                      <div className="w-full max-w-[60px] flex items-center gap-1">
                        <CryptoIcons token={a} size={16} />
                        <span className="">{a}</span>
                      </div>
                      <div className="w-full max-w-[90px]">
                        <NumberSwitchWithColor
                          value={tickers[a]?.price}
                          className=""
                        >
                          <>
                            {fmtUsd(tickers[a]?.price)}
                          </>
                        </NumberSwitchWithColor>
                      </div>
                      <div className="flex-1">
                        <div className="flex flex-col scale-[0.9] gap-1">
                          <NumberWithPrefix
                            className="leading-none "
                            former={tickers[a]?.high}
                            latter={tickers[a]?.price}
                          />
                          <NumberWithPrefix
                            className="leading-none "
                            former={tickers[a]?.low}
                            latter={tickers[a]?.price}
                          />
                        </div>
                      </div>
                      <div className="flex-2 text-right">
                        <span className="text-xs tracking-tighter text-muted-foreground">
                          {tickers[a]?.t ? dayjs(tickers[a]?.t).format("HH:mm:ss") : "-"}
                        </span>
                      </div>
                    </div>
                  </DropdownMenuItem>
                ))}
              </DropdownMenuGroup>
            ) : null}
          </>
        </DropdownMenuContent>
      </DropdownMenu>

      <div className="flex items-center gap-8">
        <ColumnField
          title={<span className="text-xs text-foreground/60">Confidence</span>}
        >
          <span>
            {confidence == null ? "-" : `${(confidence * 100).toFixed(2)}%`}
          </span>
        </ColumnField>

        <ColumnField
          title={
            <span className="text-xs text-foreground/60">last updated</span>
          }
        >
          <span>
            {lastUpdatedMs
              ? dayjs(lastUpdatedMs).format("HH:mm:ss MMM D")
              : "-"}
          </span>
        </ColumnField>
      </div>
    </div>
  );
};
