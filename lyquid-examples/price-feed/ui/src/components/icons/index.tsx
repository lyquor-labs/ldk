import { cn } from "@/lib/utils";
import { TrendingDown, TrendingUp } from "lucide-react";

export const TrendIcon = ({ trendingUp, className }: { trendingUp: boolean; className?: string }) => {
  return trendingUp ? (
    <TrendingUp className={cn("text-green-500 size-4", className)} />
  ) : (
    <TrendingDown className={cn("text-red-500 size-4", className)} />
  );
};
