import { storePrefix } from "@/constants";
import type { MarketAsset, MarketTicker } from "@/interface";
import { MARKET_ASSETS } from "@/interface";
import { create } from "zustand";
import { persist } from "zustand/middleware";

export type { MarketAsset, MarketTicker };

const pick = <T, K extends keyof T>(obj: T, keys: K[]): Pick<T, K> => {
  return keys.reduce((acc, key) => {
    acc[key] = obj[key];
    return acc;
  }, {} as Pick<T, K>);
};

type MarketStoreState = {
  assets: MarketAsset[];
  setAssets: (assets: MarketAsset[]) => void;

  selectedAsset: MarketAsset;
  _setSelectedAsset: (asset: MarketAsset) => void;
  setSelectedAsset: (asset: MarketAsset) => void;

  pollIntervalMs: number;
  setPollIntervalMs: (ms: number) => void;

  historyCount: number;
  setHistoryCount: (n: number) => void;

  maxTickSizeReserveLimit: number;
  setMaxTickSizeReserveLimit: (n: number) => void;

  tickers: Record<MarketAsset, MarketTicker>;
  setTickers: (tickers: Record<MarketAsset, MarketTicker>) => void;
};

const needPersistFields: (keyof MarketStoreState)[] = [
  "historyCount",
  "pollIntervalMs",
  "maxTickSizeReserveLimit",
];

export const useMarketStore = create<MarketStoreState>()(
  persist(
    (set) => ({
      assets: MARKET_ASSETS as unknown as MarketAsset[],
      setAssets: (assets) => set({ assets }),

      tickers: {},
      setTickers: (tickers) => set({ tickers }),

      selectedAsset: "BTC",
      _setSelectedAsset: (asset) => set({ selectedAsset: asset }),
      setSelectedAsset: (asset) => {
        dispatchEvent(new CustomEvent('asset-selected', { detail: asset }))
      },

      pollIntervalMs: 1_000,
      setPollIntervalMs: (ms) =>
        set({
          pollIntervalMs: Math.max(1_000, Math.min(60_000, Number(ms) || 1_000)),
        }),

      historyCount: 300,
      setHistoryCount: (n) =>
        set({ historyCount: Math.max(1, Math.min(1_000, Number(n) || 300)) }),

      maxTickSizeReserveLimit: 10_000,
      setMaxTickSizeReserveLimit: (n) =>
        set({ maxTickSizeReserveLimit: Math.max(1, Number(n) || 10_000) }),
    }),
    {
      name: `${storePrefix}market`,
      version: 2,
      partialize: (state) => {
        return pick(state, needPersistFields);
      },

    },
  ),
);
