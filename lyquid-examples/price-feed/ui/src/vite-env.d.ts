/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_PRICE_FEED_HOSTED_ORIGIN?: string
}

declare module "virtual:price-feed-crypto-icons" {
  export const cryptoIconUrls: Record<string, string>
}
