function readEnv(name: keyof ImportMetaEnv): string | null {
  const value = import.meta.env[name]
  return typeof value === "string" && value.trim() ? value.trim() : null
}

const priceFeedHostedOriginOverride = readEnv("VITE_PRICE_FEED_HOSTED_ORIGIN")

function isLocalBrowserOrigin() {
  if (typeof window === "undefined") {
    return false
  }

  return ["localhost", "127.0.0.1", "::1"].includes(window.location.hostname)
}

function priceFeedHostedOrigin(): string | null {
  if (!import.meta.env.DEV || !isLocalBrowserOrigin()) {
    return null
  }

  if (priceFeedHostedOriginOverride) {
    let origin: URL | null = null
    try {
      origin = new URL(priceFeedHostedOriginOverride)
    } catch {
      origin = null
    }
    if (origin && ["http:", "https:"].includes(origin.protocol)) return origin.href
  }

  return null
}

export function priceFeedHostedUrl(path: string): string {
  const origin = priceFeedHostedOrigin()
  return origin ? new URL(path, origin).href : path
}

export const dayjsFormat = 'MMM D, HH:mm:ss'
export const storePrefix = 'lyquor-price-feed-'
