import path from "path"
import { Buffer } from "node:buffer"
import { createHash } from "node:crypto"
import { readdirSync, readFileSync } from "fs"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig, type ConfigEnv, type Plugin } from "vite"
import { createHtmlPlugin } from 'vite-plugin-html'

// DO NOT MOVE!
const CRYPTO_ICON_MODULE_ID = "virtual:price-feed-crypto-icons"
const CRYPTO_ICON_RESOLVED_ID = `\0${CRYPTO_ICON_MODULE_ID}`

type CssAtRule = {
  toString: () => string
  remove: () => void
}

type CssDeclaration = {
  value: string
}

type CssRoot = {
  walkAtRules: (name: string, callback: (rule: CssAtRule) => void) => void
  walkDecls: (callback: (declaration: CssDeclaration) => void) => void
}

const systemFontPostcssPlugin = {
  postcssPlugin: "price-feed-use-system-fonts",
  Once(root: CssRoot) {
    root.walkAtRules("font-face", (rule) => {
      if (rule.toString().includes("TT_Commons")) {
        rule.remove()
      }
    })

    root.walkDecls((declaration) => {
      declaration.value = declaration.value
        .replace(
          /TTCommonsProMono,\s*TTCommonsPro,\s*Inter,\s*sans-serif/g,
          "ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif",
        )
        .replace(
          /TTCommonsProMono,\s*TTCommonsPro,\s*JetBrains Mono,\s*monospace/g,
          "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
        )
        .replace(
          /TTCommonsProMono,\s*TTCommonsPro,\s*monospace/g,
          "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
        )
    })
  },
}

function fingerprintCryptoIcons(): Plugin {
  const iconDir = path.resolve(__dirname, "./public/icons/crypto")
  let isBuild = false
  const icons = () => readdirSync(iconDir)
    .filter((file) => file.endsWith(".svg"))
    .map((file) => {
      const source = readFileSync(path.join(iconDir, file))
      const token = path.basename(file, ".svg").toUpperCase()
      const fileName = `icons/crypto/${token}.${createHash("sha256").update(source).digest("hex").slice(0, 12)}.svg`
      return { token, source, fileName }
    })

  return {
    name: "fingerprint-crypto-icons",
    configResolved(config) {
      isBuild = config.command === "build"
    },
    resolveId(id) {
      return id === CRYPTO_ICON_MODULE_ID ? CRYPTO_ICON_RESOLVED_ID : undefined
    },
    load(id) {
      if (id !== CRYPTO_ICON_RESOLVED_ID) return undefined
      const urls = Object.fromEntries(icons().map(({ token, fileName }) => [token, isBuild ? `/${fileName}` : `/icons/crypto/${token}.svg`]))
      return `export const cryptoIconUrls = ${JSON.stringify(urls)}`
    },
    generateBundle() {
      for (const { source, fileName } of icons()) {
        this.emitFile({ type: "asset", fileName, source })
      }
    },
  }
}

const hostedPaths = new Set([
  "/lyquid/info",
  "/lyquid/statusz",
  "/api/prices",
  "/api/price-head",
  "/api/price-updates",
  "/api/committee",
  "/api/config",
])

function createPriceFeedHostedDevProxy(): Plugin {
  return {
    name: "price-feed-hosted-dev-proxy",
    configureServer(server) {
      server.middlewares.use("/__price_feed_hosted__", async (request, response) => {
        try {
          const requestUrl = new URL(request.url ?? "/", "http://localhost")
          const rawTarget = requestUrl.searchParams.get("url")
          if (!rawTarget) {
            response.statusCode = 400
            response.end("Missing hosted Price Feed URL.")
            return
          }

          const target = new URL(rawTarget)
          if (!['http:', 'https:'].includes(target.protocol) || !hostedPaths.has(target.pathname)) {
            response.statusCode = 400
            response.end("Unsupported hosted Price Feed URL.")
            return
          }

          const upstream = await fetch(target, { headers: { accept: "application/json" } })
          const body = Buffer.from(await upstream.arrayBuffer())
          response.statusCode = upstream.status
          response.setHeader("cache-control", "no-store")
          response.setHeader("content-type", upstream.headers.get("content-type") ?? "application/json")
          response.end(body)
        } catch (error) {
          response.statusCode = 502
          response.setHeader("content-type", "application/json")
          response.end(JSON.stringify({ error: error instanceof Error ? error.message : String(error) }))
        }
      })
    },
  }
}

// https://vite.dev/config/
// @ts-expect-error Vite accepts this config shape; the plugin typing is narrower.
export default defineConfig(({ mode, command }: ConfigEnv) => {
  const isBuild = command === 'build'

  return {
    // Hosted Lyquids serve each app from its own vhost root. Root-relative
    // assets keep a client-side route such as `/feeds/BTC` from resolving its
    // bundle as `/feeds/assets/...`.
    base: '/',
    esbuild: {
      drop: isBuild ? ['console', 'debugger'] : [],
      legalComments: 'none',
    },

    build: {
      emptyOutDir: true,
      minify: 'esbuild',
      sourcemap: mode !== 'production',
      outDir: '../assets',
    },

    css: {
      postcss: {
        plugins: [systemFontPostcssPlugin],
      },
    },

    plugins: [
      createHtmlPlugin({
        minify: true,
        inject: {
          data: {
            title: 'Lyquor - Price Feed',
            description: 'Lyquor - Price Feed',
            url: 'https://lyquor.io',
            twitter: '@lyquor',
          },
        },
      }),
      fingerprintCryptoIcons(),
      createPriceFeedHostedDevProxy(),
      react(),
      tailwindcss()
    ],

    resolve: {
      alias: {
        "@": path.resolve(__dirname, "./src"),
      },
    },

  }
})
