import { Column } from "@/components/composition"
import { SketchReveal } from "@/components/sketch-reveal"
import { cn } from "lyquor-shadcn"
import { AnimatePresence, motion } from "framer-motion"
import { ArrowRight } from "lucide-react"
import { useEffect, useState } from "react"
import { Link } from "react-router"
import { cryptoIconUrls } from "virtual:price-feed-crypto-icons"

const CAROUSEL_ITEMS = [
  { id: "btc", origin: "/icons/sketch/BTC.png", reveal: cryptoIconUrls.BTC },
  { id: "eth", origin: "/icons/sketch/ETH.png", reveal: cryptoIconUrls.ETH },
  { id: "lyq", origin: "/icons/sketch/LYQ.png", reveal: cryptoIconUrls.LYQ },
  { id: "usdc", origin: "/icons/sketch/USDC.png", reveal: cryptoIconUrls.USDC },
  { id: "usdt", origin: "/icons/sketch/USDT.png", reveal: cryptoIconUrls.USDT },
]

function AvatarTitle() {
  const [currentIndex, setCurrentIndex] = useState(0)

  useEffect(() => {
    const interval = window.setInterval(() => {
      setCurrentIndex((current) => (current + 1) % CAROUSEL_ITEMS.length)
    }, 3000)
    return () => window.clearInterval(interval)
  }, [])

  const visibleGroup = Array.from({ length: 3 }, (_, index) => CAROUSEL_ITEMS[(currentIndex + index) % CAROUSEL_ITEMS.length])

  return (
    <Link to="/feeds" className="no-underline! group flex h-[200px] items-center gap-3">
      <div className="relative flex h-full w-[280px] items-center justify-center">
        <AnimatePresence mode="wait">
          <motion.div key={currentIndex} className="absolute inset-0" initial="initial" animate="animate" exit="exit">
            {visibleGroup.map((item, index) => {
              const xOffset = (index - 1) * 76
              const targetScale = index === 1 ? 1.1 : 0.9
              const yTarget = index === 1 ? "-60%" : "-50%"
              return (
                <motion.div
                  key={item.id}
                  className="absolute left-1/2 top-1/2"
                  style={{ zIndex: index === 1 ? 10 : 0, transformOrigin: "50% 100%" }}
                  variants={{
                    initial: { opacity: 0, scale: 0.5, x: "-50%", y: yTarget, filter: "blur(4px)" },
                    animate: {
                      opacity: 1,
                      scale: targetScale,
                      x: `calc(-50% + ${xOffset}px)`,
                      y: yTarget,
                      filter: "blur(0px)",
                      transition: { duration: 0.5, ease: [0.22, 1, 0.36, 1], delay: index * 0.08 },
                    },
                    exit: {
                      opacity: 0,
                      scale: 0.5,
                      x: "-50%",
                      y: yTarget,
                      filter: "blur(4px)",
                      transition: { duration: 0.3, ease: "easeIn", delay: (2 - index) * 0.05 },
                    },
                  }}
                >
                  <SketchReveal origin={item.origin} reveal={item.reveal} className="size-[150px]" size={135} />
                </motion.div>
              )
            })}
          </motion.div>
        </AnimatePresence>
      </div>
      <div className={cn("flex h-[110px] items-center gap-4 bg-foreground px-4 text-right text-3xl font-bold text-background font-expanded")}>
        <div>
          <p>Real-time data</p>
          <p>directly onchain</p>
        </div>
        <ArrowRight className="size-8 shrink-0 transition-transform duration-300 group-hover:translate-x-1" aria-hidden="true" />
      </div>
    </Link>
  )
}

export const Home = () => (
  <Column className="h-full pt-10">
    <div className="flex flex-col self-end px-6 text-right">
      <p className="text-xl font-medium font-expanded">Powered by Lyquor Labs.</p>
      <p className="text-xl font-medium font-expanded">Decentralized, verifiable, real-time</p>
    </div>
    <div className="flex flex-1 items-center justify-center -mt-10">
      <AvatarTitle />
    </div>
  </Column>
)
