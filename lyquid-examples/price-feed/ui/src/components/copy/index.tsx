import React, { useEffect, useState } from "react"
import c from "copy-to-clipboard"
import { CopyIcon, Check } from "lucide-react"
import { cn } from "lyquor-shadcn"

type CopyProps = {
  content: string
  timeoutMs?: number
  className?: string
  children?: React.ReactNode
  onCopied?: () => void
}

const Copy: React.FC<CopyProps> = ({
  content,
  timeoutMs = 1200,
  className = "",
  children,
  onCopied,
}) => {
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    if (!copied) return
    const id = setTimeout(() => setCopied(false), timeoutMs)
    return () => clearTimeout(id)
  }, [copied, timeoutMs])

  const handleCopy = () => {
    try {
      c(content)
      setCopied(true)
      onCopied?.()
    } catch {
      // ignore
    }
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      className={cn('inline outline-none hover:opacity-90 active:opacity-80 [&_svg]:ml-2 [&_svg]:size-3 cursor-pointer', className)}
      aria-label={copied ? "Copied" : "Copy"}
    >
      {children}
      {copied ? (
        <Check className="text-green-500 inline" />
      ) : (
        <CopyIcon className="text-muted-foreground inline" />
      )}
    </button>
  )
}

export default Copy
