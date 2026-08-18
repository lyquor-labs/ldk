import { JazzAvatar } from "@/components/jazzicon/jazzavatar"
import { dayjsFormat } from "@/constants"
import type { MarketAssetPoint } from "@/interface"
import { useThemeStore } from "@/stores/theme-store"
import { addOklchAlpha, fmtUsd, getColorVariable, shortStr } from "@/utils"
import dayjs from "dayjs"
import { Loader2, Radio, RotateCcw, ZoomInIcon, ZoomOutIcon } from "lucide-react"
import { useCallback, useEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent } from "react"
import { Area, CartesianGrid, ComposedChart, Customized, Line, ResponsiveContainer, XAxis, YAxis } from "recharts"
import { SnapshotDetailDialog } from "./snapshot-detail-dialog"

const Y_AXIS_WIDTH = 66
const X_AXIS_HEIGHT = 30
const DEFAULT_WINDOW_MS = 30 * 60_000
const MIN_WINDOW_MS = 5_000
const MAX_WINDOW_MS = 30 * 24 * 60 * 60_000
const TARGET_VISIBLE_POINT_COUNT = 60
// Stale views reserve the rightmost 30% for the elapsed future period and the
// last-known guide. That keeps the final real quote in a readable focal area
// instead of pinning it to the right edge.
const STALE_LAST_POINT_FRACTION = 0.7
const LIVE_FUTURE_FRACTION = 1 - STALE_LAST_POINT_FRACTION
const PAN_SENSITIVITY = 2
const WHEEL_ZOOM_RATE = 0.001
const DRAG_START_THRESHOLD_PX = 4
const TIME_TICK_STEPS_MS = [
  1_000, 2_000, 5_000, 10_000, 15_000, 30_000,
  60_000, 2 * 60_000, 5 * 60_000, 10 * 60_000, 15 * 60_000, 30 * 60_000,
  60 * 60_000, 2 * 60 * 60_000, 3 * 60 * 60_000, 6 * 60 * 60_000, 12 * 60 * 60_000,
  24 * 60 * 60_000, 2 * 24 * 60 * 60_000, 7 * 24 * 60 * 60_000,
]

type FeedState = "live" | "delayed" | "stale" | "recovered"
type CurveType = "natural" | "monotone" | "linear"
type ChartDatum = MarketAssetPoint & { isGap?: boolean }
type GapGuide = { from: MarketAssetPoint; to: MarketAssetPoint }
type ChartAxis = { scale?: (value: number) => number }
type ChartOffset = { left: number; top: number; width: number; height: number }
type ChartPoint = { x?: number; y?: number; payload?: ChartDatum }
type FormattedGraphicalItem = { item?: { type?: { displayName?: string } }; props?: { points?: ChartPoint[] } }
type CursorPosition = { x: number; y: number }
type FocusedPoint = { point: ChartDatum; x: number; y: number }
type LastKnownGuideProps = {
  latest?: MarketAssetPoint
  viewportEnd?: number
  stroke: string
  opacity: number
  showFutureGuide?: boolean
  historicalGaps?: GapGuide[]
  xAxisMap?: Record<string, ChartAxis>
  yAxisMap?: Record<string, ChartAxis>
  offset?: ChartOffset
  formattedGraphicalItems?: FormattedGraphicalItem[]
}
type CursorAxisReadoutProps = {
  cursor?: CursorPosition | null
  xDomain: [number, number]
  yDomain: [number, number]
  offset?: ChartOffset
  stroke: string
  textColor: string
  backgroundColor: string
  borderColor: string
  formatTime: (value: number) => string
}

const formatValue = (value: number) => value.toFixed(2)
const formatAge = (ageMs: number) => {
  const seconds = Math.max(0, Math.floor(ageMs / 1_000))
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3_600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`
  if (seconds < 86_400) return `${Math.floor(seconds / 3_600)}h ${Math.floor((seconds % 3_600) / 60)}m`
  return `${Math.floor(seconds / 86_400)}d ${Math.floor((seconds % 86_400) / 3_600)}h`
}
const stateFor = (ageMs: number, pollIntervalMs: number): Exclude<FeedState, "recovered"> => {
  const cadence = Math.max(1_000, pollIntervalMs)
  if (ageMs <= cadence * 2) return "live"
  if (ageMs <= cadence * 8) return "delayed"
  return "stale"
}
const yDomain = (points: MarketAssetPoint[]): [number, number] => {
  const values = points.flatMap((point) => [point.low, point.high, point.price]).filter(Number.isFinite)
  if (!values.length) return [0, 100]
  const min = Math.min(...values)
  const max = Math.max(...values)
  const span = Math.max(max - min, Math.abs(max) * 0.002, 0.01)
  return [min - span * 0.15, max + span * 0.15]
}
const easeOutCubic = (progress: number) => 1 - (1 - progress) ** 3
const stableTicks = (min: number, max: number, step: number) => {
  if (!Number.isFinite(min) || !Number.isFinite(max) || !Number.isFinite(step) || step <= 0 || max <= min) return []
  const epsilon = step * 1e-9
  const precision = Math.max(0, Math.ceil(-Math.log10(step)) + 2)
  const ticks: number[] = []
  for (let value = Math.ceil((min - epsilon) / step) * step; value <= max + epsilon && ticks.length < 32; value += step) {
    ticks.push(Number(value.toFixed(precision)))
  }
  return ticks
}
const timeTickStep = (rangeMs: number) => TIME_TICK_STEPS_MS.find((step) => rangeMs / step <= 6) ?? TIME_TICK_STEPS_MS.at(-1)!
const priceTickStep = (range: number) => {
  const rawStep = Math.max(range / 6, Number.EPSILON)
  const magnitude = 10 ** Math.floor(Math.log10(rawStep))
  const normalized = rawStep / magnitude
  const niceNormalized = normalized <= 1 ? 1 : normalized <= 2 ? 2 : normalized <= 2.5 ? 2.5 : normalized <= 5 ? 5 : 10
  return niceNormalized * magnitude
}
const median = (values: number[]) => {
  if (!values.length) return 0
  const sorted = [...values].sort((a, b) => a - b)
  const middle = Math.floor(sorted.length / 2)
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2
}

// The guide intentionally is not a data series. It uses Recharts' actual
// scale/plot offset so it shares the exact same coordinates as the line and
// Tooltip, while still surviving a clipped or downsampled final data point.
const LastKnownGuide = ({ latest, viewportEnd, stroke, opacity, showFutureGuide = true, historicalGaps, xAxisMap, yAxisMap, offset, formattedGraphicalItems }: LastKnownGuideProps) => {
  if (!latest || !viewportEnd || !offset) return null
  const xScale = Object.values(xAxisMap ?? {})[0]?.scale
  const yScale = Object.values(yAxisMap ?? {})[0]?.scale
  if (!xScale || !yScale) return null

  const left = offset.left
  const right = offset.left + offset.width
  const bottom = offset.top + offset.height
  const historicalSegments = (historicalGaps ?? []).flatMap(({ from, to }) => {
    const x1 = xScale(from.t)
    const x2 = xScale(to.t)
    const y1 = yScale(from.price)
    const y2 = yScale(to.price)
    // The dashed bridge is presentation-only. It begins and ends at real
    // server points but uses a smooth visual interpolation through the outage;
    // no interpolated value is exposed as market data.
    if (!Number.isFinite(x1) || !Number.isFinite(x2) || !Number.isFinite(y1) || !Number.isFinite(y2) || x2 <= left || x1 >= right || y1 < offset.top || y1 > bottom) return []
    return [{ x1: Math.max(left, x1), x2: Math.min(right, x2), y1, y2 }]
  })
  const renderedLinePoint = formattedGraphicalItems
    ?.find((item) => item.item?.type?.displayName === "Line")
    ?.props?.points
    ?.find((point) => point.payload?.id === latest.id)
  // For a visible tick, reuse the Line's final screen coordinates verbatim.
  // This stays aligned even if Recharts changes an internal axis offset. When
  // the point is outside the retained render set, use the scale as fallback.
  const x = renderedLinePoint?.x ?? xScale(latest.t)
  const y = renderedLinePoint?.y ?? yScale(latest.price)
  const latestSegment = showFutureGuide && viewportEnd > latest.t && Number.isFinite(x) && Number.isFinite(y) && x <= right && y >= offset.top && y <= bottom
    ? { x1: Math.max(left, x), x2: right, y }
    : undefined
  if (!historicalSegments.length && !latestSegment) return null

  return <g pointerEvents="none">
    {historicalSegments.map((segment) => {
      const controlX1 = segment.x1 + (segment.x2 - segment.x1) / 3
      const controlX2 = segment.x2 - (segment.x2 - segment.x1) / 3
      return <path key={`${segment.x1}-${segment.x2}-${segment.y1}-${segment.y2}`} d={`M ${segment.x1} ${segment.y1} C ${controlX1} ${segment.y1}, ${controlX2} ${segment.y2}, ${segment.x2} ${segment.y2}`} fill="none" stroke={stroke} strokeWidth={1.25} strokeOpacity={opacity} strokeDasharray="5 5" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
    })}
    {latestSegment && <line x1={latestSegment.x1} y1={latestSegment.y} x2={latestSegment.x2} y2={latestSegment.y} stroke={stroke} strokeWidth={1.25} strokeOpacity={opacity} strokeDasharray="5 5" strokeLinecap="round" vectorEffect="non-scaling-stroke" />}
  </g>
}

const CursorAxisReadout = ({ cursor, xDomain, yDomain, offset, stroke, textColor, backgroundColor, borderColor, formatTime }: CursorAxisReadoutProps) => {
  if (!cursor || !offset || offset.width <= 0 || offset.height <= 0) return null
  const left = offset.left
  const right = left + offset.width
  const top = offset.top
  const bottom = top + offset.height
  const x = Math.min(right, Math.max(left, cursor.x))
  const y = Math.min(bottom, Math.max(top, cursor.y))
  const time = xDomain[0] + ((x - left) / offset.width) * (xDomain[1] - xDomain[0])
  const price = yDomain[1] - ((y - top) / offset.height) * (yDomain[1] - yDomain[0])
  const timeLabel = formatTime(time)
  const priceLabel = formatValue(price)
  const timeWidth = Math.max(54, timeLabel.length * 6.2 + 12)
  const priceWidth = Math.max(58, priceLabel.length * 6.2 + 12)

  return <g pointerEvents="none">
    <line x1={x} y1={top} x2={x} y2={bottom} stroke={stroke} strokeDasharray="3 3" strokeOpacity={0.65} />
    <line x1={left} y1={y} x2={right} y2={y} stroke={stroke} strokeDasharray="3 3" strokeOpacity={0.65} />
    <rect x={Math.min(right - timeWidth, Math.max(left, x - timeWidth / 2))} y={bottom + 4} width={timeWidth} height={18} rx={3} fill={backgroundColor} stroke={borderColor} />
    <text x={Math.min(right - timeWidth / 2, Math.max(left + timeWidth / 2, x))} y={bottom + 13} fill={textColor} fontSize={10} textAnchor="middle" dominantBaseline="middle">{timeLabel}</text>
    <rect x={right + 3} y={Math.min(bottom - 18, Math.max(top, y - 9))} width={priceWidth} height={18} rx={3} fill={backgroundColor} stroke={borderColor} />
    <text x={right + 3 + priceWidth / 2} y={Math.min(bottom - 9, Math.max(top + 9, y))} fill={textColor} fontSize={10} textAnchor="middle" dominantBaseline="middle">{priceLabel}</text>
  </g>
}

export const ConfidenceChart = ({
  data,
  totalNodeCount = 0,
  pollIntervalMs = 1_000,
}: {
  data: MarketAssetPoint[]
  totalNodeCount?: number
  pollIntervalMs?: number
}) => {
  const { theme } = useThemeStore()
  const containerRef = useRef<HTMLDivElement>(null)
  const wheelHandlerRef = useRef<(event: WheelEvent) => void>(() => {})
  const pointPositionsRef = useRef(new Map<number, FocusedPoint>())
  const dragRef = useRef<
    | { mode: "xy"; x: number; y: number; end: number; domain: [number, number]; active: boolean }
    | { mode: "y"; y: number; domain: [number, number]; active: boolean }
    | null
  >(null)
  const viewportEndRef = useRef(Date.now() + DEFAULT_WINDOW_MS * LIVE_FUTURE_FRACTION)
  const previousBaseState = useRef<Exclude<FeedState, "recovered"> | null>(null)
  const recoveryAnimation = useRef<number | null>(null)
  const [now, setNow] = useState(Date.now())
  const [viewportEnd, setViewportEnd] = useState(() => Date.now() + DEFAULT_WINDOW_MS * LIVE_FUTURE_FRACTION)
  const [windowMs, setWindowMs] = useState(DEFAULT_WINDOW_MS)
  const [followingLive, setFollowingLive] = useState(true)
  const [recoveredUntil, setRecoveredUntil] = useState(0)
  const [activePoint, setActivePoint] = useState<FocusedPoint | null>(null)
  const [tooltipPoint, setTooltipPoint] = useState<FocusedPoint | null>(null)
  const [cursorPosition, setCursorPosition] = useState<CursorPosition | null>(null)
  const [detailPayload, setDetailPayload] = useState<MarketAssetPoint | null>(null)
  const [manualYDomain, setManualYDomain] = useState<[number, number] | null>(null)
  const [curveType, setCurveType] = useState<CurveType>("monotone")

  const realData = useMemo(
    () => [...data].filter((point) => Number.isFinite(point.t) && Number.isFinite(point.price)).sort((a, b) => a.t - b.t || a.id - b.id),
    [data],
  )
  const hasRealData = realData.length > 0
  const latest = realData.at(-1)
  const observedCadenceMs = useMemo(() => {
    const intervals = realData.slice(1).map((point, index) => point.t - realData[index].t).filter((interval) => interval > 0)
    return intervals.length >= 2 ? median(intervals) : null
  }, [realData])
  const ageMs = latest ? Math.max(0, now - latest.t) : Infinity
  const baseState = stateFor(ageMs, pollIntervalMs)
  const state: FeedState = recoveredUntil > now ? "recovered" : baseState
  // Live mode derives its viewport from server cadence instead of a fixed
  // duration, keeping roughly one screenful of real points for both
  // second-level and minute-level reporting rates. Before enough timestamps
  // exist to learn a cadence, retain the conservative startup window.
  const liveWindowMs = observedCadenceMs == null
    ? DEFAULT_WINDOW_MS
    : Math.max(MIN_WINDOW_MS, Math.min(MAX_WINDOW_MS, observedCadenceMs * TARGET_VISIBLE_POINT_COUNT / STALE_LAST_POINT_FRACTION))
  // A stale feed keeps its status and future guide, but does not inflate the
  // viewport to browser-now. Expanding by outage age would override cadence
  // fitting and compress the retained quotes into a small left-side cluster.
  const automaticWindowMs = liveWindowMs
  // `windowMs` belongs to the manual/history viewport. Auto-follow derives
  // its duration solely from the current server cadence.
  // Keeping the two separate prevents a previous pinch/zoom from changing the
  // duration that double-click restores.
  const effectiveWindowMs = followingLive ? automaticWindowMs : windowMs
  // Anchor the endpoint to the final server timestamp rather than browser-now
  // so Live, Delayed and Stale all retain the latest quote at the same 70%
  // focal position.
  const automaticViewportEnd = latest
    ? latest.t + automaticWindowMs * LIVE_FUTURE_FRACTION
    : now + automaticWindowMs * LIVE_FUTURE_FRACTION
  const domain = useMemo<[number, number]>(() => [viewportEnd - effectiveWindowMs, viewportEnd], [effectiveWindowMs, viewportEnd])
  const visiblePoints = useMemo(() => realData.filter((point) => point.t >= domain[0] && point.t <= domain[1]), [domain, realData])
  const automaticYDomain = useMemo(() => {
    // In auto-follow, keep the last-known price in the Y range even when a
    // bounded stale window has moved its original point left of the X domain.
    // That keeps the independent guide truthful and visible at its real price.
    const includeLatest = followingLive && latest && latest.t <= domain[1] && latest.t < domain[0]
    return yDomain(includeLatest ? [...visiblePoints, latest] : visiblePoints)
  }, [domain, followingLive, latest, visiblePoints])
  const activeYDomain = manualYDomain ?? automaticYDomain
  const xAxisTicks = useMemo(() => stableTicks(domain[0], domain[1], timeTickStep(effectiveWindowMs)), [domain, effectiveWindowMs])
  const yAxisTicks = useMemo(() => stableTicks(activeYDomain[0], activeYDomain[1], priceTickStep(activeYDomain[1] - activeYDomain[0])), [activeYDomain])
  const continuityGapMs = useMemo(() => {
    const intervals = realData.slice(1).map((point, index) => point.t - realData[index].t).filter((interval) => interval > 0)
    // A populated feed learns its own cadence. Sparse startup/history data uses
    // a conservative fallback so a minute-long outage is never drawn as one
    // continuous, apparently smooth price move.
    return intervals.length >= 2 ? Math.max(15_000, median(intervals) * 3) : Math.max(30_000, pollIntervalMs * 8)
  }, [pollIntervalMs, realData])
  const chartData = useMemo(() => {
    // Build geometry from the complete retained history, not the current
    // viewport. Recharts then clips this stable path to the domain, so a pan or
    // zoom cannot reshape historical curves by changing boundary points.
    return realData.flatMap<ChartDatum>((point, index) => {
      const previous = realData[index - 1]
      // A null-valued separator is a rendering control only: it has no price,
      // is not available to the Tooltip, and prevents an interpolation across
      // a server-time gap. All plotted values remain server-originated points.
      return previous && point.t - previous.t > continuityGapMs
        ? [{ ...previous, isGap: true }, point]
        : [point]
    })
  }, [continuityGapMs, realData])
  const historicalGaps = useMemo(() => chartData.reduce<GapGuide[]>((gaps, point, index) => {
    if (point.isGap) return gaps
    const previous = chartData.slice(0, index).reverse().find((candidate) => !candidate.isGap)
    if (previous && point.t - previous.t > continuityGapMs) gaps.push({ from: previous, to: point })
    return gaps
  }, []), [chartData, continuityGapMs])
  const setViewportEndSafely = useCallback((next: number) => {
    viewportEndRef.current = next
    setViewportEnd(next)
  }, [])

  const animateToLive = useCallback((target: number) => {
    if (recoveryAnimation.current !== null) cancelAnimationFrame(recoveryAnimation.current)
    const start = viewportEndRef.current
    const startedAt = performance.now()
    const frame = (frameNow: number) => {
      const progress = Math.min(1, (frameNow - startedAt) / 550)
      setViewportEndSafely(start + (target - start) * easeOutCubic(progress))
      recoveryAnimation.current = progress < 1 ? requestAnimationFrame(frame) : null
    }
    recoveryAnimation.current = requestAnimationFrame(frame)
  }, [setViewportEndSafely])

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 250)
    return () => window.clearInterval(timer)
  }, [])

  useEffect(() => {
    if (!followingLive) return
    setViewportEndSafely(automaticViewportEnd)
  }, [automaticViewportEnd, followingLive, setViewportEndSafely])

  useEffect(() => {
    const previous = previousBaseState.current
    if (previous && previous !== "live" && baseState === "live" && followingLive) {
      setRecoveredUntil(Date.now() + 900)
    }
    previousBaseState.current = baseState
  }, [baseState, followingLive, latest?.id])

  useEffect(() => () => {
    if (recoveryAnimation.current !== null) cancelAnimationFrame(recoveryAnimation.current)
  }, [])

  const pauseForHistory = useCallback(() => {
    if (recoveryAnimation.current !== null) cancelAnimationFrame(recoveryAnimation.current)
    recoveryAnimation.current = null
    // Preserve exactly the automatic stale window the user was seeing before
    // a drag or zoom turns it into a manual historical viewport.
    setWindowMs(effectiveWindowMs)
    setFollowingLive(false)
  }, [effectiveWindowMs])
  const returnToLive = () => {
    // A second double-click while already following must only reset the price
    // axis. Replaying the recovery transition on every click makes the whole
    // X domain visibly move even though its live position is already correct.
    if (followingLive) return
    const targetWindowMs = automaticWindowMs
    const windowChanged = Math.abs(windowMs - targetWindowMs) > 1
    setFollowingLive(true)
    setWindowMs(targetWindowMs)
    // Interpolating a changed domain width makes both historical and future
    // timestamps squeeze toward the middle. Reset that domain atomically;
    // only a pure same-width pan receives a short positional transition.
    if (windowChanged) setViewportEndSafely(automaticViewportEnd)
    else animateToLive(automaticViewportEnd)
  }
  const onDragStart = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (!event.isPrimary || (event.pointerType === "mouse" && event.button !== 0) || (event.target as HTMLElement).closest("button")) return
    event.preventDefault()
    event.currentTarget.setPointerCapture(event.pointerId)
    const bounds = containerRef.current?.getBoundingClientRect()
    const onYAxis = bounds ? event.clientX >= bounds.right - Y_AXIS_WIDTH : false
    dragRef.current = onYAxis
      ? { mode: "y", y: event.clientY, domain: activeYDomain, active: false }
      : { mode: "xy", x: event.clientX, y: event.clientY, end: viewportEndRef.current, domain: activeYDomain, active: false }
  }
  const onDragMove = (event: ReactPointerEvent<HTMLDivElement>) => {
    const drag = dragRef.current
    if (!drag) return
    event.preventDefault()
    const startX = drag.mode === "xy" ? drag.x : event.clientX
    if (!drag.active && Math.hypot(event.clientX - startX, event.clientY - drag.y) < DRAG_START_THRESHOLD_PX) return
    if (!drag.active) {
      drag.active = true
      pauseForHistory()
    }
    if (drag.mode === "y" || drag.mode === "xy") {
      const height = Math.max(1, containerRef.current?.clientHeight ?? 1)
      const range = drag.domain[1] - drag.domain[0]
      const shift = ((event.clientY - drag.y) / height) * range
      setManualYDomain([drag.domain[0] + shift, drag.domain[1] + shift])
    }
    if (drag.mode === "y") return
    const width = Math.max(1, containerRef.current?.clientWidth ?? 1)
    setViewportEndSafely(drag.end + ((drag.x - event.clientX) / width) * effectiveWindowMs * PAN_SENSITIVITY)
  }
  const onDragEnd = (event: ReactPointerEvent<HTMLDivElement>) => {
    dragRef.current = null
    if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId)
  }
  const handleWheel = useCallback((event: WheelEvent) => {
    event.preventDefault()
    event.stopPropagation()
    pauseForHistory()
    const bounds = containerRef.current?.getBoundingClientRect()
    const onYAxis = bounds ? event.clientX >= bounds.right - Y_AXIS_WIDTH : false
    if (onYAxis) {
      const [min, max] = activeYDomain
      const midpoint = (min + max) / 2
      const factor = Math.exp(Math.max(-100, Math.min(100, event.deltaY)) * WHEEL_ZOOM_RATE)
      const range = (max - min) * factor
      setManualYDomain([midpoint - range / 2, midpoint + range / 2])
      return
    }
    if (Math.abs(event.deltaY) >= Math.abs(event.deltaX)) {
      const factor = Math.exp(Math.max(-100, Math.min(100, event.deltaY)) * WHEEL_ZOOM_RATE)
      setWindowMs(Math.max(MIN_WINDOW_MS, Math.min(MAX_WINDOW_MS, effectiveWindowMs * factor)))
    } else {
      const width = Math.max(1, containerRef.current?.clientWidth ?? 1)
      setViewportEndSafely(viewportEndRef.current + (event.deltaX / width) * effectiveWindowMs * PAN_SENSITIVITY)
    }
  }, [activeYDomain, effectiveWindowMs, pauseForHistory, setViewportEndSafely])

  const xAxisTimeFormat = useCallback((value: number) => {
    if (effectiveWindowMs < 10 * 60_000) return dayjs(value).format("HH:mm:ss")
    if (effectiveWindowMs < 24 * 60 * 60_000) return dayjs(value).format("HH:mm")
    if (effectiveWindowMs < 7 * 24 * 60 * 60_000) return dayjs(value).format("MM-DD HH:mm")
    return dayjs(value).format("MM-DD")
  }, [effectiveWindowMs])

  useEffect(() => {
    wheelHandlerRef.current = handleWheel
  }, [handleWheel])

  useEffect(() => {
    const container = containerRef.current
    if (!container) return
    const onNativeWheel = (event: WheelEvent) => wheelHandlerRef.current(event)
    container.addEventListener("wheel", onNativeWheel, { passive: false })
    return () => container.removeEventListener("wheel", onNativeWheel)
  }, [hasRealData])

  const lineColor = getColorVariable("--chart-1")
  const guideColor = getColorVariable("--chart-2")
  const textColor = getColorVariable("--foreground")
  const borderColor = getColorVariable("--border")
  const backgroundColor = getColorVariable("--background")
  const gridColor = theme === "dark" ? addOklchAlpha(textColor, 0.08) : addOklchAlpha(textColor, 0.12)
  const areaColor = addOklchAlpha(lineColor, 0.25)
  const stateCopy = state === "live" ? "Live" : state === "recovered" ? "Recovered" : state === "delayed" ? `Delayed ${formatAge(ageMs)}` : `Stale · last ${latest ? dayjs(latest.t).format("HH:mm:ss") : "—"}`
  const stateClass = state === "live" ? "text-emerald-500" : state === "recovered" ? "text-sky-500" : state === "delayed" ? "text-amber-500" : "text-rose-500"
  const dataDot = (props: { cx?: number; cy?: number; payload?: ChartDatum }) => {
    if (props.payload?.isGap || !Number.isFinite(props.cx) || !Number.isFinite(props.cy)) return null
    pointPositionsRef.current.set(props.payload!.id, { point: props.payload!, x: props.cx!, y: props.cy! })
    const active = activePoint?.point.id === props.payload?.id
    return <g>
      <circle cx={props.cx} cy={props.cy} r={1.5} fill={lineColor} stroke={getColorVariable("--background")} strokeWidth={0.75} />
      {active && <circle cx={props.cx} cy={props.cy} r={4} fill={getColorVariable("--background")} stroke={guideColor} strokeWidth={1.5} />}
      {active && <circle cx={props.cx} cy={props.cy} r={5} fill="transparent" pointerEvents="all" onPointerEnter={() => setTooltipPoint({ point: props.payload!, x: props.cx!, y: props.cy! })} onPointerLeave={() => setTooltipPoint((current) => current?.point.id === props.payload!.id ? null : current)} onPointerDown={(event) => event.stopPropagation()} />}
    </g>
  }

  if (!hasRealData) return <div className="flex h-full items-center justify-center"><Loader2 strokeWidth={1} className="size-10 animate-spin" /></div>

  return (
    <div ref={containerRef} className="relative h-[500px] w-full select-none cursor-grab active:cursor-grabbing" style={{ overscrollBehavior: "contain", touchAction: "none" }} onPointerDown={onDragStart} onPointerMove={onDragMove} onPointerUp={onDragEnd} onPointerCancel={onDragEnd} onDoubleClick={(event) => {
      const bounds = containerRef.current?.getBoundingClientRect()
      if (bounds && event.clientX >= bounds.right - Y_AXIS_WIDTH) setManualYDomain(null)
      else {
        setManualYDomain(null)
        returnToLive()
      }
    }} onContextMenu={(event) => { event.preventDefault(); if (activePoint) setDetailPayload(activePoint.point) }}>
      <div className="absolute left-4 top-3 z-10 flex items-center gap-2 rounded border bg-background/85 px-2 py-1 text-xs backdrop-blur">
        <Radio className={`size-3 ${stateClass}`} /><span className={stateClass}>{stateCopy}</span>
        {!followingLive && <span className="text-muted-foreground">Viewing history</span>}
      </div>
      <select aria-label="Curve type" value={curveType} onPointerDown={(event) => event.stopPropagation()} onChange={(event) => setCurveType(event.target.value as CurveType)} className="absolute left-4 top-12 z-10 h-7 w-28 rounded border bg-background/85 px-2 text-xs backdrop-blur">
        <option value="linear">Linear</option>
        <option value="monotone">Smooth</option>
        <option value="natural">Natural</option>
      </select>
      <div className="absolute top-3 z-10 flex items-center gap-2" style={{ right: Y_AXIS_WIDTH + 16 }}>
        {!followingLive && <button type="button" onClick={returnToLive} className="inline-flex items-center gap-1 rounded border bg-background/90 px-2 py-1 text-xs shadow-sm hover:bg-muted"><RotateCcw className="size-3" /> Back to live</button>}
        <div className="flex overflow-hidden rounded border bg-background/90 shadow-sm">
          <button type="button" aria-label="Zoom in" onClick={() => { pauseForHistory(); setWindowMs(Math.max(MIN_WINDOW_MS, effectiveWindowMs * 0.8)) }} className="p-1.5 hover:bg-muted"><ZoomInIcon className="size-3.5" /></button>
          <button type="button" aria-label="Zoom out" onClick={() => { pauseForHistory(); setWindowMs(Math.min(MAX_WINDOW_MS, effectiveWindowMs * 1.25)) }} className="border-l p-1.5 hover:bg-muted"><ZoomOutIcon className="size-3.5" /></button>
        </div>
      </div>
      <SnapshotDetailDialog open={!!detailPayload} onOpenChange={(open) => !open && setDetailPayload(null)} payload={detailPayload} />
      {tooltipPoint && (() => {
        const width = containerRef.current?.clientWidth ?? 0
        const height = containerRef.current?.clientHeight ?? 0
        const placeLeft = tooltipPoint.x > width * 0.65
        const placeAbove = tooltipPoint.y > height * 0.55
        return <div className="pointer-events-none absolute z-20 min-w-44 rounded border bg-card p-3 text-xs shadow-lg" style={{ left: tooltipPoint.x + (placeLeft ? -12 : 12), top: tooltipPoint.y + (placeAbove ? -12 : 12), transform: `translate(${placeLeft ? "-100%" : "0"}, ${placeAbove ? "-100%" : "0"})` }}><div className="text-base">{fmtUsd(tooltipPoint.point.price)}</div><div className="mt-1 text-muted-foreground">{dayjs(tooltipPoint.point.t).format(dayjsFormat)}</div><div className="mt-2 text-muted-foreground">Aggregation inclusion: {tooltipPoint.point.candidates.length}/{totalNodeCount || tooltipPoint.point.candidates.length}</div><div className="mt-2 space-y-1">{tooltipPoint.point.candidates.map((candidate) => <div key={candidate.nodeId} className="flex items-center justify-between gap-3"><span className="flex items-center gap-1"><JazzAvatar address={candidate.nodeId} size={14} />{shortStr(candidate.nodeId, 5)}</span><span>{fmtUsd(candidate.price)}</span></div>)}</div></div>
      })()}
      <ResponsiveContainer width="100%" height="100%">
        <ComposedChart data={chartData} margin={{ top: 8, right: 0, bottom: 0, left: 0 }} onMouseMove={(event) => {
          const chartState = event as { activePayload?: Array<{ payload?: ChartDatum }>; activeCoordinate?: CursorPosition; chartX?: number; chartY?: number }
          // activeCoordinate belongs to Tooltip's nearest datum and therefore
          // snaps horizontally. Axis readouts use the raw chart pointer
          // position instead, with the snapped coordinate only as a fallback.
          const coordinate = Number.isFinite(chartState.chartX) && Number.isFinite(chartState.chartY)
            ? { x: chartState.chartX!, y: chartState.chartY! }
            : chartState.activeCoordinate
          setCursorPosition(coordinate && Number.isFinite(coordinate.x) && Number.isFinite(coordinate.y) ? coordinate : null)
          // Standard market-chart interaction is a time slice: the crosshair
          // remains free, while marker and tooltip resolve to the nearest real
          // server point by X only. Requiring a cursor to trace a price curve
          // is both fragile and unlike exchange/terminal chart behavior.
          const nearest = coordinate ? [...pointPositionsRef.current.values()].reduce<FocusedPoint | null>((best, candidate) => {
            return !best || Math.abs(candidate.x - coordinate.x) < Math.abs(best.x - coordinate.x) ? candidate : best
          }, null) : null
          setActivePoint((current) => current?.point.id === nearest?.point.id && current?.x === nearest?.x && current?.y === nearest?.y ? current : nearest)
        }} onMouseLeave={() => { setActivePoint(null); setTooltipPoint(null); setCursorPosition(null) }}>
          <defs><linearGradient id="price-feed-area-gradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={areaColor} stopOpacity={1} /><stop offset="100%" stopColor={areaColor} stopOpacity={0.15} /></linearGradient></defs>
          <CartesianGrid stroke={gridColor} strokeDasharray="2 6" />
          <XAxis type="number" dataKey="t" domain={domain} ticks={xAxisTicks} allowDataOverflow height={X_AXIS_HEIGHT} tickSize={10} axisLine={{ stroke: borderColor }} tick={{ fill: textColor, fontSize: 10 }} tickLine={false} minTickGap={32} tickFormatter={xAxisTimeFormat} />
          <YAxis type="number" width={Y_AXIS_WIDTH} orientation="right" domain={activeYDomain} ticks={yAxisTicks} tickLine={false} tick={{ fill: textColor, fontSize: 9 }} tickFormatter={formatValue} axisLine={{ stroke: borderColor }} allowDataOverflow />
          <Area type={curveType} dataKey={(point: ChartDatum) => point.isGap ? null : [point.low, point.high]} fill="url(#price-feed-area-gradient)" stroke="none" opacity={theme === "dark" ? 0.5 : 1} activeDot={false} isAnimationActive={false} connectNulls={false} />
          <Line type={curveType} dataKey={(point: ChartDatum) => point.isGap ? null : point.price} stroke={lineColor} strokeWidth={1.5} dot={dataDot} activeDot={false} isAnimationActive={false} connectNulls={false} />
          <Customized component={<LastKnownGuide latest={latest} viewportEnd={viewportEnd} historicalGaps={historicalGaps} stroke={guideColor} opacity={0.35} showFutureGuide={state === "delayed" || state === "stale"} />} />
          <Customized component={<CursorAxisReadout cursor={cursorPosition} xDomain={domain} yDomain={activeYDomain} stroke={addOklchAlpha(textColor, 0.5)} textColor={textColor} backgroundColor={backgroundColor} borderColor={borderColor} formatTime={xAxisTimeFormat} />} />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  )
}
