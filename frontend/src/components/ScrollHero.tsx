import { useEffect, useRef, useState, type ReactNode } from 'react'

const FRAME_BASE = '/hero/gemini_generated_video_8435859a_000/gemini_generated_video_8435859a_'
const TOTAL_FRAMES = 100
const EAGER_COUNT = 12
const BATCH_SIZE = 4
const TRACK_VH = 1000

function frameUrl(i: number): string {
  return `${FRAME_BASE}${String(i).padStart(3, '0')}.jpg`
}

/**
 * Apple-style scroll-scrubbed image sequence, built to avoid every jank
 * source found in the prior implementation:
 *  - Only the first EAGER_COUNT frames load immediately; the rest load in
 *    small sequential batches in the background (never 100 at once).
 *  - The raw `scroll` listener only writes a ref — no layout reads/writes
 *    happen inside it. A single rAF loop (capped at the browser's own
 *    refresh rate) does the one unavoidable layout read (getBoundingClientRect,
 *    which yields both scroll offset AND live track height in one call, so
 *    there's no separately-cached height that can go stale on mobile viewport
 *    changes) and the canvas draw.
 *  - Canvas backing store is devicePixelRatio-correct, resized only on an
 *    actual (debounced) resize event via ResizeObserver, never per scroll tick.
 *  - If the frame needed for the current scroll position hasn't loaded yet,
 *    the nearest already-loaded frame is drawn instead of leaving it blank.
 *  - If the user scrolls ahead of the background loader, the exact frame
 *    needed is loaded immediately out of order (queue-jump).
 *  - Full cleanup on unmount: rAF cancelled, listeners removed, observer
 *    disconnected — this now lives in a React Router SPA, not a static page.
 */
export function ScrollHero({ children, baseLayer }: { children?: ReactNode; baseLayer?: ReactNode }) {
  const trackRef = useRef<HTMLDivElement>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [ready, setReady] = useState(false)

  useEffect(() => {
    const track = trackRef.current
    const canvas = canvasRef.current
    if (!track || !canvas) return

    const ctx2d = canvas.getContext('2d')
    if (!ctx2d) return
    const ctx: CanvasRenderingContext2D = ctx2d

    let destroyed = false
    const images: (HTMLImageElement | null)[] = new Array(TOTAL_FRAMES).fill(null)
    const started = new Array(TOTAL_FRAMES).fill(false)
    const loaded = new Array(TOTAL_FRAMES).fill(false)
    let lastDrawnIndex = -1
    let hasDrawnOnce = false

    function ensureLoading(index: number) {
      if (index < 0 || index >= TOTAL_FRAMES || started[index]) return
      started[index] = true
      const img = new Image()
      img.decoding = 'async'
      img.onload = () => {
        loaded[index] = true
      }
      img.src = frameUrl(index)
      images[index] = img
    }

    // Eager window — covers the first screenful of scrolling instantly.
    for (let i = 0; i < EAGER_COUNT; i++) ensureLoading(i)

    // Background progressive loader — small sequential batches, never a burst.
    let batchCursor = EAGER_COUNT
    function loadNextBatch() {
      if (destroyed || batchCursor >= TOTAL_FRAMES) return
      const end = Math.min(batchCursor + BATCH_SIZE, TOTAL_FRAMES)
      for (let i = batchCursor; i < end; i++) ensureLoading(i)
      batchCursor = end
      // Yield back to the browser between batches instead of hammering the
      // network/main thread with all 100 requests at once.
      setTimeout(loadNextBatch, 60)
    }
    const kickoff = setTimeout(loadNextBatch, 50)

    function nearestLoadedIndex(target: number): number {
      if (loaded[target]) return target
      for (let d = 1; d < TOTAL_FRAMES; d++) {
        const back = target - d
        const fwd = target + d
        if (back >= 0 && loaded[back]) return back
        if (fwd < TOTAL_FRAMES && loaded[fwd]) return fwd
      }
      return -1
    }

    // Canvas backing-store sizing — devicePixelRatio-correct, recomputed only
    // on an actual resize (debounced), never inside the scroll/rAF hot path.
    let cssWidth = 0
    let cssHeight = 0
    function resizeCanvas() {
      const dpr = Math.min(window.devicePixelRatio || 1, 2.5)
      cssWidth = window.innerWidth
      cssHeight = window.innerHeight
      canvas!.width = Math.round(cssWidth * dpr)
      canvas!.height = Math.round(cssHeight * dpr)
      canvas!.style.width = `${cssWidth}px`
      canvas!.style.height = `${cssHeight}px`
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      lastDrawnIndex = -1 // force a redraw at the current frame after resize
    }
    resizeCanvas()

    let resizeTimer: ReturnType<typeof setTimeout> | null = null
    const ro = new ResizeObserver(() => {
      if (resizeTimer) clearTimeout(resizeTimer)
      resizeTimer = setTimeout(resizeCanvas, 150)
    })
    ro.observe(document.body)

    function drawFrame(index: number) {
      const img = images[index]
      if (!img) return
      const iw = img.naturalWidth
      const ih = img.naturalHeight
      if (!iw || !ih) return
      const scale = Math.max(cssWidth / iw, cssHeight / ih)
      const dw = iw * scale
      const dh = ih * scale
      const dx = (cssWidth - dw) / 2
      const dy = (cssHeight - dh) / 2
      ctx.clearRect(0, 0, cssWidth, cssHeight)
      ctx.drawImage(img, dx, dy, dw, dh)
    }

    // Scroll tracking — the listener itself does nothing but remember that a
    // scroll happened; all real work happens in the rAF loop below.
    let scrolled = false
    const onScroll = () => {
      scrolled = true
    }
    window.addEventListener('scroll', onScroll, { passive: true })

    let rafId = 0
    function tick() {
      if (destroyed) return
      if (scrolled || !hasDrawnOnce) {
        scrolled = false
        // Single layout read per animation frame — yields both the track's
        // position AND its live height, so there's no separately cached
        // height to go stale when the mobile address bar shows/hides.
        const rect = track!.getBoundingClientRect()
        const total = rect.height - window.innerHeight
        const frac = total > 0 ? Math.min(1, Math.max(0, -rect.top / total)) : 0
        const targetIndex = Math.round(frac * (TOTAL_FRAMES - 1))

        ensureLoading(targetIndex) // queue-jump if the user scrolled ahead of the background loader
        const drawIndex = nearestLoadedIndex(targetIndex)
        if (drawIndex !== -1 && drawIndex !== lastDrawnIndex) {
          drawFrame(drawIndex)
          lastDrawnIndex = drawIndex
          if (!hasDrawnOnce) {
            hasDrawnOnce = true
            setReady(true)
          }
        }
      }
      rafId = requestAnimationFrame(tick)
    }
    rafId = requestAnimationFrame(tick)

    return () => {
      destroyed = true
      clearTimeout(kickoff)
      if (resizeTimer) clearTimeout(resizeTimer)
      cancelAnimationFrame(rafId)
      window.removeEventListener('scroll', onScroll)
      ro.disconnect()
      for (const img of images) {
        if (img) img.onload = null
      }
    }
  }, [])

  return (
    <div ref={trackRef} className="relative" style={{ height: `${TRACK_VH}vh` }}>
      <div className="sticky top-0 h-screen w-full overflow-hidden">
        {baseLayer}
        <canvas
          ref={canvasRef}
          className="absolute inset-0 h-full w-full transition-opacity duration-700"
          style={{ opacity: ready ? 1 : 0 }}
        />
        {/* Legibility scrim so overlaid copy stays readable against the scrubbing frames */}
        <div className="absolute inset-0 bg-gradient-to-b from-black/70 via-black/30 to-black/80" />
        <div className="absolute inset-0 flex items-center justify-center">{children}</div>
      </div>
    </div>
  )
}
