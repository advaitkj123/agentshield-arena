import { useEffect, useRef, useState } from 'react'
import { motion, useInView } from 'framer-motion'

const STATS = [
  { value: 100, suffix: '%', label: 'Defended Pass Rate' },
  { value: 67, suffix: '+', label: 'Tests Passing' },
  { value: 11, suffix: '', label: 'Attack Scenarios' },
  { value: null, display: '<1ms', label: 'Mean Time to Defend' },
]

function Counter({ to }: { to: number }) {
  const ref = useRef<HTMLSpanElement>(null)
  const inView = useInView(ref, { once: true })
  const [val, setVal] = useState(0)

  useEffect(() => {
    if (!inView) return
    const duration = 1200
    const start = performance.now()
    let raf = 0
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration)
      const eased = 1 - Math.pow(1 - t, 3)
      setVal(Math.round(eased * to))
      if (t < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [inView, to])

  return <span ref={ref}>{val}</span>
}

export function StatsRow() {
  return (
    <section className="mx-auto max-w-5xl px-4 py-16 sm:px-6">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {STATS.map((s, i) => (
          <motion.div
            key={s.label}
            initial={{ opacity: 0, y: 16 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: i * 0.05 }}
            className="glass rounded-app px-4 py-6 text-center"
          >
            <div className="font-mono-data text-3xl font-bold text-gradient-brand sm:text-4xl">
              {s.value !== null ? (
                <>
                  <Counter to={s.value} />
                  {s.suffix}
                </>
              ) : (
                s.display
              )}
            </div>
            <div className="mt-1 text-xs text-white/50">{s.label}</div>
          </motion.div>
        ))}
      </div>
    </section>
  )
}
