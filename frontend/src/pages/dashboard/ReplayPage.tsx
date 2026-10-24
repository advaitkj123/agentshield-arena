import { useEffect, useRef, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Play, Pause, History, ShieldCheck, ShieldX, Wrench, FileSearch, Camera, FileText } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Slider } from '@/components/ui/slider'
import { Badge } from '@/components/ui/badge'
import { api } from '@/lib/api'
import { useApiData } from '@/hooks/useApiData'
import { buildSampleAuditTrail } from '@/lib/sampleData'
import { formatTimestamp, cn } from '@/lib/utils'

const EVENT_ICON: Record<string, typeof ShieldCheck> = {
  SCENARIO_LOADED: FileSearch,
  ACTION_PROPOSED: Wrench,
  POLICY_DECISION: ShieldCheck,
  TOOL_EXECUTION: Wrench,
  DLP_INSPECTION: ShieldX,
  SANDBOX_STATE_SNAPSHOT: Camera,
  REPORT_GENERATED: FileText,
}

const SAMPLE_RUN_ID = 'run-sample'

export function ReplayPage() {
  const { data, isSample } = useApiData(
    () => api.getReplay(SAMPLE_RUN_ID),
    { events: buildSampleAuditTrail(SAMPLE_RUN_ID) },
  )
  const events = data.events
  const [index, setIndex] = useState(0)
  const [playing, setPlaying] = useState(false)
  const [speed, setSpeed] = useState(1)
  const intervalRef = useRef<ReturnType<typeof setInterval> | undefined>(undefined)

  useEffect(() => {
    if (!playing) return
    intervalRef.current = setInterval(() => {
      setIndex((i) => {
        if (i >= events.length - 1) {
          setPlaying(false)
          return i
        }
        return i + 1
      })
    }, 700 / speed)
    return () => clearInterval(intervalRef.current)
  }, [playing, speed, events.length])

  const current = events[index]

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-app-sm bg-brand-cyan/10">
          <History className="h-5 w-5 text-brand-cyan" />
        </div>
        <div>
          <h1 className="text-2xl font-semibold">Attack Replay</h1>
          <p className="text-sm text-white/50">Scrub through a run's audit trail event-by-event.</p>
        </div>
      </div>
      {isSample && <p className="text-xs text-white/30">Showing sample replay — backend /api/replay not reachable yet.</p>}

      <Card className="transition-shadow hover:shadow-[0_8px_40px_rgba(6,182,212,0.08)]">
        <CardHeader>
          <CardTitle>Timeline</CardTitle>
          <CardDescription>
            Event {index + 1} of {events.length}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-4">
            <Button size="icon" variant="secondary" onClick={() => setPlaying((p) => !p)}>
              {playing ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
            </Button>
            <Slider
              value={[index]}
              max={Math.max(events.length - 1, 0)}
              step={1}
              onValueChange={([v]) => setIndex(v)}
              className="flex-1"
            />
            <select
              value={speed}
              onChange={(e) => setSpeed(Number(e.target.value))}
              className="rounded-app-sm border border-white/10 bg-white/5 px-2 py-1.5 text-xs"
            >
              <option value={0.5}>0.5x</option>
              <option value={1}>1x</option>
              <option value={2}>2x</option>
              <option value={4}>4x</option>
            </select>
          </div>

          <AnimatePresence mode="wait">
            {current && (
              <motion.div
                key={current.event_id}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.18 }}
                className="glass rounded-app-sm p-4"
              >
                <div className="flex items-center gap-2">
                  {(() => {
                    const Icon = EVENT_ICON[current.event_type] ?? ShieldCheck
                    return <Icon className="h-3.5 w-3.5 text-brand-blue" />
                  })()}
                  <Badge>{current.event_type}</Badge>
                  <span className="font-mono-data text-xs text-white/40">{formatTimestamp(current.timestamp)}</span>
                </div>
                <pre className="scrollbar-thin mt-3 max-h-48 overflow-auto font-mono-data text-xs text-white/60">
                  {JSON.stringify(current.details, null, 2)}
                </pre>
              </motion.div>
            )}
          </AnimatePresence>

          <div className="scrollbar-thin flex max-h-56 flex-col gap-1 overflow-y-auto">
            {events.map((e, i) => {
              const Icon = EVENT_ICON[e.event_type] ?? ShieldCheck
              return (
              <button
                key={e.event_id}
                onClick={() => setIndex(i)}
                className={cn(
                  'flex items-center justify-between rounded-[8px] px-3 py-1.5 text-left text-xs transition-colors',
                  i === index ? 'bg-brand-blue/20 text-white' : 'text-white/50 hover:bg-white/5',
                )}
              >
                <span className="flex items-center gap-2 font-mono-data">
                  <Icon className="h-3 w-3 shrink-0 opacity-60" /> {formatTimestamp(e.timestamp)}
                </span>
                <span>{e.event_type}</span>
              </button>
              )
            })}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
