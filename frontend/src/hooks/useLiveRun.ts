import { useRef, useState, useCallback } from 'react'
import { api, type AuditEvent } from '@/lib/api'

export interface PendingApproval {
  action_id: string
  tool_name: string
}

/**
 * Shared live-run state machine: subscribes to /api/events/{run_id}, tracks
 * the event timeline, surfaces HITL approval prompts, and exposes approve/deny.
 * Used by both the Scenario Runner page (which starts its own run) and the
 * Upload Dataset page (which attaches to a run_id obtained from /api/upload).
 */
export function useLiveRun() {
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [running, setRunning] = useState(false)
  const [runId, setRunId] = useState<string | null>(null)
  const [pendingApproval, setPendingApproval] = useState<PendingApproval | null>(null)
  const [result, setResult] = useState<{ passed: boolean; metrics?: Record<string, unknown> } | null>(null)
  const stopRef = useRef<(() => void) | undefined>(undefined)

  const attach = useCallback((id: string) => {
    stopRef.current?.()
    setEvents([])
    setResult(null)
    setPendingApproval(null)
    setRunId(id)
    setRunning(true)
    stopRef.current = api.streamEvents(
      id,
      (ev) => {
        if (ev.type === 'done') {
          setResult({ passed: Boolean(ev.passed), metrics: ev.metrics as Record<string, unknown> | undefined })
          return
        }
        if (ev.type === 'approval_required') {
          setPendingApproval({ action_id: ev.action_id as string, tool_name: ev.tool_name as string })
          return
        }
        const e = ev as unknown as AuditEvent
        setEvents((prev) => [...prev, e])
      },
      () => setRunning(false),
    )
  }, [])

  const simulateLocally = useCallback((sample: AuditEvent[]) => {
    setEvents([])
    setResult(null)
    setPendingApproval(null)
    setRunning(true)
    setRunId(sample[0]?.run_id ?? `run-${Math.random().toString(16).slice(2, 10)}`)
    let i = 0
    const interval = setInterval(() => {
      if (i >= sample.length) {
        clearInterval(interval)
        setRunning(false)
        setResult({ passed: true })
        return
      }
      setEvents((prev) => [...prev, sample[i]])
      i += 1
    }, 350)
    stopRef.current = () => clearInterval(interval)
  }, [])

  const respondApproval = useCallback(async (approved: boolean) => {
    if (!runId || !pendingApproval) return
    try {
      await api.approve(runId, approved, pendingApproval.action_id)
    } catch {
      // no-op if backend unreachable — UI still clears the prompt
    }
    setPendingApproval(null)
  }, [runId, pendingApproval])

  const clear = useCallback(() => {
    stopRef.current?.()
    setEvents([])
    setResult(null)
    setPendingApproval(null)
    setRunning(false)
    setRunId(null)
  }, [])

  return { events, running, runId, pendingApproval, result, attach, simulateLocally, respondApproval, clear }
}
