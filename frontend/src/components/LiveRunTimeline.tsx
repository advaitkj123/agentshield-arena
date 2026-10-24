import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import type { AuditEvent } from '@/lib/api'
import { formatTimestamp } from '@/lib/utils'
import type { PendingApproval } from '@/hooks/useLiveRun'

function eventBadgeVariant(type: string) {
  if (type === 'TOOL_EXECUTION') return 'cyan' as const
  if (type === 'POLICY_DECISION') return 'default' as const
  if (type === 'DLP_INSPECTION') return 'purple' as const
  return 'muted' as const
}

function decisionBadgeVariant(decision: string) {
  if (decision === 'allow') return 'green' as const
  if (decision === 'deny') return 'red' as const
  if (decision === 'approval_required') return 'orange' as const
  return 'muted' as const
}

interface Props {
  runId: string | null
  events: AuditEvent[]
  pendingApproval: PendingApproval | null
  onApprove: (approved: boolean) => void
  emptyLabel?: string
}

export function LiveRunTimeline({ runId, events, pendingApproval, onApprove, emptyLabel }: Props) {
  return (
    <div className="space-y-4">
      {pendingApproval && (
        <Card className="border-brand-orange/40 bg-brand-orange/5">
          <CardContent className="flex flex-wrap items-center justify-between gap-3 p-4">
            <div>
              <div className="font-mono-data text-sm text-brand-orange">HITL Approval Required</div>
              <div className="text-sm text-white/70">
                Tool <span className="font-mono-data">{pendingApproval.tool_name}</span> needs human authorization.
              </div>
            </div>
            <div className="flex gap-2">
              <Button variant="success" size="sm" onClick={() => onApprove(true)}>Approve</Button>
              <Button variant="destructive" size="sm" onClick={() => onApprove(false)}>Deny</Button>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Live Execution Timeline</CardTitle>
          <CardDescription>{runId ? `run_id: ${runId}` : 'No run started yet'}</CardDescription>
        </CardHeader>
        <CardContent className="scrollbar-thin max-h-[480px] space-y-2 overflow-y-auto">
          {events.length === 0 && (
            <div className="py-10 text-center text-sm text-white/30">{emptyLabel ?? 'Run a scenario to see live events here.'}</div>
          )}
          {events.map((e) => (
            <div key={e.event_id} className="flex items-start gap-3 rounded-app-sm bg-white/[0.03] px-3 py-2 transition-colors hover:bg-white/[0.05]">
              <span className="mt-0.5 font-mono-data text-[11px] text-white/35">{formatTimestamp(e.timestamp)}</span>
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <Badge variant={eventBadgeVariant(e.event_type)}>{e.event_type}</Badge>
                  {typeof e.details?.tool_name === 'string' && (
                    <span className="font-mono-data text-xs text-white/60">{e.details.tool_name as string}</span>
                  )}
                  {typeof e.details?.decision === 'string' && (
                    <Badge variant={decisionBadgeVariant(e.details.decision as string)}>{e.details.decision as string}</Badge>
                  )}
                </div>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  )
}
