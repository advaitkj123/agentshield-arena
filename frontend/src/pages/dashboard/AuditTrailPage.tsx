import { useState } from 'react'
import { RefreshCw, Download } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { api } from '@/lib/api'
import { useApiData } from '@/hooks/useApiData'
import { buildSampleAuditTrail } from '@/lib/sampleData'
import { formatTimestamp } from '@/lib/utils'

const PAGE_SIZE = 25

export function AuditTrailPage() {
  const [runIdFilter, setRunIdFilter] = useState('')
  const [eventTypeFilter, setEventTypeFilter] = useState('')
  const [page, setPage] = useState(1)

  const { data, loading, isSample, reload } = useApiData(
    () => api.getAudit({ run_id: runIdFilter || undefined, event_type: eventTypeFilter || undefined, page, page_size: PAGE_SIZE }),
    { events: buildSampleAuditTrail('run-sample'), total: 12, page: 1 },
    [runIdFilter, eventTypeFilter, page],
  )

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">Audit Trail</h1>
          <p className="text-sm text-white/50">Paginated, filterable append-only event log.</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" asChild>
            <a href={api.auditExportUrl({ run_id: runIdFilter || undefined, event_type: eventTypeFilter || undefined })} download>
              <Download className="h-3.5 w-3.5" /> Export CSV
            </a>
          </Button>
          <Button variant="secondary" size="sm" onClick={reload}><RefreshCw className="h-3.5 w-3.5" /> Refresh</Button>
        </div>
      </div>

      <Card>
        <CardHeader className="flex flex-row flex-wrap items-center gap-3">
          <Input placeholder="Filter by run_id" value={runIdFilter} onChange={(e) => setRunIdFilter(e.target.value)} className="max-w-xs" />
          <Input placeholder="Filter by event_type" value={eventTypeFilter} onChange={(e) => setEventTypeFilter(e.target.value)} className="max-w-xs" />
          {isSample && <span className="text-xs text-white/30">Sample data — backend /api/audit not reachable yet.</span>}
        </CardHeader>
        <CardContent>
          <div className="scrollbar-thin overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-white/10 text-xs uppercase tracking-wide text-white/40">
                  <th className="py-2 pr-4">Timestamp</th>
                  <th className="py-2 pr-4">Run ID</th>
                  <th className="py-2 pr-4">Event Type</th>
                  <th className="py-2 pr-4">Tool</th>
                  <th className="py-2 pr-4">Decision</th>
                </tr>
              </thead>
              <tbody>
                {data.events.map((e) => (
                  <tr key={e.event_id} className="border-b border-white/5 hover:bg-white/[0.02]">
                    <td className="py-2 pr-4 font-mono-data text-xs text-white/50">{formatTimestamp(e.timestamp)}</td>
                    <td className="py-2 pr-4 font-mono-data text-xs text-white/40">{e.run_id}</td>
                    <td className="py-2 pr-4"><Badge variant="muted">{e.event_type}</Badge></td>
                    <td className="py-2 pr-4 font-mono-data text-xs">{typeof e.details?.tool_name === 'string' ? e.details.tool_name as string : '—'}</td>
                    <td className="py-2 pr-4">
                      {typeof e.details?.decision === 'string' ? (
                        <Badge variant={e.details.decision === 'allow' ? 'green' : e.details.decision === 'deny' ? 'red' : 'orange'}>
                          {e.details.decision as string}
                        </Badge>
                      ) : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-4 flex items-center justify-between text-xs text-white/40">
            <span>{loading ? 'Loading…' : `${data.events.length} of ${data.total} events`}</span>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Prev</Button>
              <Button variant="outline" size="sm" disabled={data.events.length < PAGE_SIZE} onClick={() => setPage((p) => p + 1)}>Next</Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
