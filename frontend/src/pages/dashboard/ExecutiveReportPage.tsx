import { Printer, FileText, Radar, ListChecks, ShieldCheck } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { MetricsGrid } from '@/components/MetricsGrid'
import { api } from '@/lib/api'
import { useApiData } from '@/hooks/useApiData'
import { SAMPLE_EXECUTIVE_REPORT } from '@/lib/sampleData'
import { riskColor } from '@/lib/utils'

/** Radial gauge — the blast-radius score is the single most important number on this
 * page, so it gets real visual weight instead of sitting as inline text. */
function BlastRadiusGauge({ score }: { score: number }) {
  const size = 132
  const stroke = 10
  const radius = (size - stroke) / 2
  const circumference = 2 * Math.PI * radius
  const offset = circumference * (1 - score)
  const color = riskColor(score)

  return (
    <div className="relative flex h-[132px] w-[132px] shrink-0 items-center justify-center">
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth={stroke} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 0.8s ease, stroke 0.8s ease' }}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="font-mono-data text-3xl font-bold" style={{ color }}>{(score * 100).toFixed(0)}%</span>
        <span className="text-[10px] uppercase tracking-wide text-white/40">Blast Radius</span>
      </div>
    </div>
  )
}

export function ExecutiveReportPage() {
  const { data, isSample } = useApiData(() => api.getExecutiveReport('run-sample'), SAMPLE_EXECUTIVE_REPORT)

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-app-sm bg-brand-blue/10">
            <FileText className="h-5 w-5 text-brand-blue" />
          </div>
          <div>
            <h1 className="text-2xl font-semibold">Executive Report</h1>
            <p className="text-sm text-white/50">Auto-generated incident summary for stakeholders.</p>
          </div>
        </div>
        <Button variant="secondary" onClick={() => window.print()}><Printer className="h-4 w-4" /> Export / Print</Button>
      </div>
      {isSample && <p className="text-xs text-white/30">Sample report — backend /api/report/:runId/executive not reachable yet.</p>}

      <Card className="overflow-hidden transition-shadow hover:shadow-[0_8px_40px_rgba(41,151,255,0.08)]">
        <div className="h-1 w-full bg-gradient-to-r from-brand-blue via-brand-cyan to-brand-purple" />
        <CardContent className="flex flex-col gap-6 p-6 sm:flex-row sm:items-center">
          <BlastRadiusGauge score={data.blast_radius_score} />
          <div className="flex-1 border-t border-white/10 pt-4 sm:border-t-0 sm:border-l sm:pl-6 sm:pt-0">
            <div className="flex items-center gap-2">
              <Badge variant={data.severity === 'critical' || data.severity === 'high' ? 'red' : 'orange'}>{data.severity}</Badge>
              <ShieldCheck className="h-3.5 w-3.5 text-brand-green" />
              <span className="text-xs text-white/40">Policy Gate Decision Record</span>
            </div>
            <h2 className="mt-2 text-xl font-semibold leading-snug">{data.headline}</h2>
          </div>
        </CardContent>
        <CardContent className="border-t border-white/10 pt-5">
          <MetricsGrid metrics={data.key_metrics} />
        </CardContent>
      </Card>

      <Card className="transition-shadow hover:shadow-[0_8px_40px_rgba(41,151,255,0.06)]">
        <CardHeader>
          <div className="flex items-center gap-2">
            <Radar className="h-4 w-4 text-brand-cyan" />
            <CardTitle>Timeline Highlights</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <ol className="space-y-3 border-l border-white/10 pl-4">
            {data.timeline_highlights.length === 0 && (
              <li className="text-sm text-white/30">No blocked or flagged decisions recorded for this run.</li>
            )}
            {data.timeline_highlights.map((h, i) => (
              <li key={i} className="relative flex flex-col gap-0.5 text-sm text-white/70">
                <span className="absolute -left-[21px] top-1 h-2 w-2 rounded-full bg-brand-blue" />
                <div className="flex items-center gap-2">
                  <span className="font-mono-data text-xs text-brand-blue">{String(i + 1).padStart(2, '0')}</span>
                  {h.tool_name && <Badge variant="orange">{h.tool_name}</Badge>}
                  {h.timestamp && <span className="font-mono-data text-[11px] text-white/30">{h.timestamp.split('T')[1]?.split('.')[0]}</span>}
                </div>
                <span className="pl-6">{h.summary || h.event_type}</span>
              </li>
            ))}
          </ol>
        </CardContent>
      </Card>

      <Card className="transition-shadow hover:shadow-[0_8px_40px_rgba(48,209,88,0.06)]">
        <CardHeader>
          <div className="flex items-center gap-2">
            <ListChecks className="h-4 w-4 text-brand-green" />
            <CardTitle>Recommended Actions</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <ul className="space-y-2.5">
            {data.recommended_actions.map((a, i) => (
              <li key={i} className="flex gap-2.5 text-sm text-white/70">
                <span className="mt-0.5 text-brand-green">✓</span> {a}
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
    </div>
  )
}
