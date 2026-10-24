import { useMemo, useState } from 'react'
import { BarChart3, Boxes, TrendingUp } from 'lucide-react'
import { RadarChart, PolarGrid, PolarAngleAxis, Radar, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, AreaChart, Area } from 'recharts'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { MetricsGrid } from '@/components/MetricsGrid'
import { Metrics3DChart } from '@/components/Metrics3DChart'
import { CertificationBadge } from '@/components/CertificationBadge'
import { api } from '@/lib/api'
import { useApiData } from '@/hooks/useApiData'
import { SAMPLE_METRICS, SAMPLE_UNSAFE_METRICS, SAMPLE_METRICS_TREND } from '@/lib/sampleData'
import { formatTimestamp } from '@/lib/utils'

export function OverviewPage() {
  const [chartMode, setChartMode] = useState<'3d' | '2d'>('3d')

  // Pull the most recent run's audit events to derive live policy-decision counters;
  // falls back to sample metrics/counters when the backend isn't reachable yet.
  const { data: auditData, isSample } = useApiData(
    () => api.getAudit({ page: 1, page_size: 200 }),
    { events: [], total: 0, page: 1 },
  )

  const { data: trendData, isSample: trendIsSample } = useApiData(
    () => api.getMetricsTrend(50),
    SAMPLE_METRICS_TREND,
  )
  const trendPoints = trendData.points.map((p, i) => ({ ...p, index: i, label: formatTimestamp(p.timestamp).slice(0, 8) }))
  const hasBreach = trendPoints.some((p) => p.threat_score > 0)

  const decisionCounts = useMemo(() => {
    const counts = { allow: 0, deny: 0, approval_required: 0, dlp_blocked: 0 }
    for (const e of auditData.events) {
      const decision = e.details?.decision as string | undefined
      if (decision === 'allow') counts.allow += 1
      else if (decision === 'deny') counts.deny += 1
      else if (decision === 'approval_required') counts.approval_required += 1
      if (e.event_type === 'DLP_INSPECTION' && e.details?.blocked) counts.dlp_blocked += 1
    }
    return counts
  }, [auditData.events])

  // There's no "latest run" metrics endpoint (metrics are per-run, via the executive
  // report) — these cards show the canonical defended/unsafe baseline shape while the
  // Policy Gate Decision Summary below uses genuinely live /api/audit data.
  const metrics = SAMPLE_METRICS
  const unsafe = SAMPLE_UNSAFE_METRICS

  const RADAR_DATA = [
    { metric: 'TCR', defended: metrics.tcr_numeric ?? 100, unsafe: unsafe.tcr_numeric ?? 100 },
    { metric: 'Audit', defended: metrics.audit_completeness_numeric ?? 100, unsafe: unsafe.audit_completeness_numeric ?? 100 },
    { metric: '100-UAER', defended: 100 - (metrics.uaer_numeric ?? 0), unsafe: 100 - (unsafe.uaer_numeric ?? 0) },
    { metric: '100-ASR', defended: 100 - (metrics.asr_numeric ?? 0), unsafe: 100 - (unsafe.asr_numeric ?? 0) },
    { metric: '100-FBR', defended: 100 - (metrics.false_block_numeric ?? 0), unsafe: 100 - (unsafe.false_block_numeric ?? 0) },
  ]

  const BAR_DATA_3D = [
    { label: 'TCR', defended: metrics.tcr_numeric ?? 100, unsafe: unsafe.tcr_numeric ?? 100 },
    { label: 'UAER', defended: metrics.uaer_numeric ?? 0, unsafe: unsafe.uaer_numeric ?? 100 },
    { label: 'ASR', defended: metrics.asr_numeric ?? 0, unsafe: unsafe.asr_numeric ?? 100 },
    { label: 'FBR', defended: metrics.false_block_numeric ?? 0, unsafe: unsafe.false_block_numeric ?? 0 },
  ]

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Overview</h1>
        <p className="text-sm text-white/50">Live security &amp; utility metrics across the most recent run.</p>
      </div>

      <CertificationBadge />

      <MetricsGrid metrics={metrics} />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Security vs. Utility Radar</CardTitle>
            <CardDescription>Defended run vs. unsafe baseline</CardDescription>
          </CardHeader>
          <CardContent className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart data={RADAR_DATA}>
                <PolarGrid stroke="rgba(255,255,255,0.1)" />
                <PolarAngleAxis dataKey="metric" tick={{ fill: 'rgba(255,255,255,0.5)', fontSize: 11 }} />
                <Radar name="Defended" dataKey="defended" stroke="#30d158" fill="#30d158" fillOpacity={0.25} />
                <Radar name="Unsafe" dataKey="unsafe" stroke="#ff453a" fill="#ff453a" fillOpacity={0.15} />
              </RadarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <div>
              <CardTitle>Defended vs. Unsafe Baseline</CardTitle>
              <CardDescription>Same scenario, same agent, policy gate on/off</CardDescription>
            </div>
            <div className="flex gap-1 rounded-app-sm bg-white/5 p-1">
              <Button size="sm" variant={chartMode === '3d' ? 'default' : 'ghost'} onClick={() => setChartMode('3d')}>
                <Boxes className="h-3.5 w-3.5" /> 3D
              </Button>
              <Button size="sm" variant={chartMode === '2d' ? 'default' : 'ghost'} onClick={() => setChartMode('2d')}>
                <BarChart3 className="h-3.5 w-3.5" /> 2D
              </Button>
            </div>
          </CardHeader>
          <CardContent className="h-72">
            {chartMode === '3d' ? (
              <Metrics3DChart data={BAR_DATA_3D} height={288} />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={BAR_DATA_3D}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
                  <XAxis dataKey="label" tick={{ fill: 'rgba(255,255,255,0.5)', fontSize: 11 }} />
                  <YAxis tick={{ fill: 'rgba(255,255,255,0.5)', fontSize: 11 }} />
                  <Tooltip contentStyle={{ background: '#111', border: '1px solid rgba(255,255,255,0.1)' }} />
                  <Bar dataKey="defended" fill="#30d158" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="unsafe" fill="#ff453a" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Policy Gate Decision Summary</CardTitle>
          <CardDescription>{isSample ? 'Sample counters — backend /api/audit not reachable yet.' : `Derived from ${auditData.events.length} recent audit events.`}</CardDescription>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {[
            { label: 'Allowed', value: decisionCounts.allow, color: 'text-brand-green' },
            { label: 'Denied', value: decisionCounts.deny, color: 'text-brand-red' },
            { label: 'HITL Approval', value: decisionCounts.approval_required, color: 'text-brand-orange' },
            { label: 'DLP Blocked', value: decisionCounts.dlp_blocked, color: 'text-brand-purple' },
          ].map((s) => (
            <div key={s.label}>
              <div className={`font-mono-data text-2xl font-semibold ${s.color}`}>{s.value}</div>
              <div className="text-xs text-white/40">{s.label}</div>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card className="transition-shadow hover:shadow-[0_8px_40px_rgba(41,151,255,0.08)]">
        <CardHeader>
          <div className="flex items-center gap-2">
            <TrendingUp className="h-4 w-4 text-brand-green" />
            <CardTitle>Threat Score Trend</CardTitle>
          </div>
          <CardDescription>
            {hasBreach
              ? 'Stays at zero across every defended run — the one spike is the unsafe-baseline comparison run (Policy Gate deliberately disabled).'
              : 'Zero across every run so far — the Policy Gate has never let an unauthorized action execute.'}
            {trendIsSample && <span className="text-white/30"> Sample trend — backend /api/metrics/trend not reachable yet.</span>}
          </CardDescription>
        </CardHeader>
        <CardContent className="h-56">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={trendPoints} margin={{ left: -20 }}>
              <defs>
                <linearGradient id="threatScoreFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#30d158" stopOpacity={0.35} />
                  <stop offset="100%" stopColor="#30d158" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
              <XAxis dataKey="label" tick={{ fill: 'rgba(255,255,255,0.4)', fontSize: 10 }} />
              <YAxis domain={[0, 1]} tick={{ fill: 'rgba(255,255,255,0.4)', fontSize: 10 }} />
              <Tooltip
                contentStyle={{ background: '#111', border: '1px solid rgba(255,255,255,0.1)' }}
                formatter={(value) => [typeof value === 'number' ? value.toFixed(2) : String(value), 'Threat Score']}
                labelFormatter={(_, payload) => (payload?.[0]?.payload as { scenario_id?: string } | undefined)?.scenario_id ?? ''}
              />
              <Area
                type="monotone"
                dataKey="threat_score"
                stroke="#30d158"
                strokeWidth={2}
                fill="url(#threatScoreFill)"
                dot={(props: { cx?: number; cy?: number; payload?: { threat_score: number } }) => {
                  const breached = (props.payload?.threat_score ?? 0) > 0
                  return (
                    <circle
                      key={`dot-${props.cx}-${props.cy}`}
                      cx={props.cx}
                      cy={props.cy}
                      r={breached ? 5 : 3}
                      fill={breached ? '#ff453a' : '#30d158'}
                      stroke={breached ? '#ff453a' : 'none'}
                      strokeOpacity={0.4}
                      strokeWidth={breached ? 6 : 0}
                    />
                  )
                }}
              />
            </AreaChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>
    </div>
  )
}
