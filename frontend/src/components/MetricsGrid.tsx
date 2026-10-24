import { TrendingUp, TrendingDown } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import type { MetricsBundle } from '@/lib/api'
import { cn } from '@/lib/utils'

interface MetricDef {
  key: keyof MetricsBundle
  label: string
  suffix?: string
  color: string
  goodWhenLow?: boolean
}

const METRIC_DEFS: MetricDef[] = [
  { key: 'tcr_numeric', label: 'Task Completion Rate', suffix: '%', color: 'text-brand-blue' },
  { key: 'uaer_numeric', label: 'Unauthorized Action Exec Rate', suffix: '%', color: 'text-brand-red', goodWhenLow: true },
  { key: 'asr_numeric', label: 'Attack Success Rate', suffix: '%', color: 'text-brand-red', goodWhenLow: true },
  { key: 'false_block_numeric', label: 'False-Block Rate', suffix: '%', color: 'text-brand-orange', goodWhenLow: true },
  { key: 'audit_completeness_numeric', label: 'Audit Completeness', suffix: '%', color: 'text-brand-green' },
  { key: 'threat_score', label: 'Threat Score', suffix: '', color: 'text-brand-purple', goodWhenLow: true },
]

export function MetricsGrid({ metrics, compare }: { metrics: MetricsBundle; compare?: MetricsBundle }) {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
      {METRIC_DEFS.map((def) => {
        const value = metrics[def.key]
        const compareValue = compare?.[def.key]
        const numeric = typeof value === 'number' ? value : null
        const delta =
          typeof numeric === 'number' && typeof compareValue === 'number' ? numeric - compareValue : null
        return (
          <Card key={def.key as string} className="transition-all hover:-translate-y-0.5">
            <CardHeader className="p-4 pb-1">
              <CardTitle className="text-[11px] font-normal uppercase tracking-wide text-white/40">
                {def.label}
              </CardTitle>
            </CardHeader>
            <CardContent className="p-4 pt-0">
              <div className={cn('font-mono-data text-2xl font-semibold', def.color)}>
                {numeric === null ? 'N/A' : `${numeric}${def.suffix}`}
              </div>
              {delta !== null && delta !== 0 && (() => {
                const isGood = def.goodWhenLow ? delta < 0 : delta > 0
                const TrendIcon = delta > 0 ? TrendingUp : TrendingDown
                return (
                  <div
                    className={cn(
                      'mt-1 flex items-center gap-1 font-mono-data text-xs',
                      isGood ? 'text-brand-green' : 'text-brand-red',
                    )}
                  >
                    <TrendIcon className="h-3 w-3" />
                    {delta > 0 ? '+' : ''}
                    {delta.toFixed(2)}
                    {def.suffix} vs baseline
                  </div>
                )
              })()}
            </CardContent>
          </Card>
        )
      })}
    </div>
  )
}
