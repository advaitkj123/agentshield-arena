import { Grid3x3 } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { api } from '@/lib/api'
import { useApiData } from '@/hooks/useApiData'
import { SAMPLE_COVERAGE } from '@/lib/sampleData'
import { cn } from '@/lib/utils'

export function CoveragePage() {
  const { data, isSample } = useApiData(api.getMitreCoverage, SAMPLE_COVERAGE)

  const maxScenarios = Math.max(1, ...data.mitre_techniques.map((t) => t.scenario_ids.length))

  return (
    <div className="space-y-6">
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-semibold"><Grid3x3 className="h-5 w-5 text-brand-blue" /> MITRE ATT&amp;CK / OWASP Coverage</h1>
        <p className="text-sm text-white/50">
          {data.scenario_count} adversarial scenarios mapped to real-world threat intelligence taxonomies.
          {isSample && <span className="text-white/30"> Sample data — backend /api/mitre-coverage not reachable yet.</span>}
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>MITRE ATT&amp;CK Technique Coverage</CardTitle>
          <CardDescription>Color intensity = number of scenarios exercising that technique. Green ring = empirically tested this session.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5">
            {data.mitre_techniques.map((t) => {
              const intensity = t.scenario_ids.length / maxScenarios
              return (
                <div
                  key={t.id}
                  title={`${t.id} — ${t.name}\nScenarios: ${t.scenario_ids.join(', ')}`}
                  className={cn(
                    'group relative flex flex-col gap-1 rounded-app-sm border px-3 py-3 transition-transform hover:-translate-y-0.5',
                    t.tested ? 'border-brand-green/50' : 'border-white/10',
                  )}
                  style={{
                    background: `color-mix(in srgb, var(--color-brand-blue) ${Math.round(8 + intensity * 32)}%, transparent)`,
                  }}
                >
                  <span className="font-mono-data text-xs text-white/70">{t.id}</span>
                  <span className="text-[11px] leading-tight text-white/50">{t.name}</span>
                  <div className="mt-1 flex items-center justify-between">
                    <span className="text-[10px] text-white/30">{t.scenario_ids.length} scenario{t.scenario_ids.length === 1 ? '' : 's'}</span>
                    {t.tested && <Badge variant="green">tested</Badge>}
                  </div>
                </div>
              )
            })}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>OWASP LLM Top 10 (2025) Coverage</CardTitle>
          <CardDescription>Risk categories exercised across the scenario battery.</CardDescription>
        </CardHeader>
        <CardContent className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {data.owasp_llm_risks.map((r) => (
            <div key={r.id} className="flex items-center justify-between rounded-app-sm bg-white/[0.03] px-3 py-2.5 transition-colors hover:bg-white/[0.06]">
              <div>
                <div className="font-mono-data text-xs text-brand-cyan">{r.id}</div>
                <div className="text-sm text-white/70">{r.name}</div>
              </div>
              <Badge variant="muted">{r.scenario_ids.length}</Badge>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  )
}
