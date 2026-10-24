import { useState } from 'react'
import { motion } from 'framer-motion'
import { ShieldCheck, Gauge } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { api } from '@/lib/api'
import { useApiData } from '@/hooks/useApiData'
import { SAMPLE_CERTIFICATION } from '@/lib/sampleData'
import { formatTimestamp } from '@/lib/utils'

/**
 * Shareable "trust certificate" summary of the latest benchmark run —
 * designed to be a screenshot-worthy proof point for judges.
 */
export function CertificationBadge() {
  const [notFound, setNotFound] = useState(false)
  const { data, isSample, reload } = useApiData(
    () => api.getCertification().catch((e) => { setNotFound(true); throw e }),
    SAMPLE_CERTIFICATION,
  )

  if (notFound && isSample) {
    return (
      <Card className="border-brand-orange/30 bg-brand-orange/5">
        <CardContent className="flex flex-wrap items-center justify-between gap-3 p-5">
          <div className="flex items-center gap-2 text-sm text-white/70">
            <Gauge className="h-4 w-4 text-brand-orange" /> No benchmark has run yet — run one to generate a certification.
          </div>
          <Button size="sm" variant="secondary" asChild>
            <a href="/dashboard/benchmark">Run Benchmark →</a>
          </Button>
        </CardContent>
      </Card>
    )
  }

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.98 }}
      animate={{ opacity: 1, scale: 1 }}
      className="relative overflow-hidden rounded-app border border-brand-green/30 bg-gradient-to-br from-brand-green/10 via-black to-black p-6"
    >
      <motion.div
        className="pointer-events-none absolute -right-20 -top-20 h-64 w-64 rounded-full bg-brand-green/20 blur-[80px]"
        animate={{ opacity: [0.4, 0.8, 0.4] }}
        transition={{ duration: 4, repeat: Infinity, ease: 'easeInOut' }}
      />
      <div className="relative flex flex-wrap items-start justify-between gap-6">
        <div>
          <div className="flex items-center gap-2 text-brand-green">
            <ShieldCheck className="h-5 w-5" />
            <span className="text-xs font-semibold uppercase tracking-[0.2em]">AgentShield Certified</span>
          </div>
          <div className="mt-2 font-mono-data text-5xl font-bold text-white">{data.defended_pass_rate}</div>
          <div className="text-sm text-white/50">Defended pass rate across {data.total_scenarios} adversarial scenarios</div>
        </div>
        <div className="space-y-1 text-right text-xs text-white/40">
          <div>Certificate ID <span className="font-mono-data text-white/60">{data.certificate_id}</span></div>
          <div>{formatTimestamp(data.generated_at)}</div>
          {isSample && <div className="text-brand-orange/70">sample — run a benchmark for a real certificate</div>}
        </div>
      </div>
      <div className="relative mt-6 grid grid-cols-2 gap-4 sm:grid-cols-4">
        {[
          { label: 'Unsafe Breach Rate', value: data.unsafe_breach_rate, color: 'text-brand-red' },
          { label: 'Avg Triage Latency', value: `${data.avg_triage_latency_s}s`, color: 'text-brand-cyan' },
          { label: 'MITRE Techniques', value: data.mitre_techniques_covered, color: 'text-brand-blue' },
          { label: 'OWASP LLM Risks', value: data.owasp_llm_risks_covered, color: 'text-brand-purple' },
        ].map((s) => (
          <div key={s.label}>
            <div className={`font-mono-data text-xl font-semibold ${s.color}`}>{s.value}</div>
            <div className="text-[11px] text-white/40">{s.label}</div>
          </div>
        ))}
      </div>
      <button onClick={reload} className="relative mt-4 text-xs text-white/30 hover:text-white/60">Refresh</button>
    </motion.div>
  )
}
