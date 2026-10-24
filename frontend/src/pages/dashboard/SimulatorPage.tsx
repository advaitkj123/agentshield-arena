import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { FlaskConical, ShieldAlert, ShieldCheck } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from '@/components/ui/select'
import { MetricsGrid } from '@/components/MetricsGrid'
import { api, type SimulateResponse } from '@/lib/api'
import { SAMPLE_METRICS, SAMPLE_SCENARIOS, SAMPLE_UNSAFE_METRICS } from '@/lib/sampleData'
import { cn } from '@/lib/utils'

export function SimulatorPage() {
  const [scenarioPath, setScenarioPath] = useState(SAMPLE_SCENARIOS[0].path)
  const [disableDlp, setDisableDlp] = useState(false)
  const [disableTool, setDisableTool] = useState('')
  const [disableHitl, setDisableHitl] = useState(false)
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<SimulateResponse | null>(null)

  async function simulate() {
    setBusy(true)
    try {
      const res = await api.simulate({
        scenario_path: scenarioPath,
        disable_dlp: disableDlp,
        remove_from_allowlist: disableTool || undefined,
        disable_hitl: disableHitl,
      })
      setResult(res)
    } catch {
      // Backend not reachable yet — show an illustrative before/after using sample metrics.
      setResult({
        decision_trace: [],
        baseline_metrics: SAMPLE_METRICS,
        metrics: disableDlp || disableHitl || disableTool ? SAMPLE_UNSAFE_METRICS : SAMPLE_METRICS,
      })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-app-sm bg-brand-orange/10">
          <FlaskConical className="h-5 w-5 text-brand-orange" />
        </div>
        <div>
          <h1 className="text-2xl font-semibold">What-If Simulator</h1>
          <p className="text-sm text-white/50">Weaken a policy layer and see exactly how much risk reappears.</p>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[360px_1fr]">
        <Card className="transition-shadow hover:shadow-[0_8px_40px_rgba(255,159,10,0.08)]">
          <CardHeader>
            <CardTitle>Policy Modifications</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <label className="mb-1.5 block text-xs text-white/50">Scenario</label>
              <Select value={scenarioPath} onValueChange={setScenarioPath}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {SAMPLE_SCENARIOS.map((s) => (
                    <SelectItem key={s.scenario_id} value={s.path}>{s.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-white/70">Disable Semantic DLP (Layer 4)</span>
              <Switch checked={disableDlp} onCheckedChange={setDisableDlp} />
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-white/70">Disable HITL Requirement (Layer 3)</span>
              <Switch checked={disableHitl} onCheckedChange={setDisableHitl} />
            </div>
            <div>
              <label className="mb-1.5 block text-xs text-white/50">Remove tool from allowlist (Layer 1)</label>
              <Select value={disableTool} onValueChange={setDisableTool}>
                <SelectTrigger><SelectValue placeholder="None" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="simulate_endpoint_isolation">simulate_endpoint_isolation</SelectItem>
                  <SelectItem value="create_mock_ticket">create_mock_ticket</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <Button onClick={simulate} disabled={busy} className="w-full">
              <FlaskConical className="h-4 w-4" /> {busy ? 'Simulating…' : 'Run Simulation'}
            </Button>
          </CardContent>
        </Card>

        <Card className={cn(
          'transition-shadow',
          result && (result.metrics.uaer_numeric ?? 0) > 0
            ? 'border-brand-red/40 shadow-[0_8px_40px_rgba(255,69,58,0.1)]'
            : 'hover:shadow-[0_8px_40px_rgba(255,159,10,0.08)]',
        )}>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Metrics Comparison</CardTitle>
                <CardDescription>Real/defended run vs. this hypothetical configuration</CardDescription>
              </div>
              <AnimatePresence>
                {result && (
                  <motion.div initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }}>
                    {(result.metrics.uaer_numeric ?? 0) > 0 ? (
                      <span className="flex items-center gap-1.5 rounded-pill bg-brand-red/15 px-3 py-1 text-xs font-semibold text-brand-red">
                        <ShieldAlert className="h-3.5 w-3.5" /> Breach reintroduced
                      </span>
                    ) : (
                      <span className="flex items-center gap-1.5 rounded-pill bg-brand-green/15 px-3 py-1 text-xs font-semibold text-brand-green">
                        <ShieldCheck className="h-3.5 w-3.5" /> Still defended
                      </span>
                    )}
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </CardHeader>
          <CardContent>
            {result ? (
              <MetricsGrid metrics={result.metrics} compare={result.baseline_metrics} />
            ) : (
              <div className="py-10 text-center text-sm text-white/30">Run a simulation to see the before/after delta.</div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
