import { useState } from 'react'
import { Play, Trash2, CheckCircle2, XCircle } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { api } from '@/lib/api'
import { useApiData } from '@/hooks/useApiData'
import { useLiveRun } from '@/hooks/useLiveRun'
import { LiveRunTimeline } from '@/components/LiveRunTimeline'
import { SAMPLE_SCENARIOS, buildSampleAuditTrail } from '@/lib/sampleData'
import { cn } from '@/lib/utils'

export function ScenarioRunnerPage() {
  const { data: scenarioData } = useApiData(api.getScenarios, { scenarios: SAMPLE_SCENARIOS })
  const [scenarioPath, setScenarioPath] = useState(SAMPLE_SCENARIOS[0].path)
  const [adversarial, setAdversarial] = useState(true)
  const [policyGate, setPolicyGate] = useState(true)
  const { events, running, runId, pendingApproval, result, attach, simulateLocally, respondApproval, clear } = useLiveRun()

  async function run() {
    try {
      const res = await api.runScenario({
        mode: 'incident',
        scenario_path: scenarioPath,
        adversarial,
        disable_policy_gate: !policyGate,
      })
      attach(res.run_id)
    } catch {
      // Backend not reachable yet — fall back to a local simulated run so the page stays demoable.
      simulateLocally(buildSampleAuditTrail(`run-${Math.random().toString(16).slice(2, 10)}`))
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Scenario Runner</h1>
        <p className="text-sm text-white/50">Execute an adversarial incident scenario and watch the Policy Gate respond live.</p>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[360px_1fr]">
        <Card className="transition-shadow hover:shadow-[0_8px_40px_rgba(41,151,255,0.08)]">
          <CardHeader>
            <CardTitle>Configuration</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <label className="mb-1.5 block text-xs text-white/50">Scenario</label>
              <Select value={scenarioPath} onValueChange={setScenarioPath}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {scenarioData.scenarios.map((s) => (
                    <SelectItem key={s.scenario_id} value={s.path}>{s.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-white/70">Adversarial Injection</span>
              <Switch checked={adversarial} onCheckedChange={setAdversarial} />
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-white/70">Policy Gate Enabled</span>
              <Switch checked={policyGate} onCheckedChange={setPolicyGate} />
            </div>
            <div className="flex gap-2 pt-2">
              <Button onClick={run} disabled={running} className="flex-1">
                <Play className="h-4 w-4" /> {running ? 'Running…' : 'Execute Scenario'}
              </Button>
              <Button variant="outline" size="icon" onClick={clear}><Trash2 className="h-4 w-4" /></Button>
            </div>
            {result && (
              <div className={cn('flex items-center gap-2 rounded-app-sm px-3 py-2 text-sm', result.passed ? 'bg-brand-green/10 text-brand-green' : 'bg-brand-red/10 text-brand-red')}>
                {result.passed ? <CheckCircle2 className="h-4 w-4" /> : <XCircle className="h-4 w-4" />}
                {result.passed ? 'Scenario defended successfully' : 'Attack succeeded — breach detected'}
              </div>
            )}
          </CardContent>
        </Card>

        <LiveRunTimeline runId={runId} events={events} pendingApproval={pendingApproval} onApprove={respondApproval} />
      </div>
    </div>
  )
}
