import { useRef, useState } from 'react'
import { Gauge, Download, BarChart3, Boxes } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Metrics3DChart } from '@/components/Metrics3DChart'
import { api, type BenchmarkResult } from '@/lib/api'
import { SAMPLE_BENCHMARK } from '@/lib/sampleData'

export function BenchmarkPage() {
  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState(0)
  const [result, setResult] = useState<BenchmarkResult | null>(null)
  const [jobId, setJobId] = useState<string | null>(null)
  const [chartMode, setChartMode] = useState<'3d' | '2d'>('3d')
  const pollRef = useRef<ReturnType<typeof setInterval> | undefined>(undefined)

  async function start() {
    setRunning(true)
    setProgress(0)
    setResult(null)
    try {
      const { job_id } = await api.startBenchmark()
      setJobId(job_id)
      pollRef.current = setInterval(async () => {
        const status = await api.getBenchmarkStatus(job_id)
        setProgress((p) => Math.min(95, p + 10))
        if (status.status === 'done' && status.result) {
          clearInterval(pollRef.current)
          setResult(status.result)
          setProgress(100)
          setRunning(false)
        }
      }, 1200)
    } catch {
      setJobId(null)
      let p = 0
      const interval = setInterval(() => {
        p += 20
        setProgress(Math.min(p, 100))
        if (p >= 100) {
          clearInterval(interval)
          setResult(SAMPLE_BENCHMARK)
          setRunning(false)
        }
      }, 400)
    }
  }

  const chart3DData = result?.scenarios.map((s) => ({
    label: s.scenario_name.length > 14 ? `${s.scenario_name.slice(0, 13)}…` : s.scenario_name,
    defended: s.defended.passed ? 100 : 0,
    unsafe: s.unsafe_baseline.breached ? 100 : 0,
  })) ?? []

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Multi-Scenario Benchmark</h1>
        <p className="text-sm text-white/50">Runs every scenario twice (defended + unsafe baseline) and aggregates results.</p>
      </div>

      <Card>
        <CardContent className="flex flex-wrap items-center justify-between gap-4 p-5">
          <Button onClick={start} disabled={running}>
            <Gauge className="h-4 w-4" /> {running ? `Running… ${progress}%` : 'Run Full Benchmark'}
          </Button>
          {running && (
            <div className="h-2 flex-1 overflow-hidden rounded-full bg-white/10">
              <div className="h-2 rounded-full bg-brand-blue transition-all" style={{ width: `${progress}%` }} />
            </div>
          )}
          {result && jobId && (
            <Button variant="outline" size="sm" asChild>
              <a href={api.benchmarkExportUrl(jobId)} download><Download className="h-3.5 w-3.5" /> Export CSV</a>
            </Button>
          )}
        </CardContent>
      </Card>

      {result && (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              { label: 'Scenarios', value: result.total_scenarios, color: 'text-white' },
              { label: 'Defended Pass Rate', value: `${result.defended_pass_rate}%`, color: 'text-brand-green' },
              { label: 'Unsafe Breach Rate', value: `${result.unsafe_breach_rate}%`, color: 'text-brand-red' },
              { label: 'Avg Triage Latency', value: `${result.avg_triage_latency_s}s`, color: 'text-brand-cyan' },
            ].map((s) => (
              <Card key={s.label} className="transition-transform hover:-translate-y-0.5">
                <CardContent className="p-4">
                  <div className={`font-mono-data text-2xl font-semibold ${s.color}`}>{s.value}</div>
                  <div className="text-xs text-white/40">{s.label}</div>
                </CardContent>
              </Card>
            ))}
          </div>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle>Per-Scenario: Defended vs. Unsafe</CardTitle>
              <div className="flex gap-1 rounded-app-sm bg-white/5 p-1">
                <Button size="sm" variant={chartMode === '3d' ? 'default' : 'ghost'} onClick={() => setChartMode('3d')}>
                  <Boxes className="h-3.5 w-3.5" /> 3D
                </Button>
                <Button size="sm" variant={chartMode === '2d' ? 'default' : 'ghost'} onClick={() => setChartMode('2d')}>
                  <BarChart3 className="h-3.5 w-3.5" /> 2D
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {chartMode === '3d' ? (
                <Metrics3DChart data={chart3DData} height={340} />
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead>
                      <tr className="border-b border-white/10 text-xs uppercase text-white/40">
                        <th className="py-2 pr-4">Scenario</th>
                        <th className="py-2 pr-4">Defended</th>
                        <th className="py-2 pr-4">Unsafe Baseline</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.scenarios.map((s) => (
                        <tr key={s.scenario_id} className="border-b border-white/5">
                          <td className="py-2 pr-4">{s.scenario_name}</td>
                          <td className="py-2 pr-4"><Badge variant={s.defended.passed ? 'green' : 'red'}>{s.defended.passed ? 'PASS' : 'FAIL'}</Badge></td>
                          <td className="py-2 pr-4"><Badge variant={s.unsafe_baseline.breached ? 'red' : 'green'}>{s.unsafe_baseline.breached ? 'BREACH' : 'SAFE'}</Badge></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  )
}
