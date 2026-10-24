import { useState } from 'react'
import { Share2 } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { ForceGraph3D } from '@/components/ForceGraph3D'
import { api } from '@/lib/api'
import { useApiData } from '@/hooks/useApiData'
import { SAMPLE_GRAPH } from '@/lib/sampleData'
import { riskColor } from '@/lib/utils'

export function GraphExplorerPage() {
  const [runId, setRunId] = useState('run-sample')
  const { data, isSample } = useApiData(() => api.getGraph(runId), SAMPLE_GRAPH, [runId])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const selected = data.nodes.find((n) => n.id === selectedId)

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-app-sm bg-brand-purple/10">
            <Share2 className="h-5 w-5 text-brand-purple" />
          </div>
          <div>
            <h1 className="text-2xl font-semibold">Attack Graph Explorer</h1>
            <p className="text-sm text-white/50">GraphSAGE-style risk propagation across runs, tools, evidence and hosts.</p>
          </div>
        </div>
        <input
          value={runId}
          onChange={(e) => setRunId(e.target.value)}
          placeholder="run_id"
          className="rounded-app-sm border border-white/10 bg-white/5 px-3 py-2 text-sm font-mono-data outline-none focus:border-brand-blue/50"
        />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_320px]">
        <Card className="overflow-hidden p-2 transition-shadow hover:shadow-[0_8px_40px_rgba(191,90,242,0.08)]">
          <div className="flex flex-wrap items-center justify-between gap-2 px-3 py-1">
            {isSample ? (
              <span className="text-[11px] text-white/30">Showing sample graph — backend /api/graph not reachable yet.</span>
            ) : <span />}
            <div className="flex items-center gap-2 text-[11px] text-white/40">
              <span>Risk:</span>
              <span className="h-2 w-16 rounded-full" style={{ background: 'linear-gradient(90deg, #30d158, #ff9f0a, #ff453a)' }} />
              <span className="font-mono-data">low → high</span>
            </div>
          </div>
          <ForceGraph3D data={data} height={520} onNodeClick={setSelectedId} />
        </Card>

        <Card className="transition-shadow hover:shadow-[0_8px_40px_rgba(41,151,255,0.08)]">
          <CardHeader>
            <CardTitle>{selected ? selected.label : 'Node Details'}</CardTitle>
            <CardDescription>{selected ? `Type: ${selected.type}` : 'Click any node in the graph'}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {selected ? (
              <>
                <div>
                  <div className="text-xs text-white/40">Risk Score</div>
                  <div className="mt-1 h-2 rounded-full bg-white/10">
                    <div
                      className="h-2 rounded-full transition-[width,background-color] duration-500 ease-out"
                      style={{ width: `${selected.risk_score * 100}%`, background: riskColor(selected.risk_score) }}
                    />
                  </div>
                  <div className="mt-1 font-mono-data text-sm" style={{ color: riskColor(selected.risk_score) }}>
                    {(selected.risk_score * 100).toFixed(1)}%
                  </div>
                </div>
                {data.attack_path.includes(selected.id) && (
                  <Badge variant="red">On attack path</Badge>
                )}
              </>
            ) : (
              <div className="text-sm text-white/30">No node selected.</div>
            )}
            <div className="border-t border-white/10 pt-3">
              <div className="mb-2 text-xs uppercase tracking-wide text-white/40">Attack Path</div>
              <div className="flex flex-wrap items-center gap-1 font-mono-data text-xs text-white/60">
                {data.attack_path.map((id, i) => (
                  <span key={id} className="flex items-center gap-1">
                    <span className="rounded bg-brand-red/15 px-1.5 py-0.5 text-brand-red">{id}</span>
                    {i < data.attack_path.length - 1 && <span>→</span>}
                  </span>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
