import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { ScanSearch, ShieldAlert, ShieldCheck, OctagonAlert, TriangleAlert } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { api, type DlpInspectResult } from '@/lib/api'
import { useApiData } from '@/hooks/useApiData'
import { SAMPLE_DLP_PATTERNS } from '@/lib/sampleData'

export function DlpInspectorPage() {
  const { data: patternData } = useApiData(api.getDlpPatterns, { patterns: SAMPLE_DLP_PATTERNS, count: SAMPLE_DLP_PATTERNS.length })
  const [toolName, setToolName] = useState('create_mock_ticket')
  const [argKey, setArgKey] = useState('title')
  const [argValue, setArgValue] = useState("Found credential AKIAABCDEFGHIJKLMNOP in logs")
  const [result, setResult] = useState<DlpInspectResult | null>(null)
  const [busy, setBusy] = useState(false)

  async function test() {
    setBusy(true)
    try {
      const res = await api.inspectDlp({ tool_name: toolName, arguments: { [argKey]: argValue } })
      setResult(res)
    } catch {
      const blocked = /AKIA|sk-|BEGIN (RSA|OPENSSH)|shadow|password\s*=/i.test(argValue)
      setResult({
        blocked,
        violations: blocked ? [{ pattern_id: 'DLP-AWS-KEY', severity: 'BLOCK', description: 'AWS Access Key ID pattern matched', matched_text: argValue.slice(0, 40) }] : [],
        inspection_summary: blocked ? '1 blocking violation found (offline heuristic check)' : 'Clean (offline heuristic check)',
      })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-app-sm bg-brand-purple/10">
          <ShieldAlert className="h-5 w-5 text-brand-purple" />
        </div>
        <div>
          <h1 className="text-2xl font-semibold">DLP Inspector</h1>
          <p className="text-sm text-white/50">Test any argument value against the full semantic DLP pattern registry.</p>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card className="transition-shadow hover:shadow-[0_8px_40px_rgba(191,90,242,0.08)]">
          <CardHeader><CardTitle>Test an Argument</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            <Input placeholder="tool_name" value={toolName} onChange={(e) => setToolName(e.target.value)} />
            <Input placeholder="argument key" value={argKey} onChange={(e) => setArgKey(e.target.value)} />
            <textarea
              value={argValue}
              onChange={(e) => setArgValue(e.target.value)}
              rows={4}
              className="w-full rounded-app-sm border border-white/10 bg-white/5 px-3 py-2 text-sm outline-none focus:border-brand-blue/50"
            />
            <Button onClick={test} disabled={busy} className="w-full">
              <ScanSearch className="h-4 w-4" /> {busy ? 'Inspecting…' : 'Inspect'}
            </Button>
            <AnimatePresence mode="wait">
              {result && (
                <motion.div
                  key={result.blocked ? 'blocked' : 'passed'}
                  initial={{ opacity: 0, y: 8, scale: 0.98 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0 }}
                  className={`rounded-app-sm p-3 text-sm ${result.blocked ? 'bg-brand-red/10 text-brand-red' : 'bg-brand-green/10 text-brand-green'}`}
                >
                  <div className="flex items-center gap-2 font-semibold">
                    {result.blocked ? <OctagonAlert className="h-4 w-4" /> : <ShieldCheck className="h-4 w-4" />}
                    {result.blocked ? 'BLOCKED' : 'PASSED'}
                  </div>
                  <div className="mt-1 text-xs text-white/60">{result.inspection_summary}</div>
                  {result.violations.map((v, i) => (
                    <motion.div
                      key={i}
                      initial={{ opacity: 0, x: -6 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: 0.08 * i }}
                      className="mt-2 flex items-center gap-2 font-mono-data text-xs"
                    >
                      <Badge variant={v.severity === 'BLOCK' ? 'red' : 'orange'}>
                        {v.severity === 'BLOCK' ? <OctagonAlert className="h-3 w-3" /> : <TriangleAlert className="h-3 w-3" />}
                        {v.pattern_id}
                      </Badge>
                      <span className="text-white/50">{v.description}</span>
                    </motion.div>
                  ))}
                </motion.div>
              )}
            </AnimatePresence>
          </CardContent>
        </Card>

        <Card className="transition-shadow hover:shadow-[0_8px_40px_rgba(191,90,242,0.08)]">
          <CardHeader>
            <CardTitle>Active DLP Pattern Registry ({patternData.count} patterns)</CardTitle>
            <CardDescription>13+ regex and entropy signatures evaluated on every permitted tool call</CardDescription>
          </CardHeader>
          <CardContent className="scrollbar-thin max-h-[420px] space-y-2 overflow-y-auto">
            {patternData.patterns.map((p) => (
              <div key={p.pattern_id} className="flex items-start gap-2 rounded-app-sm bg-white/[0.03] px-3 py-2 transition-colors hover:bg-white/[0.06]">
                <Badge variant={p.severity === 'BLOCK' ? 'red' : 'orange'}>
                  {p.severity === 'BLOCK' ? <OctagonAlert className="h-3 w-3" /> : <TriangleAlert className="h-3 w-3" />}
                  {p.severity}
                </Badge>
                <div>
                  <div className="font-mono-data text-xs">{p.pattern_id}</div>
                  <div className="text-xs text-white/50">{p.description}</div>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
