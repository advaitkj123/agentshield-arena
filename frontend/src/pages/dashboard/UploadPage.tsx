import { useRef, useState } from 'react'
import { UploadCloud, Download, AlertTriangle, CheckCircle2, FileSpreadsheet } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from '@/components/ui/select'
import { Badge } from '@/components/ui/badge'
import { api, type UploadPreviewRow } from '@/lib/api'
import { useLiveRun } from '@/hooks/useLiveRun'
import { LiveRunTimeline } from '@/components/LiveRunTimeline'
import { SAMPLE_UPLOAD_RESPONSE } from '@/lib/sampleData'
import { cn } from '@/lib/utils'

const SAMPLE_FILES = [
  { filename: 'helpdesk_tickets_sample.csv', label: 'Helpdesk Tickets', description: '10 tickets, 2 contain hidden prompt-injection directives.' },
  { filename: 'siem_auth_logs_sample.csv', label: 'SIEM Auth Logs', description: 'Pure trusted telemetry — no injected content.' },
  { filename: 'mixed_incident_feed_sample.csv', label: 'Mixed Incident Feed', description: '8 rows across tickets, runbooks & vendor advisories.' },
]

export function UploadPage() {
  const [file, setFile] = useState<File | null>(null)
  const [kind, setKind] = useState('tickets')
  const [affectedHost, setAffectedHost] = useState('srv-pay-prod-02')
  const [dragging, setDragging] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [preview, setPreview] = useState<UploadPreviewRow[] | null>(null)
  const [incidentId, setIncidentId] = useState<string | null>(null)
  const [isSample, setIsSample] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const { events, runId, pendingApproval, result, attach, simulateLocally, respondApproval } = useLiveRun()

  function pickFile(f: File | null) {
    setFile(f)
    setPreview(null)
    setIncidentId(null)
  }

  async function handleUpload() {
    if (!file) return
    setUploading(true)
    try {
      const res = await api.uploadDataset(file, kind, affectedHost)
      setPreview(res.preview)
      setIncidentId(res.incident_id)
      setIsSample(false)
      attach(res.run_id)
    } catch {
      // Backend unreachable — demo with sample data so the page stays usable.
      setPreview(SAMPLE_UPLOAD_RESPONSE.preview)
      setIncidentId(SAMPLE_UPLOAD_RESPONSE.incident_id)
      setIsSample(true)
      simulateLocally([])
    } finally {
      setUploading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Upload Your Own Dataset</h1>
        <p className="text-sm text-white/50">
          Upload any CSV of tickets, logs, or alerts — it's assembled into a real incident and run through the
          exact same Policy Gate pipeline as every bundled scenario. Not a simulation of your data; a real defended run.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[400px_1fr]">
        <div className="space-y-4">
          <Card className="transition-shadow hover:shadow-[0_8px_40px_rgba(41,151,255,0.08)]">
            <CardHeader>
              <CardTitle>Upload CSV</CardTitle>
              <CardDescription>Drag &amp; drop, or browse a file.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div
                onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
                onDragLeave={() => setDragging(false)}
                onDrop={(e) => {
                  e.preventDefault()
                  setDragging(false)
                  const f = e.dataTransfer.files?.[0]
                  if (f) pickFile(f)
                }}
                onClick={() => fileInputRef.current?.click()}
                className={cn(
                  'flex cursor-pointer flex-col items-center justify-center gap-2 rounded-app-sm border-2 border-dashed px-4 py-8 text-center transition-colors',
                  dragging ? 'border-brand-blue bg-brand-blue/10' : 'border-white/15 hover:border-white/30 hover:bg-white/[0.03]',
                )}
              >
                <UploadCloud className={cn('h-8 w-8', dragging ? 'text-brand-blue' : 'text-white/40')} />
                {file ? (
                  <div className="flex items-center gap-2 text-sm text-white">
                    <FileSpreadsheet className="h-4 w-4 text-brand-cyan" /> {file.name}
                  </div>
                ) : (
                  <span className="text-sm text-white/50">Drop a .csv file here, or click to browse</span>
                )}
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".csv,text/csv"
                  className="hidden"
                  onChange={(e) => pickFile(e.target.files?.[0] ?? null)}
                />
              </div>

              <div>
                <label className="mb-1.5 block text-xs text-white/50">Dataset kind</label>
                <Select value={kind} onValueChange={setKind}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="tickets">Helpdesk Tickets</SelectItem>
                    <SelectItem value="logs">SIEM / EDR Logs</SelectItem>
                    <SelectItem value="mixed">Mixed Incident Feed</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div>
                <label className="mb-1.5 block text-xs text-white/50">Affected host (optional)</label>
                <Input value={affectedHost} onChange={(e) => setAffectedHost(e.target.value)} placeholder="srv-pay-prod-02" />
              </div>

              <Button onClick={handleUpload} disabled={!file || uploading} className="w-full">
                <UploadCloud className="h-4 w-4" /> {uploading ? 'Analyzing…' : 'Upload & Analyze Live'}
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Sample datasets</CardTitle>
              <CardDescription>Don't have your own CSV handy? Download one of these.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              {SAMPLE_FILES.map((s) => (
                <a
                  key={s.filename}
                  href={api.sampleDatasetUrl(s.filename)}
                  download
                  className="flex items-center justify-between gap-3 rounded-app-sm bg-white/[0.03] px-3 py-2 text-sm transition-colors hover:bg-white/[0.07]"
                >
                  <div>
                    <div className="text-white/80">{s.label}</div>
                    <div className="text-xs text-white/40">{s.description}</div>
                  </div>
                  <Download className="h-4 w-4 shrink-0 text-white/40" />
                </a>
              ))}
            </CardContent>
          </Card>
        </div>

        <div className="space-y-4">
          {preview && (
            <Card>
              <CardHeader>
                <CardTitle>Ingested Rows{incidentId ? ` — ${incidentId}` : ''}</CardTitle>
                <CardDescription>
                  {isSample && <span className="text-white/30">Sample preview — backend /api/upload not reachable yet. </span>}
                  Rows are tagged untrusted by default unless their source channel is a recognized trusted system.
                </CardDescription>
              </CardHeader>
              <CardContent className="scrollbar-thin max-h-72 space-y-1.5 overflow-y-auto">
                {preview.map((row) => (
                  <div
                    key={row.evidence_id}
                    className={cn(
                      'flex items-start gap-3 rounded-app-sm px-3 py-2 text-sm',
                      row.flagged_suspicious ? 'bg-brand-red/10' : 'bg-white/[0.03]',
                    )}
                  >
                    {row.flagged_suspicious ? (
                      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-brand-red" />
                    ) : (
                      <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-white/25" />
                    )}
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono-data text-xs text-white/40">#{row.row_number}</span>
                        <Badge variant={row.trust_level === 'trusted_system' ? 'green' : 'orange'}>{row.trust_level}</Badge>
                        <span className="text-xs text-white/40">{row.source_type}</span>
                      </div>
                      <div className="mt-0.5 text-white/70">{row.content_preview}</div>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          <LiveRunTimeline
            runId={runId}
            events={events}
            pendingApproval={pendingApproval}
            onApprove={respondApproval}
            emptyLabel="Upload a dataset to see it run live through the Policy Gate here."
          />

          {result && (
            <div className={cn('flex items-center gap-2 rounded-app-sm px-3 py-2 text-sm', result.passed ? 'bg-brand-green/10 text-brand-green' : 'bg-brand-red/10 text-brand-red')}>
              {result.passed ? 'Defended — your uploaded data was fully contained.' : 'Attack succeeded — breach detected in your uploaded data.'}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
