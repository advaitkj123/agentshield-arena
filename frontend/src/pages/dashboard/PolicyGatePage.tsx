import { ShieldCheck, ShieldAlert, Lock, Eye, ShieldX } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { api } from '@/lib/api'
import { useApiData } from '@/hooks/useApiData'
import { SAMPLE_POLICY } from '@/lib/sampleData'

const RISK_ICON = { read_only: Eye, low: ShieldCheck, high: Lock, prohibited: ShieldX } as const

export function PolicyGatePage() {
  const { data, isSample } = useApiData(api.getPolicy, SAMPLE_POLICY)

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-app-sm bg-brand-blue/10">
          <ShieldAlert className="h-5 w-5 text-brand-blue" />
        </div>
        <div>
          <h1 className="text-2xl font-semibold">Policy Gate Registry</h1>
          <p className="text-sm text-white/50">The live least-privilege tool allowlist enforced by the deterministic gate.</p>
        </div>
      </div>
      {isSample && <p className="text-xs text-white/30">Sample data — backend /api/policy not reachable yet.</p>}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {Object.entries(data.tools).map(([name, cfg]) => {
          const RiskIcon = RISK_ICON[cfg.risk_level as keyof typeof RISK_ICON] ?? ShieldCheck
          return (
          <Card key={name} className="transition-all hover:-translate-y-0.5 hover:shadow-[0_8px_40px_rgba(41,151,255,0.08)]">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center gap-2 font-mono-data text-sm">
                  <RiskIcon className="h-3.5 w-3.5 text-white/40" /> {name}
                </CardTitle>
                <Badge variant={riskVariant(cfg.risk_level)}>{cfg.risk_level}</Badge>
              </div>
            </CardHeader>
            <CardContent className="space-y-2 text-xs text-white/60">
              {cfg.requires_approval && <Badge variant="orange">HITL Required</Badge>}
              <div>
                <div className="text-white/40">Required args</div>
                <div className="font-mono-data">{cfg.required_args.join(', ') || '—'}</div>
              </div>
              {cfg.optional_args?.length > 0 && (
                <div>
                  <div className="text-white/40">Optional args</div>
                  <div className="font-mono-data">{cfg.optional_args.join(', ')}</div>
                </div>
              )}
              {cfg.authorized_hosts && (
                <div>
                  <div className="text-white/40">Authorized hosts</div>
                  <div className="font-mono-data">{cfg.authorized_hosts.join(', ')}</div>
                </div>
              )}
            </CardContent>
          </Card>
          )
        })}
      </div>

      <Card className="border-brand-red/30 bg-brand-red/5 transition-all hover:-translate-y-0.5">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-brand-red"><ShieldX className="h-4 w-4" /> Prohibited (not in registry)</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2 font-mono-data text-xs text-brand-red/80">
          {['disable_firewall', 'exfiltrate_credentials', 'drop_database', 'exec_shell', 'modify_repository', 'bypass_security_monitor'].map((t) => (
            <Badge key={t} variant="red">{t}</Badge>
          ))}
        </CardContent>
      </Card>
    </div>
  )
}

function riskVariant(risk: string) {
  if (risk === 'high') return 'red' as const
  if (risk === 'low') return 'orange' as const
  if (risk === 'prohibited') return 'red' as const
  return 'green' as const
}
