import { Mail, Send, Bot, CheckCircle2, XCircle } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ChatWidget } from '@/components/ChatWidget'
import { api } from '@/lib/api'
import { useApiData } from '@/hooks/useApiData'
import { cn } from '@/lib/utils'

const SAMPLE_STATUS = {
  brevo_email: { configured: false },
  telegram: { configured: false },
  gemini_ai: { configured: false },
}

export function IntegrationsPage() {
  const { data, isSample, reload } = useApiData(api.getIntegrationsStatus, SAMPLE_STATUS)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Integrations &amp; Alerts</h1>
        <p className="text-sm text-white/50">Brevo email, Telegram push, and the Gemini AI Security Advisor.</p>
        {isSample && <p className="text-xs text-white/30">Sample status — backend /api/integrations/status not reachable yet.</p>}
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <IntegrationCard
          icon={Mail}
          title="Brevo Email"
          configured={data.brevo_email.configured}
          onTest={() => api.testEmail().catch(() => {})}
          testLabel="Send Test Email"
        />
        <IntegrationCard
          icon={Send}
          title="Telegram Bot"
          configured={data.telegram.configured}
          onTest={() => api.testTelegram().catch(() => {})}
          testLabel="Send Test Alert"
        />
        <IntegrationCard icon={Bot} title="Gemini AI Advisor" configured={data.gemini_ai.configured} />
      </div>

      <Button variant="secondary" size="sm" onClick={reload}>Refresh Status</Button>

      <Card>
        <CardHeader>
          <CardTitle>AI Security Advisor</CardTitle>
          <CardDescription>Embedded panel — same shared component as the floating widget</CardDescription>
        </CardHeader>
        <CardContent>
          <ChatWidget mode="embedded" />
        </CardContent>
      </Card>
    </div>
  )
}

function IntegrationCard({
  icon: Icon,
  title,
  configured,
  onTest,
  testLabel,
}: {
  icon: typeof Mail
  title: string
  configured: boolean
  onTest?: () => void
  testLabel?: string
}) {
  return (
    <Card
      className={cn(
        'overflow-hidden border-l-2 transition-all hover:-translate-y-0.5',
        configured ? 'border-l-brand-green/60 hover:shadow-[0_8px_40px_rgba(48,209,88,0.08)]' : 'border-l-white/15',
      )}
    >
      <CardHeader className="flex flex-row items-center justify-between">
        <div className="flex items-center gap-2">
          <div className={cn('flex h-8 w-8 items-center justify-center rounded-app-sm', configured ? 'bg-brand-green/10' : 'bg-white/5')}>
            <Icon className={cn('h-4 w-4', configured ? 'text-brand-green' : 'text-white/40')} />
          </div>
          <CardTitle className="text-sm">{title}</CardTitle>
        </div>
        <Badge variant={configured ? 'green' : 'muted'}>
          {configured ? <CheckCircle2 className="h-3 w-3" /> : <XCircle className="h-3 w-3" />}
          {configured ? 'Configured' : 'Not Configured'}
        </Badge>
      </CardHeader>
      {onTest && (
        <CardContent>
          <Button variant="outline" size="sm" onClick={onTest} disabled={!configured}>{testLabel}</Button>
        </CardContent>
      )}
    </Card>
  )
}
