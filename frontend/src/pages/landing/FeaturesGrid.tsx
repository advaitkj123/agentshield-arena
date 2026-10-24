import { motion } from 'framer-motion'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import {
  ShieldCheck, Bot, ScanSearch, Swords, Mail, Gavel, LineChart, Radio, Lock,
} from 'lucide-react'

const FEATURES = [
  {
    icon: ShieldCheck,
    title: 'Four-Layer Policy Gate',
    desc: 'Tool allowlist → argument schema → HITL approval → semantic DLP. Every layer is deterministic code, never a model.',
    span: true,
    tag: 'Core Architecture',
    tagVariant: 'default' as const,
  },
  { icon: Bot, title: 'Gemini AI Advisor', desc: 'Floating chatbot powered by Gemini 2.5 Flash — explains decisions, analyzes incidents, multi-turn context.', tag: 'New', tagVariant: 'green' as const },
  { icon: ScanSearch, title: 'Semantic DLP Inspector', desc: '13 regex + entropy signatures blocking credentials, API keys, S3 URLs, shadow files.' },
  { icon: Swords, title: '11 Adversarial Scenarios', desc: 'Covers MITRE ATT&CK techniques and OWASP LLM Top 10 categories across IT, cloud, and OT domains.' },
  { icon: Mail, title: 'Email & Telegram Alerts', desc: 'Automated Brevo + Telegram notifications for policy blocks, DLP violations, and HITL requests.', tag: 'New', tagVariant: 'green' as const },
  { icon: Gavel, title: 'Human-in-the-Loop', desc: 'Cryptographically bound, single-use approval tokens gate every high-impact action.' },
  { icon: LineChart, title: '7 Evaluation Metrics', desc: 'TCR, UAER, ASR, FBR, ACR, MTTD, Threat Score — scored on every run, visualized live.' },
  { icon: Radio, title: 'Live Streaming Dashboard', desc: 'FastAPI + Server-Sent Events push every decision to the UI the instant it happens.', tag: 'Open Source', tagVariant: 'default' as const },
  { icon: Lock, title: 'Immutable Audit Trail', desc: 'Append-only JSONL with run-ID isolation — a full forensic chain of custody.' },
]

export function FeaturesGrid() {
  return (
    <section id="features" className="mx-auto max-w-6xl px-4 py-24 sm:px-6">
      <motion.div initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} className="mb-12 text-center">
        <div className="text-sm font-medium uppercase tracking-wide text-brand-blue/80">Capabilities</div>
        <h2 className="mt-3 text-3xl font-bold tracking-tight sm:text-4xl">Everything you need to trust your AI agents.</h2>
      </motion.div>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {FEATURES.map((f, i) => (
          <motion.div
            key={f.title}
            initial={{ opacity: 0, y: 16 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: (i % 3) * 0.06 }}
            className={f.span ? 'sm:col-span-2' : ''}
          >
            <Card className="h-full transition-colors hover:bg-white/[0.06]">
              <CardHeader>
                <div className="mb-2 flex items-center justify-between">
                  <div className="flex h-9 w-9 items-center justify-center rounded-app-sm bg-white/10">
                    <f.icon className="h-5 w-5 text-brand-blue" />
                  </div>
                  {f.tag && <Badge variant={f.tagVariant}>{f.tag}</Badge>}
                </div>
                <CardTitle>{f.title}</CardTitle>
                <CardDescription>{f.desc}</CardDescription>
              </CardHeader>
              <CardContent />
            </Card>
          </motion.div>
        ))}
      </div>
    </section>
  )
}
