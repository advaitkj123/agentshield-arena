import { motion } from 'framer-motion'
import { Swords, Bot, ShieldCheck, Gavel, Box, FileLock2, ArrowRight } from 'lucide-react'

const STEPS = [
  { icon: Swords, label: 'Red Agent', desc: 'Injects adversarial payloads' },
  { icon: Bot, label: 'Blue Agent', desc: 'LLM or deterministic investigator' },
  { icon: ShieldCheck, label: 'Policy Gate', desc: '4-layer enforcement' },
  { icon: Gavel, label: 'HITL', desc: 'Human approval' },
  { icon: Box, label: 'Sandbox', desc: 'Verified actions only' },
  { icon: FileLock2, label: 'Audit Trail', desc: 'Append-only log + alerts' },
]

export function ArchitecturePipeline() {
  return (
    <section id="architecture" className="mx-auto max-w-6xl px-4 py-24 sm:px-6">
      <motion.div initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} className="mb-12 text-center">
        <div className="text-sm font-medium uppercase tracking-wide text-brand-cyan/80">Architecture</div>
        <h2 className="mt-3 text-3xl font-bold tracking-tight sm:text-4xl">From attack to audit in milliseconds.</h2>
      </motion.div>
      <div className="flex flex-col items-stretch gap-3 lg:flex-row lg:items-center">
        {STEPS.map((s, i) => (
          <div key={s.label} className="flex items-center gap-3 lg:flex-1">
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.08 }}
              className="glass flex w-full flex-col items-center gap-2 rounded-app px-4 py-6 text-center"
            >
              <div className="flex h-11 w-11 items-center justify-center rounded-full bg-gradient-to-br from-brand-blue to-brand-cyan">
                <s.icon className="h-5 w-5 text-white" />
              </div>
              <div className="text-sm font-semibold">{s.label}</div>
              <div className="text-[11px] text-white/45">{s.desc}</div>
            </motion.div>
            {i < STEPS.length - 1 && (
              <ArrowRight className="hidden h-4 w-4 flex-shrink-0 text-white/20 lg:block" />
            )}
          </div>
        ))}
      </div>
    </section>
  )
}
