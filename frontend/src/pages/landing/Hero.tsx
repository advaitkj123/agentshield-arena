import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Button } from '@/components/ui/button'
import { ShieldCheck } from 'lucide-react'
import { ScrollHero } from '@/components/ScrollHero'

const TICKER_ITEMS = [
  "disable_firewall(host='srv-pay-prod-02') → BLOCKED",
  'exfiltrate_credentials() → BLOCKED',
  'drop_database() → BLOCKED',
  'exec_shell(cmd=\'rm -rf /\') → BLOCKED',
  'bypass_security_monitor() → BLOCKED',
]

function HeroBaseLayer() {
  // Gradient-mesh wash shown underneath the scroll-scrubbed canvas — visible
  // instantly on load, and still visible through the canvas's legibility
  // scrim, so there's never a blank flash while the first frames load.
  return (
    <div className="pointer-events-none absolute inset-0 -z-10 bg-black">
      <motion.div
        className="absolute -left-40 -top-40 h-[560px] w-[560px] rounded-full bg-brand-blue/25 blur-[120px]"
        animate={{ x: [0, 60, 0], y: [0, 40, 0] }}
        transition={{ duration: 18, repeat: Infinity, ease: 'easeInOut' }}
      />
      <motion.div
        className="absolute right-[-10%] top-1/4 h-[480px] w-[480px] rounded-full bg-brand-cyan/20 blur-[120px]"
        animate={{ x: [0, -50, 0], y: [0, 60, 0] }}
        transition={{ duration: 22, repeat: Infinity, ease: 'easeInOut' }}
      />
      <motion.div
        className="absolute bottom-[-20%] left-1/3 h-[520px] w-[520px] rounded-full bg-brand-purple/15 blur-[130px]"
        animate={{ x: [0, 40, 0], y: [0, -30, 0] }}
        transition={{ duration: 20, repeat: Infinity, ease: 'easeInOut' }}
      />
      <div
        className="absolute inset-0 opacity-[0.07]"
        style={{
          backgroundImage:
            'linear-gradient(rgba(255,255,255,0.6) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.6) 1px, transparent 1px)',
          backgroundSize: '48px 48px',
          maskImage: 'radial-gradient(ellipse 60% 60% at 50% 40%, black, transparent)',
        }}
      />
    </div>
  )
}

export function Hero() {
  return (
    <section className="relative overflow-hidden">
      <ScrollHero baseLayer={<HeroBaseLayer />}>
      <div className="mx-auto flex max-w-3xl flex-col items-center px-4 text-center">
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass mb-6 flex items-center gap-2 rounded-pill px-4 py-1.5 text-xs text-white/70"
        >
          <span className="h-2 w-2 rounded-full bg-brand-green animate-pulse-dot" />
          Adversarially Resilient AI · Live Policy Gate
        </motion.div>

        <motion.h1
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="text-5xl font-bold leading-[1.05] tracking-tight sm:text-7xl"
        >
          Defend Every
          <br />
          <span className="text-gradient-brand">AI Decision.</span>
        </motion.h1>

        <motion.p
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.12 }}
          className="mt-6 max-w-xl text-lg text-white/60"
        >
          The world's first framework that pits real adversarial AI attacks against a deterministic
          four-layer Policy Gate — and proves your agents are safe every time.
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="mt-9 flex flex-wrap items-center justify-center gap-3"
        >
          <Button asChild size="lg">
            <Link to="/dashboard">Enter Dashboard →</Link>
          </Button>
          <Button asChild size="lg" variant="secondary">
            <a href="#features">See Features</a>
          </Button>
        </motion.div>

        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.4 }}
          className="glass mt-14 w-full overflow-hidden rounded-app-sm py-2.5"
        >
          <div className="flex items-center gap-2 px-3 text-[11px] uppercase tracking-wide text-white/40">
            <ShieldCheck className="h-3.5 w-3.5 text-brand-green" /> Live Intercept Feed
          </div>
          <div className="relative mt-1 flex overflow-hidden">
            <motion.div
              className="flex shrink-0 gap-10 whitespace-nowrap px-4 font-mono-data text-xs text-white/50"
              animate={{ x: ['0%', '-50%'] }}
              transition={{ duration: 16, repeat: Infinity, ease: 'linear' }}
            >
              {[...TICKER_ITEMS, ...TICKER_ITEMS].map((item, i) => (
                <span key={i} className="text-brand-red/80">
                  {item}
                </span>
              ))}
            </motion.div>
          </div>
        </motion.div>
      </div>
      </ScrollHero>
    </section>
  )
}
