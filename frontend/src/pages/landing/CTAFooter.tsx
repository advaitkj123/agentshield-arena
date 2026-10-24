import { Link } from 'react-router-dom'
import { Button } from '@/components/ui/button'

export function CTASection() {
  return (
    <section className="mx-auto max-w-4xl px-4 py-24 text-center sm:px-6">
      <h2 className="text-3xl font-bold tracking-tight sm:text-4xl">Ready to defend your AI?</h2>
      <p className="mt-4 text-white/60">Launch the dashboard and run your first adversarial benchmark in seconds.</p>
      <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
        <Button asChild size="lg">
          <Link to="/dashboard">🚀 Enter Dashboard</Link>
        </Button>
        <Button asChild size="lg" variant="secondary">
          <a href="/docs">📖 API Reference</a>
        </Button>
      </div>
    </section>
  )
}

export function Footer() {
  return (
    <footer className="border-t border-white/5 py-10">
      <div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-4 px-4 text-sm text-white/40 sm:flex-row sm:px-6">
        <div>© 2026 AgentShield Arena · MIT License · 67+ tests passing</div>
        <div className="flex gap-5">
          <Link to="/dashboard" className="hover:text-white">Dashboard</Link>
          <a href="/docs" className="hover:text-white">API Docs</a>
          <a href="https://github.com" target="_blank" rel="noreferrer" className="hover:text-white">GitHub</a>
          <Link to="/dashboard/integrations" className="hover:text-white">Integrations</Link>
        </div>
      </div>
    </footer>
  )
}
