import { Link } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { Shield } from 'lucide-react'

export function Nav() {
  return (
    <header className="glass fixed inset-x-0 top-0 z-50 border-b border-white/5">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6">
        <Link to="/" className="flex items-center gap-2 font-semibold">
          <span className="flex h-8 w-8 items-center justify-center rounded-[10px] bg-gradient-to-br from-brand-blue to-brand-cyan">
            <Shield className="h-4 w-4 text-white" />
          </span>
          <span className="hidden sm:inline">AgentShield Arena</span>
        </Link>
        <nav className="hidden items-center gap-6 text-sm text-white/60 md:flex">
          <a href="#features" className="hover:text-white">Features</a>
          <a href="#architecture" className="hover:text-white">Architecture</a>
          <a href="#problem" className="hover:text-white">The Problem</a>
          <a href="/docs" className="hover:text-white">API</a>
        </nav>
        <Button asChild size="pill" variant="secondary" className="text-sm">
          <Link to="/dashboard">Open Dashboard →</Link>
        </Button>
      </div>
    </header>
  )
}
