import { useState } from 'react'
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom'
import { AnimatePresence, motion } from 'framer-motion'
import {
  Activity, PlayCircle, Network, Rewind, FlaskConical, ScrollText,
  ShieldCheck, ScanSearch, Gauge, FileText, Plug, Menu, Shield, ArrowLeft,
  UploadCloud, Grid3x3,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Sheet, SheetContent, SheetTrigger } from '@/components/ui/sheet'
import { ChatWidget } from '@/components/ChatWidget'
import { DashboardBackdrop } from '@/components/DashboardBackdrop'

const NAV_ITEMS = [
  { to: '/dashboard', label: 'Overview', icon: Activity, end: true },
  { to: '/dashboard/run', label: 'Scenario Runner', icon: PlayCircle },
  { to: '/dashboard/upload', label: 'Upload Dataset', icon: UploadCloud },
  { to: '/dashboard/graph', label: 'Attack Graph Explorer', icon: Network },
  { to: '/dashboard/replay', label: 'Attack Replay', icon: Rewind },
  { to: '/dashboard/simulate', label: 'What-If Simulator', icon: FlaskConical },
  { to: '/dashboard/coverage', label: 'MITRE/OWASP Coverage', icon: Grid3x3 },
  { to: '/dashboard/audit', label: 'Audit Trail', icon: ScrollText },
  { to: '/dashboard/policy', label: 'Policy Gate', icon: ShieldCheck },
  { to: '/dashboard/dlp', label: 'DLP Inspector', icon: ScanSearch },
  { to: '/dashboard/benchmark', label: 'Benchmark', icon: Gauge },
  { to: '/dashboard/report', label: 'Executive Report', icon: FileText },
  { to: '/dashboard/integrations', label: 'Integrations', icon: Plug },
]

function SidebarContent() {
  return (
    <div className="flex h-full flex-col">
      <Link to="/" className="mb-6 flex items-center gap-2 px-2 font-semibold">
        <span className="flex h-8 w-8 items-center justify-center rounded-[10px] bg-gradient-to-br from-brand-blue to-brand-cyan">
          <Shield className="h-4 w-4 text-white" />
        </span>
        AgentShield Arena
      </Link>
      <nav className="scrollbar-thin flex-1 space-y-1 overflow-y-auto">
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              cn(
                'flex items-center gap-2.5 rounded-app-sm px-3 py-2 text-sm transition-colors',
                isActive ? 'bg-brand-blue text-white' : 'text-white/60 hover:bg-white/5 hover:text-white',
              )
            }
          >
            <item.icon className="h-4 w-4" />
            {item.label}
          </NavLink>
        ))}
      </nav>
      <Link to="/" className="mt-4 flex items-center gap-2 px-3 py-2 text-xs text-white/40 hover:text-white">
        <ArrowLeft className="h-3.5 w-3.5" /> Back to landing page
      </Link>
    </div>
  )
}

export function DashboardLayout() {
  const [mobileOpen, setMobileOpen] = useState(false)
  const location = useLocation()

  return (
    <div className="relative flex min-h-screen bg-surface-0">
      <DashboardBackdrop />
      <aside className="hidden w-64 shrink-0 border-r border-white/5 bg-[#060606]/80 p-4 backdrop-blur-xl lg:block">
        <SidebarContent />
      </aside>

      <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
        <SheetContent className="p-4">
          <SidebarContent />
        </SheetContent>
      </Sheet>

      <div className="flex min-h-screen flex-1 flex-col">
        <header className="flex h-14 items-center gap-3 border-b border-white/5 bg-surface-0/60 px-4 backdrop-blur-xl">
          <button onClick={() => setMobileOpen(true)} className="rounded-app-sm p-2 text-white/60 hover:bg-white/5 lg:hidden">
            <Menu className="h-5 w-5" />
          </button>
          <div className="flex items-center gap-2 text-sm text-white/40">
            <span className="h-2 w-2 rounded-full bg-brand-green animate-pulse-dot" />
            Policy Gate Active
          </div>
        </header>
        <main className="scrollbar-thin flex-1 overflow-y-auto p-4 sm:p-6">
          <AnimatePresence mode="wait">
            <motion.div
              key={location.pathname}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.18, ease: 'easeOut' }}
            >
              <Outlet />
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
      <ChatWidget />
    </div>
  )
}
