import { useEffect, useRef, useState } from 'react'
import { Bot, Send, Sparkles, X } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { api } from '@/lib/api'
import { cn } from '@/lib/utils'

interface Msg {
  role: 'user' | 'assistant'
  text: string
}

const SUGGESTIONS = [
  'Explain the last policy decision',
  'What is the Threat Score formula?',
  'Summarize this incident',
]

/**
 * Single shared Gemini advisor chat implementation — used both as a floating
 * widget (`mode="floating"`) and embedded inline on the Integrations page
 * (`mode="embedded"`). Replaces the old dashboard's two independent, drifting
 * chat implementations.
 */
export function ChatWidget({ mode = 'floating' }: { mode?: 'floating' | 'embedded' }) {
  const [open, setOpen] = useState(mode === 'embedded')
  const [messages, setMessages] = useState<Msg[]>([
    { role: 'assistant', text: "Hi, I'm the AgentShield AI Security Advisor. Ask me about any policy decision, DLP pattern, or incident." },
  ])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' })
  }, [messages, busy])

  async function send(text: string) {
    if (!text.trim() || busy) return
    setMessages((m) => [...m, { role: 'user', text }])
    setInput('')
    setBusy(true)
    try {
      const res = await api.chat(text)
      setMessages((m) => [...m, { role: 'assistant', text: res.success ? res.response : `Advisor unavailable: ${res.error ?? 'unknown error'}` }])
    } catch {
      setMessages((m) => [
        ...m,
        { role: 'assistant', text: 'The advisor API is not reachable right now. (Configure GEMINI_API_KEY on the backend and ensure it is running.)' },
      ])
    } finally {
      setBusy(false)
    }
  }

  const panel = (
    <div className={cn('flex flex-col', mode === 'floating' ? 'h-[520px] w-[380px]' : 'h-[460px] w-full')}>
      <div className="flex items-center justify-between border-b border-white/10 p-4">
        <div className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-gradient-to-br from-brand-blue to-brand-cyan">
            <Bot className="h-4 w-4 text-white" />
          </div>
          <div>
            <div className="text-sm font-semibold">AI Security Advisor</div>
            <div className="text-[11px] text-white/40">Gemini 2.5 Flash</div>
          </div>
        </div>
        {mode === 'floating' && (
          <button onClick={() => setOpen(false)} className="rounded-full p-1 text-white/50 hover:bg-white/10 hover:text-white">
            <X className="h-4 w-4" />
          </button>
        )}
      </div>
      <div ref={scrollRef} className="scrollbar-thin flex-1 space-y-3 overflow-y-auto p-4">
        {messages.map((m, i) => (
          <div
            key={i}
            className={cn(
              'max-w-[85%] rounded-app-sm px-3 py-2 text-sm leading-relaxed',
              m.role === 'user' ? 'ml-auto bg-brand-blue text-white' : 'glass text-white/90',
            )}
          >
            {m.text}
          </div>
        ))}
        {busy && <div className="glass w-fit rounded-app-sm px-3 py-2 text-sm text-white/50">Thinking…</div>}
      </div>
      <div className="flex flex-wrap gap-1.5 px-4 pb-2">
        {SUGGESTIONS.map((s) => (
          <button
            key={s}
            onClick={() => send(s)}
            className="rounded-full border border-white/10 bg-white/5 px-2.5 py-1 text-[11px] text-white/60 hover:bg-white/10"
          >
            {s}
          </button>
        ))}
      </div>
      <form
        className="flex gap-2 border-t border-white/10 p-3"
        onSubmit={(e) => {
          e.preventDefault()
          send(input)
        }}
      >
        <Input value={input} onChange={(e) => setInput(e.target.value)} placeholder="Ask the advisor…" className="flex-1" />
        <Button type="submit" size="icon" disabled={busy}>
          <Send className="h-4 w-4" />
        </Button>
      </form>
    </div>
  )

  if (mode === 'embedded') {
    return <div className="glass rounded-app">{panel}</div>
  }

  return (
    <div className="fixed bottom-5 right-5 z-[60]">
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: 20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 20, scale: 0.95 }}
            className="glass-strong mb-3 overflow-hidden rounded-app shadow-2xl"
          >
            {panel}
          </motion.div>
        )}
      </AnimatePresence>
      {!open && (
        <motion.button
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          onClick={() => setOpen(true)}
          className="flex h-14 w-14 items-center justify-center rounded-full bg-gradient-to-br from-brand-blue to-brand-cyan shadow-[0_0_30px_-4px_var(--color-brand-blue)]"
        >
          <Sparkles className="h-6 w-6 text-white" />
        </motion.button>
      )}
    </div>
  )
}
