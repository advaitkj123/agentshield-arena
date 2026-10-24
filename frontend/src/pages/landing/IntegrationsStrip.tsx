const ITEMS = [
  'Google Gemini', 'OpenAI GPT-4', 'Brevo Email', 'Telegram Bot',
  'FastAPI + SSE', 'MITRE ATT&CK', 'GitHub Actions CI', 'Python 3.11+',
]

export function IntegrationsStrip() {
  return (
    <section className="mx-auto max-w-6xl px-4 py-16 sm:px-6">
      <div className="mb-6 text-center text-xs uppercase tracking-wide text-white/40">Works with your stack</div>
      <div className="flex flex-wrap items-center justify-center gap-3">
        {ITEMS.map((item) => (
          <span key={item} className="glass rounded-pill px-4 py-2 text-sm text-white/60">
            {item}
          </span>
        ))}
      </div>
    </section>
  )
}
