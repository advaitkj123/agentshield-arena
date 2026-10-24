import { useEffect, useState } from 'react'

export type FetchState<T> = {
  data: T
  loading: boolean
  error: string | null
  isSample: boolean
  reload: () => void
}

/**
 * Fetches from a live endpoint; on failure (backend not up yet, network error,
 * non-2xx) falls back to the provided sample data so the page stays demoable.
 */
export function useApiData<T>(fetcher: () => Promise<T>, sample: T, deps: unknown[] = []): FetchState<T> {
  const [data, setData] = useState<T>(sample)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [isSample, setIsSample] = useState(true)
  const [tick, setTick] = useState(0)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    fetcher()
      .then((res) => {
        if (cancelled) return
        setData(res)
        setIsSample(false)
        setLoading(false)
      })
      .catch((err) => {
        if (cancelled) return
        setData(sample)
        setIsSample(true)
        setError(err instanceof Error ? err.message : 'Request failed')
        setLoading(false)
      })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick, ...deps])

  return { data, loading, error, isSample, reload: () => setTick((t) => t + 1) }
}
