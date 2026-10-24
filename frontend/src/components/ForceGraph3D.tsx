import { useEffect, useRef } from 'react'
import ForceGraph3DLib from '3d-force-graph'
import { riskColor } from '@/lib/utils'
import type { GraphResponse } from '@/lib/api'

interface Props {
  data: GraphResponse
  height?: number
  interactive?: boolean
  onNodeClick?: (nodeId: string) => void
}

export function ForceGraph3D({ data, height = 420, interactive = true, onNodeClick }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const graphRef = useRef<any>(null)

  useEffect(() => {
    if (!containerRef.current) return

    const attackPathEdges = new Set<string>()
    for (let i = 0; i < data.attack_path.length - 1; i++) {
      attackPathEdges.add(`${data.attack_path[i]}->${data.attack_path[i + 1]}`)
      attackPathEdges.add(`${data.attack_path[i + 1]}->${data.attack_path[i]}`)
    }

    const graph: any = (ForceGraph3DLib as any)()(containerRef.current)
      .graphData({
        nodes: data.nodes.map((n) => ({ ...n })),
        links: data.edges.map((e) => ({ ...e, id: `${e.source}->${e.target}` })),
      })
      .nodeLabel((n: any) => `${n.label}\n${n.type} · risk ${(n.risk_score * 100).toFixed(0)}%`)
      .nodeColor((n: any) => riskColor(n.risk_score ?? 0))
      .nodeVal((n: any) => 2 + (n.risk_score ?? 0) * 8)
      .linkColor((l: any) => (attackPathEdges.has(l.id) ? '#ff453a' : 'rgba(255,255,255,0.25)'))
      .linkWidth((l: any) => (attackPathEdges.has(l.id) ? 2.5 : 0.6))
      .linkDirectionalParticles((l: any) => (attackPathEdges.has(l.id) ? 4 : 0))
      .linkDirectionalParticleWidth(2)
      .linkDirectionalParticleColor(() => '#ff453a')
      .backgroundColor('rgba(0,0,0,0)')
      .showNavInfo(false)
      .enableNodeDrag(interactive)
      .enableNavigationControls(interactive)

    if (onNodeClick) {
      graph.onNodeClick((n: any) => onNodeClick(n.id))
    }

    graphRef.current = graph

    const ro = new ResizeObserver(() => {
      if (!containerRef.current) return
      graph.width(containerRef.current.clientWidth)
      graph.height(containerRef.current.clientHeight)
    })
    ro.observe(containerRef.current)

    if (!interactive) {
      let frame = 0
      const spin = () => {
        frame += 1
        graph.cameraPosition({
          x: 220 * Math.sin(frame * 0.003),
          z: 220 * Math.cos(frame * 0.003),
        })
        raf = requestAnimationFrame(spin)
      }
      var raf = requestAnimationFrame(spin)
      return () => {
        cancelAnimationFrame(raf)
        ro.disconnect()
        containerRef.current?.replaceChildren()
      }
    }

    return () => {
      ro.disconnect()
      containerRef.current?.replaceChildren()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data])

  return <div ref={containerRef} style={{ height }} className="w-full overflow-hidden rounded-app" />
}
