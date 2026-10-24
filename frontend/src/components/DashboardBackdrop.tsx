import { useEffect, useRef } from 'react'
import * as THREE from 'three'

/**
 * Sparse, GPU-cheap ambient particle field behind the dashboard shell.
 * Mounted once in DashboardLayout (not per-page) so it survives route
 * navigation instead of re-initializing a WebGL context on every click.
 */
export function DashboardBackdrop() {
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const container = containerRef.current
    if (!container) return

    const scene = new THREE.Scene()
    const camera = new THREE.PerspectiveCamera(60, container.clientWidth / container.clientHeight, 0.1, 100)
    camera.position.z = 18

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true })
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.75))
    renderer.setSize(container.clientWidth, container.clientHeight)
    container.appendChild(renderer.domElement)

    const COUNT = 220
    const positions = new Float32Array(COUNT * 3)
    for (let i = 0; i < COUNT; i++) {
      positions[i * 3] = (Math.random() - 0.5) * 40
      positions[i * 3 + 1] = (Math.random() - 0.5) * 24
      positions[i * 3 + 2] = (Math.random() - 0.5) * 30
    }
    const geo = new THREE.BufferGeometry()
    geo.setAttribute('position', new THREE.BufferAttribute(positions, 3))
    const mat = new THREE.PointsMaterial({ color: 0x2997ff, size: 0.06, transparent: true, opacity: 0.35 })
    const points = new THREE.Points(geo, mat)
    scene.add(points)

    // Sparse faint connecting lines for a "network" feel, not a dense mesh.
    const lineGeo = new THREE.BufferGeometry()
    const linePositions: number[] = []
    for (let i = 0; i < 40; i++) {
      const a = Math.floor(Math.random() * COUNT)
      const b = Math.floor(Math.random() * COUNT)
      linePositions.push(
        positions[a * 3], positions[a * 3 + 1], positions[a * 3 + 2],
        positions[b * 3], positions[b * 3 + 1], positions[b * 3 + 2],
      )
    }
    lineGeo.setAttribute('position', new THREE.BufferAttribute(new Float32Array(linePositions), 3))
    const lineMat = new THREE.LineBasicMaterial({ color: 0x06b6d4, transparent: true, opacity: 0.08 })
    const lines = new THREE.LineSegments(lineGeo, lineMat)
    scene.add(lines)

    let destroyed = false
    let rafId = 0
    function animate() {
      if (destroyed) return
      points.rotation.y += 0.0004
      lines.rotation.y += 0.0004
      renderer.render(scene, camera)
      rafId = requestAnimationFrame(animate)
    }
    rafId = requestAnimationFrame(animate)

    const ro = new ResizeObserver(() => {
      const w = container.clientWidth || 1
      const h = container.clientHeight || 1
      camera.aspect = w / h
      camera.updateProjectionMatrix()
      renderer.setSize(w, h)
    })
    ro.observe(container)

    return () => {
      destroyed = true
      cancelAnimationFrame(rafId)
      ro.disconnect()
      geo.dispose()
      mat.dispose()
      lineGeo.dispose()
      lineMat.dispose()
      renderer.dispose()
      container.removeChild(renderer.domElement)
    }
  }, [])

  return (
    <div
      ref={containerRef}
      className="pointer-events-none fixed inset-0 -z-10 opacity-60"
      aria-hidden="true"
    />
  )
}
