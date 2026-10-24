import { useEffect, useRef } from 'react'
import * as THREE from 'three'
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js'

export interface Metrics3DSeries {
  label: string
  defended: number // 0-100
  unsafe: number // 0-100
}

interface Props {
  data: Metrics3DSeries[]
  height?: number
}

const COLOR_DEFENDED = 0x30d158
const COLOR_UNSAFE = 0xff453a
const COLOR_GRID = 0x2997ff

/**
 * Extruded 3D bar-tower comparison chart, built with raw three.js to match
 * the mount/resize/cleanup pattern already established by ForceGraph3D.tsx
 * in this codebase. Auto-rotates gently; drag to orbit manually.
 */
export function Metrics3DChart({ data, height = 360 }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const container = containerRef.current
    if (!container) return

    const scene = new THREE.Scene()
    const width = container.clientWidth || 1
    const h = container.clientHeight || height

    const camera = new THREE.PerspectiveCamera(45, width / h, 0.1, 1000)
    camera.position.set(0, 9, 16)

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true })
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2))
    renderer.setSize(width, h)
    container.appendChild(renderer.domElement)

    scene.add(new THREE.AmbientLight(0xffffff, 0.5))
    const point = new THREE.PointLight(0xffffff, 1.2, 60)
    point.position.set(6, 12, 10)
    scene.add(point)
    const point2 = new THREE.PointLight(0x2997ff, 0.8, 60)
    point2.position.set(-8, 6, -6)
    scene.add(point2)

    // Ground grid for spatial reference
    const grid = new THREE.GridHelper(20, 20, COLOR_GRID, 0x222222)
    ;(grid.material as THREE.Material).opacity = 0.25
    ;(grid.material as THREE.Material).transparent = true
    scene.add(grid)

    const n = Math.max(data.length, 1)
    const spacing = 2.6
    const totalWidth = (n - 1) * spacing
    const barDepth = 0.9
    const maxBarHeight = 7

    const group = new THREE.Group()
    scene.add(group)

    function makeBar(value: number, color: number, x: number, z: number) {
      const h2 = Math.max(0.05, (value / 100) * maxBarHeight)
      const geo = new THREE.BoxGeometry(0.9, h2, barDepth)
      const mat = new THREE.MeshStandardMaterial({
        color,
        emissive: color,
        emissiveIntensity: 0.35,
        metalness: 0.3,
        roughness: 0.4,
      })
      const mesh = new THREE.Mesh(geo, mat)
      mesh.position.set(x, h2 / 2, z)
      group.add(mesh)
    }

    data.forEach((d, i) => {
      const x = i * spacing - totalWidth / 2
      makeBar(d.defended, COLOR_DEFENDED, x, -0.6)
      makeBar(d.unsafe, COLOR_UNSAFE, x, 0.6)
    })

    const controls = new OrbitControls(camera, renderer.domElement)
    controls.enableDamping = true
    controls.dampingFactor = 0.08
    controls.minDistance = 8
    controls.maxDistance = 30
    controls.maxPolarAngle = Math.PI / 2.1
    controls.target.set(0, 2, 0)
    controls.update()

    let autoRotate = true
    const stopAutoRotate = () => { autoRotate = false }
    renderer.domElement.addEventListener('pointerdown', stopAutoRotate)

    let destroyed = false
    let rafId = 0
    function animate() {
      if (destroyed) return
      if (autoRotate) group.rotation.y += 0.0025
      controls.update()
      renderer.render(scene, camera)
      rafId = requestAnimationFrame(animate)
    }
    rafId = requestAnimationFrame(animate)

    const ro = new ResizeObserver(() => {
      const w = container.clientWidth || 1
      const hh = container.clientHeight || height
      camera.aspect = w / hh
      camera.updateProjectionMatrix()
      renderer.setSize(w, hh)
    })
    ro.observe(container)

    return () => {
      destroyed = true
      cancelAnimationFrame(rafId)
      ro.disconnect()
      controls.dispose()
      renderer.domElement.removeEventListener('pointerdown', stopAutoRotate)
      scene.traverse((obj) => {
        if (obj instanceof THREE.Mesh) {
          obj.geometry.dispose()
          const mat = obj.material
          if (Array.isArray(mat)) mat.forEach((m) => m.dispose())
          else mat.dispose()
        }
      })
      renderer.dispose()
      container.removeChild(renderer.domElement)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, height])

  return <div ref={containerRef} style={{ height }} className="w-full overflow-hidden rounded-app" />
}
