import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ForceGraph3D } from '@/components/ForceGraph3D'
import { SAMPLE_GRAPH } from '@/lib/sampleData'

export function GraphTeaser() {
  return (
    <section className="mx-auto max-w-6xl px-4 py-24 sm:px-6">
      <motion.div initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} className="mb-10 text-center">
        <Badge variant="purple" className="mb-3">GraphSAGE Risk Propagation</Badge>
        <h2 className="text-3xl font-bold tracking-tight sm:text-4xl">See the attack path, not just the verdict.</h2>
        <p className="mx-auto mt-4 max-w-2xl text-white/60">
          Every run is modeled as a typed graph — evidence, tools, policy rules, hosts — and scored
          with a from-scratch GraphSAGE-style message-passing pass to surface blast radius and the
          exact path from injected evidence to a prohibited tool call.
        </p>
      </motion.div>
      <Card className="overflow-hidden p-2">
        <ForceGraph3D data={SAMPLE_GRAPH} height={380} interactive={false} />
      </Card>
      <div className="mt-6 text-center">
        <Button asChild variant="secondary">
          <Link to="/dashboard/graph">Open Attack Graph Explorer →</Link>
        </Button>
      </div>
    </section>
  )
}
