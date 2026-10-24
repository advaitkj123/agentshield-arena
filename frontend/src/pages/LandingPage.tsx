import { Nav } from './landing/Nav'
import { Hero } from './landing/Hero'
import { ProblemStatement } from './landing/ProblemStatement'
import { StatsRow } from './landing/StatsRow'
import { FeaturesGrid } from './landing/FeaturesGrid'
import { ArchitecturePipeline } from './landing/ArchitecturePipeline'
import { GraphTeaser } from './landing/GraphTeaser'
import { IntegrationsStrip } from './landing/IntegrationsStrip'
import { CTASection, Footer } from './landing/CTAFooter'
import { ChatWidget } from '@/components/ChatWidget'

export function LandingPage() {
  return (
    <div className="min-h-screen">
      <Nav />
      <Hero />
      <ProblemStatement />
      <StatsRow />
      <FeaturesGrid />
      <ArchitecturePipeline />
      <GraphTeaser />
      <IntegrationsStrip />
      <CTASection />
      <Footer />
      <ChatWidget />
    </div>
  )
}
