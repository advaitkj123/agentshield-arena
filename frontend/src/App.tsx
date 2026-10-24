import { Route, Routes } from 'react-router-dom'
import { LandingPage } from '@/pages/LandingPage'
import { DashboardLayout } from '@/pages/dashboard/DashboardLayout'
import { OverviewPage } from '@/pages/dashboard/OverviewPage'
import { ScenarioRunnerPage } from '@/pages/dashboard/ScenarioRunnerPage'
import { UploadPage } from '@/pages/dashboard/UploadPage'
import { CoveragePage } from '@/pages/dashboard/CoveragePage'
import { GraphExplorerPage } from '@/pages/dashboard/GraphExplorerPage'
import { ReplayPage } from '@/pages/dashboard/ReplayPage'
import { SimulatorPage } from '@/pages/dashboard/SimulatorPage'
import { AuditTrailPage } from '@/pages/dashboard/AuditTrailPage'
import { PolicyGatePage } from '@/pages/dashboard/PolicyGatePage'
import { DlpInspectorPage } from '@/pages/dashboard/DlpInspectorPage'
import { BenchmarkPage } from '@/pages/dashboard/BenchmarkPage'
import { ExecutiveReportPage } from '@/pages/dashboard/ExecutiveReportPage'
import { IntegrationsPage } from '@/pages/dashboard/IntegrationsPage'

function App() {
  return (
    <Routes>
      <Route path="/" element={<LandingPage />} />
      <Route path="/dashboard" element={<DashboardLayout />}>
        <Route index element={<OverviewPage />} />
        <Route path="run" element={<ScenarioRunnerPage />} />
        <Route path="upload" element={<UploadPage />} />
        <Route path="graph" element={<GraphExplorerPage />} />
        <Route path="replay" element={<ReplayPage />} />
        <Route path="simulate" element={<SimulatorPage />} />
        <Route path="coverage" element={<CoveragePage />} />
        <Route path="audit" element={<AuditTrailPage />} />
        <Route path="policy" element={<PolicyGatePage />} />
        <Route path="dlp" element={<DlpInspectorPage />} />
        <Route path="benchmark" element={<BenchmarkPage />} />
        <Route path="report" element={<ExecutiveReportPage />} />
        <Route path="integrations" element={<IntegrationsPage />} />
      </Route>
    </Routes>
  )
}

export default App
