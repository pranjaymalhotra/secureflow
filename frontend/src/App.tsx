import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from './contexts/AuthContext'
import LoginPage from './pages/LoginPage'
import DashboardPage from './pages/DashboardPage'
import AnalysisPage from './pages/AnalysisPage'
import ReportPage from './pages/ReportPage'
import JobsPage from './pages/JobsPage'
import ModelsPage from './pages/ModelsPage'
import Layout from './components/Layout'
import LoadingSpinner from './components/LoadingSpinner'

function App() {
  const { user, loading } = useAuth()

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <LoadingSpinner size="large" />
          <p className="mt-4 text-gray-400">Loading SecureFlow...</p>
        </div>
      </div>
    )
  }

  if (!user) {
    return (
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    )
  }

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/analysis" element={<AnalysisPage />} />
        <Route path="/jobs" element={<JobsPage />} />
        <Route path="/models" element={<ModelsPage />} />
        <Route path="/report/:jobId" element={<ReportPage />} />
        <Route path="/reports" element={<Navigate to="/jobs" replace />} />
        <Route path="/report/:id" element={<ReportPage />} />
        <Route path="/login" element={<Navigate to="/" replace />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  )
}

export default App

