import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { 
  Shield, 
  Search, 
  FileText, 
  Activity, 
  AlertTriangle,
  CheckCircle,
  Clock,
  TrendingUp
} from 'lucide-react'
import { jobsAPI, systemAPI } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'
import { formatRelativeTime, getStatusColor } from '../utils/cn'

export default function DashboardPage() {
  const { data: jobs, isLoading: jobsLoading } = useQuery({
    queryKey: ['jobs', 'recent'],
    queryFn: () => jobsAPI.list(5, 0),
    refetchInterval: 60000, // 
  })

  const { data: healthData } = useQuery({
    queryKey: ['system', 'health'],
    queryFn: () => systemAPI.health(),
    refetchInterval: 60000, // 
  })

  const recentJobs = jobs?.data.jobs || []

  // Calculate dashboard stats
  const totalJobs = recentJobs.length
  const completedJobs = recentJobs.filter(job => job.status === 'completed').length
  const runningJobs = recentJobs.filter(job => job.status === 'running').length
  const failedJobs = recentJobs.filter(job => job.status === 'failed').length

  const stats = [
    {
      name: 'Total Analyses',
      value: totalJobs,
      icon: FileText,
      color: 'text-blue-400',
      bgColor: 'bg-blue-900/20'
    },
    {
      name: 'Completed',
      value: completedJobs,
      icon: CheckCircle,
      color: 'text-green-400',
      bgColor: 'bg-green-900/20'
    },
    {
      name: 'Running',
      value: runningJobs,
      icon: Clock,
      color: 'text-yellow-400',
      bgColor: 'bg-yellow-900/20'
    },
    {
      name: 'System Health',
      value: healthData?.data.status === 'healthy' ? 'Online' : 'Issues',
      icon: Activity,
      color: healthData?.data.status === 'healthy' ? 'text-green-400' : 'text-red-400',
      bgColor: healthData?.data.status === 'healthy' ? 'bg-green-900/20' : 'bg-red-900/20'
    }
  ]

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Security Analysis Dashboard</h1>
        <p className="mt-1 text-sm text-gray-400">
          Monitor your security analyses and system health
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
        {stats.map((stat) => {
          const Icon = stat.icon
          return (
            <div key={stat.name} className="card">
              <div className="flex items-center">
                <div className={`flex-shrink-0 ${stat.bgColor} p-3 rounded-lg`}>
                  <Icon className={`h-6 w-6 ${stat.color}`} />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-400">{stat.name}</p>
                  <p className="text-2xl font-semibold text-white">{stat.value}</p>
                </div>
              </div>
            </div>
          )
        })}
      </div>

      {/* Quick Actions */}
      <div className="card">
        <div className="card-header">
          <h2 className="card-title">Quick Actions</h2>
          <p className="card-description">
            Start a new security analysis or view existing results
          </p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Link
            to="/analysis"
            className="flex items-center p-4 bg-gray-700 rounded-lg hover:bg-gray-600 transition-colors group"
          >
            <div className="flex-shrink-0 bg-blue-600 p-3 rounded-lg group-hover:bg-blue-500 transition-colors">
              <Search className="h-6 w-6 text-white" />
            </div>
            <div className="ml-4">
              <h3 className="text-lg font-medium text-white">New Analysis</h3>
              <p className="text-sm text-gray-400">
                Upload files or analyze a GitHub repository
              </p>
            </div>
          </Link>

          <Link
            to="/jobs"
            className="flex items-center p-4 bg-gray-700 rounded-lg hover:bg-gray-600 transition-colors group"
          >
            <div className="flex-shrink-0 bg-green-600 p-3 rounded-lg group-hover:bg-green-500 transition-colors">
              <FileText className="h-6 w-6 text-white" />
            </div>
            <div className="ml-4">
              <h3 className="text-lg font-medium text-white">View Reports</h3>
              <p className="text-sm text-gray-400">
                Browse all analysis jobs and reports
              </p>
            </div>
          </Link>
        </div>
      </div>

      {/* Recent Jobs */}
      <div className="card">
        <div className="card-header">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="card-title">Recent Analyses</h2>
              <p className="card-description">
                Your latest security analysis jobs
              </p>
            </div>
            <Link
              to="/jobs"
              className="text-sm text-blue-400 hover:text-blue-300 transition-colors"
            >
              View all →
            </Link>
          </div>
        </div>

        {jobsLoading ? (
          <div className="flex items-center justify-center py-8">
            <LoadingSpinner size="large" />
          </div>
        ) : recentJobs.length === 0 ? (
          <div className="text-center py-8">
            <Shield className="mx-auto h-12 w-12 text-gray-600" />
            <h3 className="mt-2 text-sm font-medium text-gray-400">No analyses yet</h3>
            <p className="mt-1 text-sm text-gray-500">
              Start your first security analysis to see results here
            </p>
            <div className="mt-6">
              <Link
                to="/analysis"
                className="btn btn-primary btn-sm"
              >
                <Search className="h-4 w-4 mr-2" />
                New Analysis
              </Link>
            </div>
          </div>
        ) : (
          <div className="overflow-hidden">
            <ul className="divide-y divide-gray-700">
              {recentJobs.map((job) => (
                <li key={job.id}>
                  <div className="px-4 py-4 sm:px-0">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <div className={`flex-shrink-0 w-2 h-2 rounded-full ${
                          job.status === 'completed' ? 'bg-green-400' :
                          job.status === 'running' ? 'bg-blue-400' :
                          job.status === 'failed' ? 'bg-red-400' :
                          'bg-yellow-400'
                        }`} />
                        <div>
                          <p className="text-sm font-medium text-white">
                            {job.source_type === 'github' ? (
                              <>GitHub: {job.source_url?.split('/').slice(-2).join('/')}</>
                            ) : (
                              `File Upload (${job.files_total} files)`
                            )}
                          </p>
                          <p className="text-xs text-gray-400">
                            {formatRelativeTime(job.created_at)} • {job.files_total} files
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-3">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(job.status)}`}>
                          {job.status}
                        </span>
                        {job.status === 'completed' && (
                          <Link
                            to={`/report/${job.id}`}
                            className="text-blue-400 hover:text-blue-300 text-xs"
                          >
                            View Report →
                          </Link>
                        )}
                      </div>
                    </div>
                    {job.status === 'running' && (
                      <div className="mt-2">
                        <div className="flex items-center justify-between text-xs text-gray-400">
                          <span>Progress: {job.files_scanned}/{job.files_total} files</span>
                          <span>{Math.round(job.progress)}%</span>
                        </div>
                        <div className="mt-1 progress">
                          <div 
                            className="progress-bar" 
                            style={{ width: `${job.progress}%` }}
                          />
                        </div>
                      </div>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* System Information */}
      {healthData?.data && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="card">
            <div className="card-header">
              <h2 className="card-title">System Status</h2>
            </div>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-400">Database</span>
                <span className={`text-sm ${
                  healthData.data.database === 'connected' ? 'text-green-400' : 'text-red-400'
                }`}>
                  {healthData.data.database}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-400">Job Manager</span>
                <span className="text-sm text-green-400">Active</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-400">WebSocket Connections</span>
                <span className="text-sm text-blue-400">
                  {healthData.data.active_connections || 0}
                </span>
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-header">
              <h2 className="card-title">Quick Tips</h2>
            </div>
            <div className="space-y-3 text-sm text-gray-300">
              <div className="flex items-start space-x-2">
                <AlertTriangle className="h-4 w-4 text-yellow-400 mt-0.5 flex-shrink-0" />
                <p>Upload multiple files or entire repositories for comprehensive analysis</p>
              </div>
              <div className="flex items-start space-x-2">
                <CheckCircle className="h-4 w-4 text-green-400 mt-0.5 flex-shrink-0" />
                <p>Use multiple AI models for better vulnerability detection accuracy</p>
              </div>
              <div className="flex items-start space-x-2">
                <TrendingUp className="h-4 w-4 text-blue-400 mt-0.5 flex-shrink-0" />
                <p>Review detailed reports to understand security findings and fixes</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}