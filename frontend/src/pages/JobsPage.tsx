import { useState, useEffect, useRef, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link, useLocation } from 'react-router-dom'
import { 
  FileText, 
  Clock, 
  CheckCircle, 
  XCircle, 
  Github, 
  Upload,
  Trash2,
  Eye,
  RefreshCw,
  AlertCircle
} from 'lucide-react'
import { toast } from 'sonner'

import { jobsAPI } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'
import ProgressBar from '../components/ProgressBar'
import Badge from '../components/Badge'
import { formatRelativeTime, getStatusColor } from '../utils/cn'

// Types
interface ProgressUpdate {
  job_id: string
  stage: string
  files_scanned: number
  total_files: number
  progress_percentage: number
  current_file?: string
  active_models?: string[]
  status: string
}

interface Job {
  id: string
  status: string
  source_type: string
  source_url?: string
  progress: number
  files_scanned: number
  files_total: number
  created_at: string
  current_stage?: string
  error_message?: string
}

// WebSocket Hook with better error handling and proper ping handling
function useWebSocket(jobId: string | null, onMessage?: (data: ProgressUpdate) => void) {
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectAttemptsRef = useRef(0)
  const maxReconnectAttempts = 5
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  
  const connect = useCallback(() => {
    if (!jobId) return

    // Fix: Use the correct backend port for WebSocket connections
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsHost = window.location.hostname
    const wsPort = window.location.port === '5173' ? '8000' : window.location.port // Development fix
    const wsUrl = `${wsProtocol}//${wsHost}:${wsPort}/ws/${jobId}`

    try {
      wsRef.current = new WebSocket(wsUrl)

      wsRef.current.onopen = () => {
        console.log(`WebSocket connected for job ${jobId}`)
        reconnectAttemptsRef.current = 0
      }

      wsRef.current.onmessage = (event) => {
        try {
          // Fix: Handle ping messages properly
          if (event.data.startsWith('ping:')) {
            console.debug('Received ping:', event.data)
            return
          }
          
          const data: ProgressUpdate = JSON.parse(event.data)
          onMessage?.(data)
        } catch (error) {
          console.error('Error parsing WebSocket message:', error, 'Raw data:', event.data)
        }
      }

      wsRef.current.onerror = (error: Event) => {
        console.error('WebSocket error:', error)
      }

      wsRef.current.onclose = (event) => {
        console.log('WebSocket closed', event.code, event.reason)
        
        if (event.code !== 1000 && reconnectAttemptsRef.current < maxReconnectAttempts) {
          const delay = Math.min(1000 * (2 ** reconnectAttemptsRef.current), 30000)
          console.log(`Attempting to reconnect in ${delay}ms...`)
          
          reconnectTimeoutRef.current = setTimeout(() => {
            reconnectAttemptsRef.current++
            connect()
          }, delay)
        }
      }
    } catch (error) {
      console.error('Error creating WebSocket:', error)
    }
  }, [jobId, onMessage])

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
      reconnectTimeoutRef.current = null
    }
    
    if (wsRef.current) {
      wsRef.current.close(1000, 'Component unmounted')
      wsRef.current = null
    }
  }, [])

  return { connect, disconnect }
}

// Helper Functions
const getStatusIcon = (status: string) => {
  switch (status) {
    case 'completed':
      return CheckCircle
    case 'running':
      return Clock
    case 'failed':
      return XCircle
    case 'cancelled':
      return XCircle
    default:
      return Clock
  }
}

const getStatusBadgeVariant = (status: string) => {
  switch (status) {
    case 'completed':
      return 'low'
    case 'running':
      return 'info'
    case 'failed':
      return 'critical'
    case 'cancelled':
      return 'medium'
    default:
      return 'info'
  }
}

// Job Row Component with Real-time Updates
function JobRow({ job, onCancel }: { job: Job; onCancel: (jobId: string) => void }) {
  const [currentProgress, setCurrentProgress] = useState<ProgressUpdate | null>(null)
  const [activeModels, setActiveModels] = useState<string[]>([])

  const { connect, disconnect } = useWebSocket(
    job.status === 'running' ? job.id : null,
    (progress: ProgressUpdate) => {
      setCurrentProgress(progress)
      setActiveModels(progress.active_models || [])
    }
  )

  useEffect(() => {
    if (job.status === 'running') {
      connect()
    }
    return () => disconnect()
  }, [job.status, connect, disconnect])

  const StatusIcon = getStatusIcon(job.status)
  const progress = currentProgress?.progress_percentage || job.progress || 0
  const filesScanned = currentProgress?.files_scanned || job.files_scanned || 0
  const totalFiles = currentProgress?.total_files || job.files_total || 0
  const stage = currentProgress?.stage || ''

  return (
    <>
      <td className="py-4 px-4">
        <div className="flex items-center space-x-3">
          {job.source_type === 'github' ? (
            <Github className="h-5 w-5 text-blue-400 flex-shrink-0" />
          ) : (
            <Upload className="h-5 w-5 text-green-400 flex-shrink-0" />
          )}
          <div className="min-w-0">
            <p className="text-sm font-medium text-white truncate">
              {job.source_type === 'github' ? (
                job.source_url?.split('/').slice(-2).join('/') || 'GitHub Repository'
              ) : (
                'File Upload'
              )}
            </p>
            <p className="text-xs text-gray-400 capitalize">
              {job.source_type}
            </p>
          </div>
        </div>
      </td>
      
      <td className="py-4 px-4">
        <div className="flex items-center space-x-2">
          <StatusIcon className={`h-4 w-4 ${
            job.status === 'completed' ? 'text-green-400' :
            job.status === 'running' ? 'text-blue-400' :
            job.status === 'failed' ? 'text-red-400' :
            'text-yellow-400'
          }`} />
          <Badge variant={getStatusBadgeVariant(job.status)}>
            {job.status}
          </Badge>
        </div>
        {job.status === 'running' && stage && (
          <div className="text-xs text-gray-400 mt-1">
            {stage.replace('processing_with_', '🤖 ').replace('_', ' ')}
          </div>
        )}
        {activeModels.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-1">
            {activeModels.map((model) => (
              <span key={model} className="px-2 py-0.5 text-xs bg-blue-900/30 text-blue-300 rounded animate-pulse">
                {model.replace(':', '_')}
              </span>
            ))}
          </div>
        )}
        {job.status === 'failed' && job.error_message && (
          <div className="text-xs text-red-400 mt-1">
            {job.error_message}
          </div>
        )}
      </td>
      
      <td className="py-4 px-4">
        {job.status === 'running' ? (
          <div className="w-24">
            <ProgressBar 
              value={progress} 
              showPercentage={false}
            />
            <div className="text-xs text-gray-400 mt-1">
              {filesScanned}/{totalFiles}
            </div>
          </div>
        ) : (
          <span className="text-sm text-gray-400">
            {job.status === 'completed' ? '100%' : '-'}
          </span>
        )}
      </td>
      
      <td className="py-4 px-4">
        <span className="text-sm text-gray-300">
          {totalFiles || job.files_total}
        </span>
      </td>
      
      <td className="py-4 px-4">
        <span className="text-sm text-gray-400">
          {formatRelativeTime(job.created_at)}
        </span>
      </td>
      
      <td className="py-4 px-4">
        <div className="flex items-center space-x-2">
          {job.status === 'completed' && (
            <Link
              to={`/report/${job.id}`}
              className="text-blue-400 hover:text-blue-300 p-1"
              title="View Report"
            >
              <Eye className="h-4 w-4" />
            </Link>
          )}
          {(job.status === 'running' || job.status === 'queued') && (
            <button
              onClick={() => onCancel(job.id)}
              className="text-red-400 hover:text-red-300 p-1"
              title="Cancel Job"
            >
              <Trash2 className="h-4 w-4" />
            </button>
          )}
        </div>
      </td>
    </>
  )
}

// Mobile Job Card Component
function JobCard({ job, onCancel }: { job: Job; onCancel: (jobId: string) => void }) {
  const [currentProgress, setCurrentProgress] = useState<ProgressUpdate | null>(null)
  const [activeModels, setActiveModels] = useState<string[]>([])

  const { connect, disconnect } = useWebSocket(
    job.status === 'running' ? job.id : null,
    (progress: ProgressUpdate) => {
      setCurrentProgress(progress)
      setActiveModels(progress.active_models || [])
    }
  )

  useEffect(() => {
    if (job.status === 'running') {
      connect()
    }
    return () => disconnect()
  }, [job.status, connect, disconnect])

  const StatusIcon = getStatusIcon(job.status)
  const progress = currentProgress?.progress_percentage || job.progress || 0
  const filesScanned = currentProgress?.files_scanned || job.files_scanned || 0
  const totalFiles = currentProgress?.total_files || job.files_total || 0
  const stage = currentProgress?.stage || ''

  return (
    <div className="bg-gray-700 rounded-lg p-4">
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center space-x-3">
          {job.source_type === 'github' ? (
            <Github className="h-5 w-5 text-blue-400 flex-shrink-0" />
          ) : (
            <Upload className="h-5 w-5 text-green-400 flex-shrink-0" />
          )}
          <div className="min-w-0">
            <p className="text-sm font-medium text-white truncate">
              {job.source_type === 'github' ? (
                job.source_url?.split('/').slice(-2).join('/') || 'GitHub Repository'
              ) : (
                'File Upload'
              )}
            </p>
            <p className="text-xs text-gray-400">
              {formatRelativeTime(job.created_at)} • {totalFiles || job.files_total} files
            </p>
          </div>
        </div>
        <Badge variant={getStatusBadgeVariant(job.status)}>
          {job.status}
        </Badge>
      </div>

      {job.status === 'running' && stage && (
        <div className="text-xs text-gray-400 mb-2">
          {stage.replace('processing_with_', '🤖 ').replace('_', ' ')}
        </div>
      )}

      {activeModels.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-3">
          {activeModels.map((model) => (
            <span key={model} className="px-2 py-0.5 text-xs bg-blue-900/30 text-blue-300 rounded animate-pulse">
              {model.replace(':', '_')}
            </span>
          ))}
        </div>
      )}

      {job.status === 'failed' && job.error_message && (
        <div className="text-xs text-red-400 mb-2">
          {job.error_message}
        </div>
      )}

      {job.status === 'running' && (
        <div className="mb-3">
          <ProgressBar 
            value={progress} 
            showPercentage={true}
          />
          <div className="text-xs text-gray-400 mt-1">
            {filesScanned} of {totalFiles} files analyzed
          </div>
        </div>
      )}

      <div className="flex items-center justify-end space-x-2">
        {job.status === 'completed' && (
          <Link
            to={`/report/${job.id}`}
            className="btn btn-ghost btn-sm"
          >
            <Eye className="h-4 w-4 mr-1" />
            View Report
          </Link>
        )}
        {(job.status === 'running' || job.status === 'queued') && (
          <button
            onClick={() => onCancel(job.id)}
            className="btn btn-danger btn-sm"
          >
            <Trash2 className="h-4 w-4 mr-1" />
            Cancel
          </button>
        )}
      </div>
    </div>
  )
}

// Main JobsPage Component
export default function JobsPage() {
  const [page, setPage] = useState(0)
  const limit = 20
  const queryClient = useQueryClient()
  const location = useLocation()
  
  const searchParams = new URLSearchParams(location.search)
  const highlightedJobId = searchParams.get('highlight')
  const [highlightedJob, setHighlightedJob] = useState<string | null>(highlightedJobId)

  useEffect(() => {
    if (highlightedJobId) {
      setHighlightedJob(highlightedJobId)
      const timer = setTimeout(() => {
        setHighlightedJob(null)
      }, 5000)
      return () => clearTimeout(timer)
    }
  }, [highlightedJobId])

  // Faster polling to catch new jobs immediately
  const { data: jobsData, isLoading, refetch } = useQuery({
    queryKey: ['jobs', page],
    queryFn: () => jobsAPI.list(limit, page * limit),
    refetchInterval: 1000, // Poll every 1 second for immediate updates
    refetchIntervalInBackground: true
  })

  // Fixed WebSocket monitor connection
  useEffect(() => {
    console.log("Setting up monitor WebSocket connection...");
    
    // Use backend port explicitly to avoid proxy issues
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsHost = window.location.hostname;
    const wsPort = '8000'; // Always use backend port directly
    const wsUrl = `${wsProtocol}//${wsHost}:${wsPort}/ws/monitor`;
    
    console.log(`🔗 Connecting to WebSocket: ${wsUrl}`);
    
    let ws: WebSocket | null = null;
    let reconnectTimeout: NodeJS.Timeout | null = null;
    let reconnectAttempts = 0;
    const maxReconnectAttempts = 5;

  const connect = () => {
    try {
      console.log(`🔗 Connecting to monitor WebSocket (attempt ${reconnectAttempts + 1})...`);
      
      ws = new WebSocket(wsUrl);
      
      // Only set handlers if ws was successfully created
      if (ws) {
        ws.onopen = () => {
          console.log('✅ Monitor WebSocket connected successfully');
          reconnectAttempts = 0; // Reset on successful connection
          
          // Send initial message to confirm connection
          try {
            // Add null check before calling send
            if (ws) {
              ws.send(JSON.stringify({ type: 'client_connected', client: 'monitor' }));
            }
          } catch (e) {
            console.error('Error sending initial message:', e);
          }
        };
        
        ws.onmessage = (event) => {
          try {
            console.log('📨 Monitor message received:', event.data);
            
            // CRITICAL: Handle ping messages separately - don't parse as JSON
            if (typeof event.data === 'string' && event.data.startsWith('ping:')) {
              console.debug('🏓 Ping received from monitor');
              return; // Exit early, don't try to parse as JSON
            }
            
            // Handle welcome messages
            if (typeof event.data === 'string' && event.data.includes('welcome')) {
              console.log('👋 Welcome message received');
              return;
            }
            
            // Only try to parse as JSON for actual job updates
            try {
              const data = JSON.parse(event.data);
              console.log('📊 Parsed monitor data:', data);
              
              if (data.type === 'job_update' || data.type === 'welcome') {
                console.log('🔄 Job update received, refreshing job list...');
                queryClient.invalidateQueries({ queryKey: ['jobs'] });
              }
            } catch (jsonError) {
              console.debug('📝 Non-JSON message received (probably text):', event.data);
            }
            
          } catch (error) {
            console.error('❌ Error handling monitor message:', error);
          }
        };
        
        ws.onerror = (error) => {
          console.error('❌ Monitor WebSocket error:', error);
        };
        
        ws.onclose = (event) => {
          console.log(`🔌 Monitor WebSocket closed: code=${event.code}, reason="${event.reason}"`);
          
          // Try to reconnect unless it was a normal closure or max attempts reached
          if (event.code !== 1000 && event.code !== 1001 && reconnectAttempts < maxReconnectAttempts) {
            const delay = Math.min(1000 * (reconnectAttempts + 1), 10000); // Linear backoff, max 10s
            console.log(`🔄 Reconnecting monitor in ${delay}ms... (attempt ${reconnectAttempts + 1}/${maxReconnectAttempts})`);
            
            reconnectTimeout = setTimeout(() => {
              reconnectAttempts++;
              connect();
            }, delay);
          }
        };
      }
    } catch (error) {
      console.error('❌ Error creating WebSocket connection:', error);
      
      // Try to reconnect after error in creation
      if (reconnectAttempts < maxReconnectAttempts) {
        const delay = Math.min(1000 * (reconnectAttempts + 1), 10000);
        console.log(`🔄 Reconnecting after error in ${delay}ms... (attempt ${reconnectAttempts + 1}/${maxReconnectAttempts})`);
        
        reconnectTimeout = setTimeout(() => {
          reconnectAttempts++;
          connect();
        }, delay);
      }
    }
  };
    
    // Initial connection
    connect();
    
    // Cleanup function
    return () => {
      console.log('🧹 Cleaning up monitor WebSocket...');
      
      if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
        reconnectTimeout = null;
      }
      
      if (ws) {
        // Use a try-catch as the socket might already be closing/closed
        try {
          ws.close(1000, 'Component unmounted');
        } catch (e) {
          console.error('Error closing WebSocket:', e);
        }
        ws = null;
      }
    };
  }, [queryClient]); // Only re-run if queryClient changes

  const handleRefresh = () => {
    refetch()
  }
  
  const cancelMutation = useMutation({
    mutationFn: (jobId: string) => jobsAPI.cancel(jobId),
    onSuccess: () => {
      toast.success('Job cancelled successfully')
      queryClient.invalidateQueries({ queryKey: ['jobs'] })
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.detail || 'Failed to cancel job')
    }
  })

  const jobs = jobsData?.data.jobs || []
  const total = jobsData?.data.total || 0
  const totalPages = Math.ceil(total / limit)

  const handleCancelJob = (jobId: string) => {
    if (confirm('Are you sure you want to cancel this job?')) {
      cancelMutation.mutate(jobId)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Analysis Jobs</h1>
          <p className="mt-1 text-sm text-gray-400">
            Monitor and manage your security analysis jobs
          </p>
        </div>
        <div className="flex items-center space-x-4">
          <button
            onClick={handleRefresh}
            className="btn btn-ghost btn-sm"
            disabled={isLoading}
          >
            <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <Link to="/analysis" className="btn btn-primary btn-sm">
            <FileText className="h-4 w-4 mr-2" />
            New Analysis
          </Link>
        </div>
      </div>

      {/* Jobs List */}
      <div className="card">
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <LoadingSpinner size="large" />
          </div>
        ) : jobs.length === 0 ? (
          <div className="text-center py-12">
            <FileText className="mx-auto h-12 w-12 text-gray-600" />
            <h3 className="mt-2 text-sm font-medium text-gray-400">No analysis jobs yet</h3>
            <p className="mt-1 text-sm text-gray-500">
              Start your first security analysis to see results here
            </p>
            <div className="mt-6">
              <Link to="/analysis" className="btn btn-primary btn-sm">
                <FileText className="h-4 w-4 mr-2" />
                New Analysis
              </Link>
            </div>
          </div>
        ) : (
          <>
            {/* Desktop Table View */}
            <div className="hidden md:block overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th className="text-left py-3 px-4 font-medium text-gray-300">Source</th>
                    <th className="text-left py-3 px-4 font-medium text-gray-300">Status</th>
                    <th className="text-left py-3 px-4 font-medium text-gray-300">Progress</th>
                    <th className="text-left py-3 px-4 font-medium text-gray-300">Files</th>
                    <th className="text-left py-3 px-4 font-medium text-gray-300">Created</th>
                    <th className="text-left py-3 px-4 font-medium text-gray-300">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {jobs.map((job) => (
                    <tr 
                      key={job.id} 
                      className={`${job.id === highlightedJob ? 'bg-blue-900/30 animate-pulse' : 'hover:bg-gray-800/50'}`}
                    >
                      <JobRow job={job} onCancel={handleCancelJob} />
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Mobile Card View */}
            <div className="md:hidden space-y-4">
              {jobs.map((job) => (
                <div
                  key={job.id}
                  className={`${job.id === highlightedJob ? 'ring-2 ring-blue-500 animate-pulse' : ''}`}
                >
                  <JobCard job={job} onCancel={handleCancelJob} />
                </div>
              ))}
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between px-4 py-3 border-t border-gray-700">
                <div className="text-sm text-gray-400">
                  Showing {page * limit + 1} to {Math.min((page + 1) * limit, total)} of {total} jobs
                </div>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => setPage(page - 1)}
                    disabled={page === 0}
                    className="btn btn-ghost btn-sm"
                  >
                    Previous
                  </button>
                  <span className="text-sm text-gray-400">
                    Page {page + 1} of {totalPages}
                  </span>
                  <button
                    onClick={() => setPage(page + 1)}
                    disabled={page === totalPages - 1}
                    className="btn btn-ghost btn-sm"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}