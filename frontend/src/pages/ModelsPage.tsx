import React, { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { 
  Brain, 
  Cpu, 
  Zap, 
  Shield, 
  Activity, 
  BarChart3,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Clock,
  Gauge,
  Settings,
  Info,
  TrendingUp,
  Users,
  FileText,
  Target,
  Award,
  Database,
  Eye,
  GitBranch
} from 'lucide-react'
import { toast } from 'sonner'
import LoadingSpinner from '../components/LoadingSpinner'
import Badge from '../components/Badge'

// Types
interface ModelConfig {
  name: string
  type: 'ollama' | 'openai' | 'gemini' | 'anthropic'
  weight: number
  enabled: boolean
  description: string
  specializations: string[]
  api_key_env?: string
  model_size?: string
  parameters?: string
  context_window?: number
  max_tokens?: number
  temperature?: number
}

interface ModelStats {
  total_scans: number
  total_findings: number
  avg_confidence: number
  avg_scan_time: number
  success_rate: number
  last_used: string
  findings_by_severity: {
    critical: number
    high: number
    medium: number
    low: number
    info: number
  }
  top_categories: Array<[string, number]>
  performance_metrics: {
    speed_score: number
    accuracy_score: number
    consistency_score: number
  }
}

interface ModelInsight {
  model: ModelConfig
  stats: ModelStats
  health_status: 'healthy' | 'warning' | 'error' | 'unknown'
  availability: boolean
  last_health_check: string
}

// Mock API function - replace with your actual API
const getModelsInsights = async (): Promise<ModelInsight[]> => {
  // This should be replaced with actual API call
  const response = await fetch('/api/models/insights')
  if (!response.ok) {
    // Return mock data for now
    return mockModelsData
  }
  return response.json()
}

// Mock data - replace with actual data from your backend
const mockModelsData: ModelInsight[] = [
  {
    model: {
      name: "qwen2.5-coder:7b",
      type: "ollama",
      weight: 1.0,
      enabled: true,
      description: "Qwen2.5-Coder 7B - Excellent for code analysis",
      specializations: ["code_review", "vulnerability_detection", "secure_coding"],
      model_size: "7B",
      parameters: "7.0B",
      context_window: 32768,
      max_tokens: 8192,
      temperature: 0.1
    },
    stats: {
      total_scans: 145,
      total_findings: 428,
      avg_confidence: 0.85,
      avg_scan_time: 12.5,
      success_rate: 0.96,
      last_used: "2025-06-09T07:11:30.897479",
      findings_by_severity: {
        critical: 45,
        high: 123,
        medium: 156,
        low: 89,
        info: 15
      },
      top_categories: [
        ["hardcoded_secrets", 89],
        ["sql_injection", 67],
        ["xss", 45],
        ["weak_password", 34],
        ["info_disclosure", 28]
      ],
      performance_metrics: {
        speed_score: 8.5,
        accuracy_score: 9.2,
        consistency_score: 8.8
      }
    },
    health_status: "healthy",
    availability: true,
    last_health_check: "2025-06-09T07:15:00.000Z"
  },
  {
    model: {
      name: "deepseek-coder-v2:16b",
      type: "ollama",
      weight: 0.85,
      enabled: true,
      description: "DeepSeek Coder V2 16B - Advanced code understanding",
      specializations: ["general_security", "best_practices", "code_smells"],
      model_size: "16B",
      parameters: "16.0B",
      context_window: 16384,
      max_tokens: 4096,
      temperature: 0.2
    },
    stats: {
      total_scans: 98,
      total_findings: 312,
      avg_confidence: 0.78,
      avg_scan_time: 18.3,
      success_rate: 0.93,
      last_used: "2025-06-09T06:45:12.123456",
      findings_by_severity: {
        critical: 28,
        high: 87,
        medium: 134,
        low: 52,
        info: 11
      },
      top_categories: [
        ["injection_flaws", 76],
        ["access_control", 54],
        ["crypto_failures", 42],
        ["design_flaws", 31],
        ["logging_failures", 23]
      ],
      performance_metrics: {
        speed_score: 6.8,
        accuracy_score: 8.9,
        consistency_score: 9.1
      }
    },
    health_status: "healthy",
    availability: true,
    last_health_check: "2025-06-09T07:10:00.000Z"
  },
  {
    model: {
      name: "codellama:7b",
      type: "ollama",
      weight: 0.9,
      enabled: true,
      description: "Code Llama 7B - Strong code understanding",
      specializations: ["static_analysis", "code_patterns", "security_flaws"],
      model_size: "7B",
      parameters: "7.0B",
      context_window: 16384,
      max_tokens: 4096,
      temperature: 0.1
    },
    stats: {
      total_scans: 187,
      total_findings: 445,
      avg_confidence: 0.82,
      avg_scan_time: 14.7,
      success_rate: 0.91,
      last_used: "2025-06-09T05:30:45.789012",
      findings_by_severity: {
        critical: 52,
        high: 134,
        medium: 178,
        low: 67,
        info: 14
      },
      top_categories: [
        ["buffer_overflow", 92],
        ["race_conditions", 68],
        ["memory_leaks", 55],
        ["null_pointer", 43],
        ["format_string", 29]
      ],
      performance_metrics: {
        speed_score: 7.9,
        accuracy_score: 8.4,
        consistency_score: 8.1
      }
    },
    health_status: "warning",
    availability: true,
    last_health_check: "2025-06-09T07:05:00.000Z"
  },
  {
    model: {
      name: "gemini-pro",
      type: "gemini",
      weight: 1.0,
      enabled: true,
      description: "Google Gemini Pro - High quality analysis",
      specializations: ["advanced_threats", "complex_vulnerabilities", "enterprise_security"],
      api_key_env: "GEMINI_API_KEY",
      context_window: 32768,
      max_tokens: 8192,
      temperature: 0.1
    },
    stats: {
      total_scans: 67,
      total_findings: 203,
      avg_confidence: 0.91,
      avg_scan_time: 8.2,
      success_rate: 0.98,
      last_used: "2025-06-09T07:11:30.894086",
      findings_by_severity: {
        critical: 34,
        high: 67,
        medium: 78,
        low: 21,
        info: 3
      },
      top_categories: [
        ["advanced_persistent_threats", 45],
        ["zero_day_patterns", 32],
        ["enterprise_vulns", 28],
        ["cloud_security", 24],
        ["api_security", 19]
      ],
      performance_metrics: {
        speed_score: 9.5,
        accuracy_score: 9.8,
        consistency_score: 9.3
      }
    },
    health_status: "healthy",
    availability: true,
    last_health_check: "2025-06-09T07:12:00.000Z"
  },
  {
    model: {
      name: "codegemma:7b",
      type: "ollama",
      weight: 0.7,
      enabled: true,
      description: "CodeGemma 7B - Quick vulnerability detection",
      specializations: ["quick_scan", "common_vulnerabilities"],
      model_size: "7B",
      parameters: "7.0B",
      context_window: 8192,
      max_tokens: 2048,
      temperature: 0.15
    },
    stats: {
      total_scans: 234,
      total_findings: 567,
      avg_confidence: 0.76,
      avg_scan_time: 6.8,
      success_rate: 0.89,
      last_used: "2025-06-09T07:06:09.338326",
      findings_by_severity: {
        critical: 23,
        high: 89,
        medium: 234,
        low: 187,
        info: 34
      },
      top_categories: [
        ["input_validation", 123],
        ["output_encoding", 89],
        ["session_management", 76],
        ["error_handling", 54],
        ["data_validation", 43]
      ],
      performance_metrics: {
        speed_score: 9.2,
        accuracy_score: 7.6,
        consistency_score: 7.8
      }
    },
    health_status: "healthy",
    availability: true,
    last_health_check: "2025-06-09T07:08:00.000Z"
  }
]

const getHealthStatusColor = (status: string) => {
  switch (status) {
    case 'healthy': return 'text-green-400'
    case 'warning': return 'text-yellow-400'
    case 'error': return 'text-red-400'
    default: return 'text-gray-400'
  }
}

const getHealthStatusIcon = (status: string) => {
  switch (status) {
    case 'healthy': return CheckCircle
    case 'warning': return AlertTriangle
    case 'error': return XCircle
    default: return Clock
  }
}

const getModelTypeIcon = (type: string) => {
  switch (type) {
    case 'ollama': return Cpu
    case 'openai': return Brain
    case 'gemini': return Zap
    case 'anthropic': return Shield
    default: return Brain
  }
}

const getModelTypeColor = (type: string) => {
  switch (type) {
    case 'ollama': return 'text-blue-400 bg-blue-900/20'
    case 'openai': return 'text-green-400 bg-green-900/20'
    case 'gemini': return 'text-purple-400 bg-purple-900/20'
    case 'anthropic': return 'text-orange-400 bg-orange-900/20'
    default: return 'text-gray-400 bg-gray-900/20'
  }
}

export default function ModelsPage() {
  const [selectedModel, setSelectedModel] = useState<string | null>(null)
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid')

  const { data: modelsData, isLoading, error, refetch } = useQuery({
    queryKey: ['models-insights'],
    queryFn: getModelsInsights,
    refetchInterval: 30000, // Refresh every 30 seconds
  })

  const models = modelsData || mockModelsData

  const overallStats = models.reduce((acc, model) => ({
    totalModels: acc.totalModels + 1,
    activeModels: acc.activeModels + (model.model.enabled ? 1 : 0),
    totalScans: acc.totalScans + model.stats.total_scans,
    totalFindings: acc.totalFindings + model.stats.total_findings,
    avgSuccessRate: acc.avgSuccessRate + model.stats.success_rate,
  }), { totalModels: 0, activeModels: 0, totalScans: 0, totalFindings: 0, avgSuccessRate: 0 })

  overallStats.avgSuccessRate = overallStats.avgSuccessRate / models.length

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="text-center">
          <LoadingSpinner size="large" />
          <p className="mt-4 text-gray-400">Loading models insights...</p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="mx-auto h-12 w-12 text-red-400" />
        <h3 className="mt-2 text-lg font-medium text-white">Failed to Load Models</h3>
        <p className="mt-1 text-sm text-gray-400">
          Unable to fetch model insights data.
        </p>
        <button 
          onClick={() => refetch()}
          className="mt-4 btn btn-primary btn-sm"
        >
          🔄 Retry
        </button>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center">
            <Brain className="h-8 w-8 mr-3 text-blue-400" />
            AI Models Insights
          </h1>
          <p className="text-gray-400 mt-2">
            Comprehensive analysis of your security scanning AI models
          </p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center bg-gray-800 rounded-lg p-1">
            <button
              onClick={() => setViewMode('grid')}
              className={`px-3 py-1 rounded text-sm ${
                viewMode === 'grid' 
                  ? 'bg-blue-600 text-white' 
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              Grid
            </button>
            <button
              onClick={() => setViewMode('list')}
              className={`px-3 py-1 rounded text-sm ${
                viewMode === 'list' 
                  ? 'bg-blue-600 text-white' 
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              List
            </button>
          </div>
          <button 
            onClick={() => refetch()}
            className="btn btn-outline btn-sm"
          >
            🔄 Refresh
          </button>
        </div>
      </div>

      {/* Overall Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="card p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400">Total Models</p>
              <p className="text-2xl font-bold text-white">{overallStats.totalModels}</p>
            </div>
            <Database className="h-8 w-8 text-blue-400" />
          </div>
        </div>
        <div className="card p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400">Active Models</p>
              <p className="text-2xl font-bold text-green-400">{overallStats.activeModels}</p>
            </div>
            <CheckCircle className="h-8 w-8 text-green-400" />
          </div>
        </div>
        <div className="card p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400">Total Scans</p>
              <p className="text-2xl font-bold text-white">{overallStats.totalScans.toLocaleString()}</p>
            </div>
            <Activity className="h-8 w-8 text-purple-400" />
          </div>
        </div>
        <div className="card p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400">Total Findings</p>
              <p className="text-2xl font-bold text-white">{overallStats.totalFindings.toLocaleString()}</p>
            </div>
            <Shield className="h-8 w-8 text-red-400" />
          </div>
        </div>
        <div className="card p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400">Avg Success Rate</p>
              <p className="text-2xl font-bold text-white">{Math.round(overallStats.avgSuccessRate * 100)}%</p>
            </div>
            <TrendingUp className="h-8 w-8 text-yellow-400" />
          </div>
        </div>
      </div>

      {/* Models Grid/List */}
      <div className={viewMode === 'grid' ? 'grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6' : 'space-y-4'}>
        {models.map((modelInsight) => {
          const { model, stats, health_status, availability } = modelInsight
          const HealthIcon = getHealthStatusIcon(health_status)
          const TypeIcon = getModelTypeIcon(model.type)
          
          return (
            <div 
              key={model.name} 
              className={`card p-6 hover:border-gray-600 transition-all duration-200 cursor-pointer ${
                selectedModel === model.name ? 'ring-2 ring-blue-500 border-blue-500' : ''
              }`}
              onClick={() => setSelectedModel(selectedModel === model.name ? null : model.name)}
            >
              {/* Model Header */}
              <div className="flex items-start justify-between mb-4">
                <div className="flex-1">
                  <div className="flex items-center space-x-2 mb-2">
                    <TypeIcon className="h-5 w-5 text-blue-400" />
                    <h3 className="text-lg font-semibold text-white truncate">
                      {model.name}
                    </h3>
                    <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getModelTypeColor(model.type)}`}>
                      {model.type}
                    </span>
                  </div>
                  <p className="text-sm text-gray-400 mb-3">{model.description}</p>
                  
                  {/* Status and Availability */}
                  <div className="flex items-center space-x-4 mb-3">
                    <div className="flex items-center space-x-1">
                      <HealthIcon className={`h-4 w-4 ${getHealthStatusColor(health_status)}`} />
                      <span className={`text-xs ${getHealthStatusColor(health_status)}`}>
                        {health_status.charAt(0).toUpperCase() + health_status.slice(1)}
                      </span>
                    </div>
                    <div className="flex items-center space-x-1">
                      <div className={`h-2 w-2 rounded-full ${availability ? 'bg-green-400' : 'bg-red-400'}`} />
                      <span className="text-xs text-gray-400">
                        {availability ? 'Available' : 'Unavailable'}
                      </span>
                    </div>
                    <Badge variant={model.enabled ? 'info' : 'low'}>
                      {model.enabled ? 'Enabled' : 'Disabled'}
                    </Badge>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-sm text-gray-400">Weight</div>
                  <div className="text-lg font-bold text-white">{model.weight}</div>
                </div>
              </div>

              {/* Quick Stats */}
              <div className="grid grid-cols-2 gap-4 mb-4">
                <div className="bg-gray-700 p-3 rounded-lg text-center">
                  <p className="text-xs text-gray-400">Scans</p>
                  <p className="text-lg font-bold text-white">{stats.total_scans}</p>
                </div>
                <div className="bg-gray-700 p-3 rounded-lg text-center">
                  <p className="text-xs text-gray-400">Findings</p>
                  <p className="text-lg font-bold text-white">{stats.total_findings}</p>
                </div>
                <div className="bg-gray-700 p-3 rounded-lg text-center">
                  <p className="text-xs text-gray-400">Confidence</p>
                  <p className="text-lg font-bold text-white">{Math.round(stats.avg_confidence * 100)}%</p>
                </div>
                <div className="bg-gray-700 p-3 rounded-lg text-center">
                  <p className="text-xs text-gray-400">Success</p>
                  <p className="text-lg font-bold text-white">{Math.round(stats.success_rate * 100)}%</p>
                </div>
              </div>

              {/* Performance Metrics */}
              <div className="space-y-2 mb-4">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-gray-400">Speed</span>
                  <span className="text-white">{stats.performance_metrics.speed_score}/10</span>
                </div>
                <div className="w-full bg-gray-600 rounded-full h-1">
                  <div 
                    className="bg-blue-500 h-1 rounded-full" 
                    style={{ width: `${stats.performance_metrics.speed_score * 10}%` }}
                  />
                </div>
                
                <div className="flex items-center justify-between text-xs">
                  <span className="text-gray-400">Accuracy</span>
                  <span className="text-white">{stats.performance_metrics.accuracy_score}/10</span>
                </div>
                <div className="w-full bg-gray-600 rounded-full h-1">
                  <div 
                    className="bg-green-500 h-1 rounded-full" 
                    style={{ width: `${stats.performance_metrics.accuracy_score * 10}%` }}
                  />
                </div>
              </div>

              {/* Specializations */}
              <div className="mb-4">
                <p className="text-xs text-gray-400 mb-2">Specializations</p>
                <div className="flex flex-wrap gap-1">
                  {model.specializations.slice(0, 3).map((spec, index) => (
                    <span key={index} className="text-xs bg-gray-700 text-gray-300 px-2 py-1 rounded">
                      {spec.replace(/_/g, ' ')}
                    </span>
                  ))}
                  {model.specializations.length > 3 && (
                    <span className="text-xs bg-gray-700 text-gray-300 px-2 py-1 rounded">
                      +{model.specializations.length - 3}
                    </span>
                  )}
                </div>
              </div>

              {/* Expanded Details */}
              {selectedModel === model.name && (
                <div className="border-t border-gray-600 pt-4 mt-4 space-y-4">
                  {/* Technical Specs */}
                  <div>
                    <h4 className="text-sm font-medium text-white mb-2 flex items-center">
                      <Settings className="h-4 w-4 mr-1" />
                      Technical Specifications
                    </h4>
                    <div className="grid grid-cols-2 gap-2 text-xs">
                      {model.model_size && (
                        <>
                          <span className="text-gray-400">Model Size:</span>
                          <span className="text-white">{model.model_size}</span>
                        </>
                      )}
                      {model.context_window && (
                        <>
                          <span className="text-gray-400">Context Window:</span>
                          <span className="text-white">{model.context_window.toLocaleString()}</span>
                        </>
                      )}
                      {model.max_tokens && (
                        <>
                          <span className="text-gray-400">Max Tokens:</span>
                          <span className="text-white">{model.max_tokens.toLocaleString()}</span>
                        </>
                      )}
                      {model.temperature && (
                        <>
                          <span className="text-gray-400">Temperature:</span>
                          <span className="text-white">{model.temperature}</span>
                        </>
                      )}
                      <span className="text-gray-400">Avg Scan Time:</span>
                      <span className="text-white">{stats.avg_scan_time.toFixed(1)}s</span>
                    </div>
                  </div>

                  {/* Findings Breakdown */}
                  <div>
                    <h4 className="text-sm font-medium text-white mb-2 flex items-center">
                      <BarChart3 className="h-4 w-4 mr-1" />
                      Findings by Severity
                    </h4>
                    <div className="space-y-1">
                      {Object.entries(stats.findings_by_severity).map(([severity, count]) => (
                        <div key={severity} className="flex items-center justify-between text-xs">
                          <span className="capitalize text-gray-400">{severity}:</span>
                          <span className={`font-medium ${
                            severity === 'critical' ? 'text-red-400' :
                            severity === 'high' ? 'text-orange-400' :
                            severity === 'medium' ? 'text-yellow-400' :
                            severity === 'low' ? 'text-blue-400' : 'text-gray-400'
                          }`}>
                            {count}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Top Categories */}
                  <div>
                    <h4 className="text-sm font-medium text-white mb-2 flex items-center">
                      <Target className="h-4 w-4 mr-1" />
                      Top Vulnerability Categories
                    </h4>
                    <div className="space-y-1">
                      {stats.top_categories.slice(0, 3).map(([category, count]) => (
                        <div key={category} className="flex items-center justify-between text-xs">
                          <span className="text-gray-400 capitalize">
                            {category.replace(/_/g, ' ')}:
                          </span>
                          <span className="text-white font-medium">{count}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Last Activity */}
                  <div className="text-xs text-gray-400 border-t border-gray-600 pt-2">
                    <div className="flex justify-between">
                      <span>Last Used:</span>
                      <span>{new Date(stats.last_used).toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between mt-1">
                      <span>Health Check:</span>
                      <span>{new Date(modelInsight.last_health_check).toLocaleString()}</span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>

      {/* Performance Comparison Chart */}
      <div className="card">
        <div className="card-header">
          <h2 className="card-title flex items-center">
            <BarChart3 className="h-5 w-5 mr-2" />
            Performance Comparison
          </h2>
        </div>
        
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left py-3 px-4 text-gray-400">Model</th>
                <th className="text-center py-3 px-4 text-gray-400">Type</th>
                <th className="text-center py-3 px-4 text-gray-400">Scans</th>
                <th className="text-center py-3 px-4 text-gray-400">Findings</th>
                <th className="text-center py-3 px-4 text-gray-400">Confidence</th>
                <th className="text-center py-3 px-4 text-gray-400">Speed</th>
                <th className="text-center py-3 px-4 text-gray-400">Accuracy</th>
                <th className="text-center py-3 px-4 text-gray-400">Success Rate</th>
                <th className="text-center py-3 px-4 text-gray-400">Status</th>
              </tr>
            </thead>
            <tbody>
              {models.map((modelInsight) => {
                const { model, stats, health_status } = modelInsight
                const HealthIcon = getHealthStatusIcon(health_status)
                
                return (
                  <tr key={model.name} className="border-b border-gray-800 hover:bg-gray-800/50">
                    <td className="py-3 px-4">
                      <div className="flex items-center space-x-2">
                        <div className={`h-2 w-2 rounded-full ${model.enabled ? 'bg-green-400' : 'bg-gray-400'}`} />
                        <span className="text-white font-medium">{model.name}</span>
                      </div>
                    </td>
                    <td className="py-3 px-4 text-center">
                      <span className={`inline-flex items-center px-2 py-1 rounded text-xs ${getModelTypeColor(model.type)}`}>
                        {model.type}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-center text-white">{stats.total_scans}</td>
                    <td className="py-3 px-4 text-center text-white">{stats.total_findings}</td>
                    <td className="py-3 px-4 text-center text-white">{Math.round(stats.avg_confidence * 100)}%</td>
                    <td className="py-3 px-4 text-center text-white">{stats.performance_metrics.speed_score}/10</td>
                    <td className="py-3 px-4 text-center text-white">{stats.performance_metrics.accuracy_score}/10</td>
                    <td className="py-3 px-4 text-center text-white">{Math.round(stats.success_rate * 100)}%</td>
                    <td className="py-3 px-4 text-center">
                      <HealthIcon className={`h-4 w-4 mx-auto ${getHealthStatusColor(health_status)}`} />
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}