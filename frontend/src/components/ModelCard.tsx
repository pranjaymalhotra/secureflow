import { useState } from 'react'
import { 
  Bot, 
  CheckCircle, 
  XCircle, 
  Settings, 
  Play, 
  Download,
  AlertTriangle,
  Clock,
  Zap
} from 'lucide-react'
import { ModelConfig, ModelStatus } from '../types/models'
import { useTestModel, useToggleModel, useDownloadModel } from '../hooks/useModels'
import LoadingSpinner from './LoadingSpinner'
import Badge from './Badge'

interface ModelCardProps {
  model: ModelConfig
  status?: ModelStatus
  onConfigure?: (model: ModelConfig) => void
}

export default function ModelCard({ model, status, onConfigure }: ModelCardProps) {
  const [isExpanded, setIsExpanded] = useState(false)
  const testModel = useTestModel()
  const toggleModel = useToggleModel()
  const downloadModel = useDownloadModel()

  const handleTest = () => {
    testModel.mutate(model.name)
  }

  const handleToggle = () => {
    toggleModel.mutate({ modelName: model.name, enabled: !model.enabled })
  }

  const handleDownload = () => {
    downloadModel.mutate(model.name)
  }

  const getStatusIcon = () => {
    if (!status) return <Clock className="h-4 w-4 text-gray-400" />
    
    if (status.available && model.enabled) {
      return <CheckCircle className="h-4 w-4 text-green-400" />
    } else if (status.error) {
      return <XCircle className="h-4 w-4 text-red-400" />
    } else if (!status.available) {
      return <AlertTriangle className="h-4 w-4 text-yellow-400" />
    } else {
      return <Clock className="h-4 w-4 text-gray-400" />
    }
  }

  const getStatusText = () => {
    if (!status) return 'Unknown'
    
    if (status.available && model.enabled) {
      return 'Ready'
    } else if (status.error) {
      return 'Error'
    } else if (!status.available && model.type === 'ollama') {
      return 'Not Downloaded'
    } else if (!status.available) {
      return 'Unavailable'
    } else if (!model.enabled) {
      return 'Disabled'
    } else {
      return 'Unknown'
    }
  }

  const canDownload = model.type === 'ollama' && status && !status.available

  return (
    <div className={`card transition-all duration-200 ${
      model.enabled ? 'border-blue-600 bg-blue-900/10' : 'border-gray-700'
    }`}>
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-start space-x-3">
          <div className={`p-2 rounded-lg ${
            model.type === 'ollama' ? 'bg-blue-900/20 text-blue-400' :
            model.type === 'gemini' ? 'bg-green-900/20 text-green-400' :
            'bg-purple-900/20 text-purple-400'
          }`}>
            <Bot className="h-5 w-5" />
          </div>
          <div>
            <h3 className="font-medium text-white">{model.name}</h3>
            <p className="text-sm text-gray-400 capitalize">{model.type} model</p>
          </div>
        </div>
        
        <div className="flex items-center space-x-2">
          {getStatusIcon()}
          <Badge variant={
            getStatusText() === 'Ready' ? 'low' :
            getStatusText() === 'Error' ? 'critical' :
            getStatusText() === 'Disabled' ? 'medium' :
            'info'
          }>
            {getStatusText()}
          </Badge>
        </div>
      </div>

      {/* Description */}
      <p className="text-sm text-gray-300 mb-4">{model.description}</p>

      {/* Weight and Specializations */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-4">
          <div className="text-xs text-gray-400">
            Weight: <span className="text-white font-medium">{model.weight}</span>
          </div>
          <div className="flex items-center space-x-1">
            <Zap className="h-3 w-3 text-yellow-400" />
            <span className="text-xs text-gray-400">Priority Model</span>
          </div>
        </div>
      </div>

      {/* Specializations */}
      <div className="mb-4">
        <p className="text-xs text-gray-400 mb-2">Specializations:</p>
        <div className="flex flex-wrap gap-1">
          {model.specializations.slice(0, isExpanded ? undefined : 3).map((spec, index) => (
            <span 
              key={index}
              className="inline-flex items-center px-2 py-1 rounded text-xs bg-gray-700 text-gray-300"
            >
              {spec.replace(/_/g, ' ')}
            </span>
          ))}
          {model.specializations.length > 3 && !isExpanded && (
            <button
              onClick={() => setIsExpanded(true)}
              className="text-xs text-blue-400 hover:text-blue-300"
            >
              +{model.specializations.length - 3} more
            </button>
          )}
        </div>
      </div>

      {/* Error Message */}
      {status?.error && (
        <div className="mb-4 p-2 bg-red-900/20 border border-red-600 rounded text-xs text-red-200">
          {status.error}
        </div>
      )}

      {/* API Key Requirement */}
      {model.api_key_env && (
        <div className="mb-4 p-2 bg-yellow-900/20 border border-yellow-600 rounded text-xs text-yellow-200">
          Requires API key: {model.api_key_env}
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          {canDownload && (
            <button
              onClick={handleDownload}
              disabled={downloadModel.isPending}
              className="btn btn-ghost btn-sm"
            >
              {downloadModel.isPending ? (
                <LoadingSpinner size="small" className="mr-1" />
              ) : (
                <Download className="h-4 w-4 mr-1" />
              )}
              Download
            </button>
          )}
          
          <button
            onClick={handleTest}
            disabled={testModel.isPending || !status?.available}
            className="btn btn-ghost btn-sm"
          >
            {testModel.isPending ? (
              <LoadingSpinner size="small" className="mr-1" />
            ) : (
              <Play className="h-4 w-4 mr-1" />
            )}
            Test
          </button>
        </div>

        <div className="flex items-center space-x-2">
          {onConfigure && (
            <button
              onClick={() => onConfigure(model)}
              className="btn btn-ghost btn-sm"
            >
              <Settings className="h-4 w-4" />
            </button>
          )}
          
          <label className="relative inline-flex items-center cursor-pointer">
            <input
              type="checkbox"
              checked={model.enabled}
              onChange={handleToggle}
              disabled={toggleModel.isPending}
              className="sr-only peer"
            />
            <div className="w-11 h-6 bg-gray-600 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
          </label>
        </div>
      </div>

      {/* Last Check */}
      {status?.last_check && (
        <div className="mt-2 text-xs text-gray-500">
          Last checked: {new Date(status.last_check).toLocaleString()}
        </div>
      )}
    </div>
  )
}