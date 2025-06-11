import { useState, useEffect } from 'react'
import { X, Save, AlertTriangle } from 'lucide-react'
import { ModelConfig } from '../types/models'
import { useUpdateModelsConfiguration } from '../hooks/useModels'
import LoadingSpinner from './LoadingSpinner'

interface ModelConfigModalProps {
  model: ModelConfig | null
  isOpen: boolean
  onClose: () => void
}

export default function ModelConfigModal({ model, isOpen, onClose }: ModelConfigModalProps) {
  const [formData, setFormData] = useState<Partial<ModelConfig>>({})
  const updateConfig = useUpdateModelsConfiguration()

  useEffect(() => {
    if (model) {
      setFormData({ ...model })
    }
  }, [model])

  if (!isOpen || !model) return null

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    
    // Update the specific model in the configuration
    updateConfig.mutate({
      worker_models: [formData as ModelConfig]  // This would need proper implementation
    })
    
    onClose()
  }

  const handleChange = (field: keyof ModelConfig, value: any) => {
    setFormData(prev => ({ ...prev, [field]: value }))
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      
      <div className="relative bg-gray-800 rounded-lg p-6 w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-bold text-white">Configure {model.name}</h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white"
          >
            <X className="h-6 w-6" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Basic Settings */}
          <div className="space-y-4">
            <h3 className="text-lg font-medium text-white">Basic Settings</h3>
            
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Model Name
              </label>
              <input
                type="text"
                value={formData.name || ''}
                onChange={(e) => handleChange('name', e.target.value)}
                className="input"
                disabled
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Description
              </label>
              <textarea
                value={formData.description || ''}
                onChange={(e) => handleChange('description', e.target.value)}
                className="input min-h-[80px] resize-none"
                rows={3}
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Weight (0.0 - 1.0)
                </label>
                <input
                  type="number"
                  min="0"
                  max="1"
                  step="0.1"
                  value={formData.weight || 0}
                  onChange={(e) => handleChange('weight', parseFloat(e.target.value))}
                  className="input"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Type
                </label>
                <select
                  value={formData.type || 'ollama'}
                  onChange={(e) => handleChange('type', e.target.value)}
                  className="input"
                  disabled
                >
                  <option value="ollama">Ollama</option>
                  <option value="gemini">Gemini</option>
                  <option value="openai">OpenAI</option>
                </select>
              </div>
            </div>

            <div>
              <label className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={formData.enabled || false}
                  onChange={(e) => handleChange('enabled', e.target.checked)}
                  className="rounded border-gray-600 bg-gray-700 text-blue-600 focus:ring-blue-500"
                />
                <span className="text-sm text-gray-300">Enable this model</span>
              </label>
            </div>
          </div>

          {/* Specializations */}
          <div className="space-y-4">
            <h3 className="text-lg font-medium text-white">Specializations</h3>
            <div className="grid grid-cols-2 gap-2">
              {[
                'code_review', 'vulnerability_detection', 'secure_coding',
                'static_analysis', 'code_patterns', 'security_flaws',
                'general_security', 'best_practices', 'code_smells',
                'quick_scan', 'common_vulnerabilities', 'code_analysis'
              ].map((spec) => (
                <label key={spec} className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={formData.specializations?.includes(spec) || false}
                    onChange={(e) => {
                      const current = formData.specializations || []
                      if (e.target.checked) {
                        handleChange('specializations', [...current, spec])
                      } else {
                        handleChange('specializations', current.filter(s => s !== spec))
                      }
                    }}
                    className="rounded border-gray-600 bg-gray-700 text-blue-600 focus:ring-blue-500"
                  />
                  <span className="text-sm text-gray-300">
                    {spec.replace(/_/g, ' ')}
                  </span>
                </label>
              ))}
            </div>
          </div>

          {/* API Key (for cloud models) */}
          {(formData.type === 'gemini' || formData.type === 'openai') && (
            <div className="space-y-4">
              <h3 className="text-lg font-medium text-white">API Configuration</h3>
              
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  API Key Environment Variable
                </label>
                <input
                  type="text"
                  value={formData.api_key_env || ''}
                  onChange={(e) => handleChange('api_key_env', e.target.value)}
                  placeholder="e.g., GEMINI_API_KEY"
                  className="input"
                />
              </div>

              <div className="alert alert-warning">
                <AlertTriangle className="h-4 w-4" />
                <div>
                  <p className="font-medium">API Key Required</p>
                  <p className="text-sm">
                    This model requires an API key to be set in your environment variables.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Actions */}
          <div className="flex items-center justify-end space-x-4 pt-6 border-t border-gray-700">
            <button
              type="button"
              onClick={onClose}
              className="btn btn-ghost"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={updateConfig.isPending}
              className="btn btn-primary"
            >
              {updateConfig.isPending ? (
                <>
                  <LoadingSpinner size="small" className="mr-2" />
                  Saving...
                </>
              ) : (
                <>
                  <Save className="h-4 w-4 mr-2" />
                  Save Changes
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
