import { apiClient } from './api'
import { ModelsConfiguration, SystemConfiguration, ModelStatus } from '../types/models'

export const modelsAPI = {
  // Get current models configuration
  getConfiguration: () =>
    apiClient.get<ModelsConfiguration>('/models/config'),

  // Update models configuration
  updateConfiguration: (config: Partial<ModelsConfiguration>) =>
    apiClient.put<ModelsConfiguration>('/models/config', config),

  // Get system configuration including model status
  getSystemConfiguration: () =>
    apiClient.get<SystemConfiguration>('/models/system'),

  // Get individual model status
  getModelStatus: (modelName: string) =>
    apiClient.get<ModelStatus>(`/models/status/${modelName}`),

  // Test model availability
  testModel: (modelName: string) =>
    apiClient.post<{ success: boolean; response_time_ms: number; error?: string }>
      (`/models/test/${modelName}`),

  // Get available Ollama models
  getAvailableOllamaModels: () =>
    apiClient.get<{ models: Array<{ name: string; size: number; modified_at: string }> }>
      ('/models/ollama/available'),

  // Download/pull a new model
  downloadModel: (modelName: string) =>
    apiClient.post<{ job_id: string; message: string }>
      (`/models/download/${modelName}`),

  // Get download progress
  getDownloadProgress: (jobId: string) =>
    apiClient.get<{ progress: number; status: string; eta_seconds?: number }>
      (`/models/download/progress/${jobId}`),

  // Enable/disable a model
  toggleModel: (modelName: string, enabled: boolean) =>
    apiClient.patch<ModelStatus>(`/models/${modelName}/toggle`, { enabled }),

  // Get model performance metrics
  getModelMetrics: () =>
    apiClient.get<{
      models: Array<{
        name: string
        avg_response_time_ms: number
        success_rate: number
        total_requests: number
        last_used: string
      }>
    }>('/models/metrics'),
}