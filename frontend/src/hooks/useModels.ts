import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { modelsAPI } from '../services/modelsApi'
import { ModelsConfiguration } from '../types/models'

export function useModelsConfiguration() {
  return useQuery({
    queryKey: ['models', 'configuration'],
    queryFn: () => modelsAPI.getConfiguration(),
    staleTime: 1000 * 60 * 5, // 5 minutes
  })
}

export function useSystemConfiguration() {
  return useQuery({
    queryKey: ['models', 'system'],
    queryFn: () => modelsAPI.getSystemConfiguration(),
    refetchInterval: 1000 * 30, // Refresh every 30 seconds
  })
}

export function useModelStatus(modelName: string) {
  return useQuery({
    queryKey: ['models', 'status', modelName],
    queryFn: () => modelsAPI.getModelStatus(modelName),
    enabled: !!modelName,
    refetchInterval: 1000 * 60, // Refresh every minute
  })
}

export function useAvailableOllamaModels() {
  return useQuery({
    queryKey: ['models', 'ollama', 'available'],
    queryFn: () => modelsAPI.getAvailableOllamaModels(),
    staleTime: 1000 * 60 * 10, // 10 minutes
  })
}

export function useModelMetrics() {
  return useQuery({
    queryKey: ['models', 'metrics'],
    queryFn: () => modelsAPI.getModelMetrics(),
    refetchInterval: 1000 * 60 * 5, // Refresh every 5 minutes
  })
}

export function useUpdateModelsConfiguration() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (config: Partial<ModelsConfiguration>) =>
      modelsAPI.updateConfiguration(config),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['models'] })
      toast.success('Models configuration updated successfully')
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.detail || 'Failed to update configuration')
    },
  })
}

export function useTestModel() {
  return useMutation({
    mutationFn: (modelName: string) => modelsAPI.testModel(modelName),
    onSuccess: (data, modelName) => {
      if (data.data.success) {
        toast.success(`${modelName} is working (${data.data.response_time_ms}ms)`)
      } else {
        toast.error(`${modelName} test failed: ${data.data.error}`)
      }
    },
    onError: (error: any, modelName) => {
      toast.error(`Failed to test ${modelName}: ${error.response?.data?.detail || error.message}`)
    },
  })
}

export function useToggleModel() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ modelName, enabled }: { modelName: string; enabled: boolean }) =>
      modelsAPI.toggleModel(modelName, enabled),
    onSuccess: (data, { modelName, enabled }) => {
      queryClient.invalidateQueries({ queryKey: ['models'] })
      toast.success(`${modelName} ${enabled ? 'enabled' : 'disabled'}`)
    },
    onError: (error: any, { modelName }) => {
      toast.error(`Failed to toggle ${modelName}: ${error.response?.data?.detail || error.message}`)
    },
  })
}

export function useDownloadModel() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (modelName: string) => modelsAPI.downloadModel(modelName),
    onSuccess: (data, modelName) => {
      queryClient.invalidateQueries({ queryKey: ['models'] })
      toast.success(`Started downloading ${modelName}`)
    },
    onError: (error: any, modelName) => {
      toast.error(`Failed to download ${modelName}: ${error.response?.data?.detail || error.message}`)
    },
  })
}