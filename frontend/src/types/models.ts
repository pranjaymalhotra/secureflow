export interface ModelConfig {
  name: string
  type: 'ollama' | 'gemini' | 'openai'
  weight: number
  enabled: boolean
  description: string
  specializations: string[]
  api_key_env?: string
}

export interface SentinelModel {
  name: string
  type: string
  description: string
  fallback_models: string[]
}

export interface RuntimeConfig {
  ollama: {
    base_url: string
    timeout: number
    num_ctx: number
    temperature: number
    top_p: number
    repeat_penalty: number
  }
  gemini: {
    timeout: number
    temperature: number
    max_tokens: number
  }
  openai: {
    timeout: number
    temperature: number
    max_tokens: number
  }
}

export interface VulnerabilityCategory {
  weight: number
  subcategories: string[]
}

export interface ModelsConfiguration {
  primary_model: string
  worker_models: ModelConfig[]
  sentinel_model: SentinelModel
  runtime_config: RuntimeConfig
  vulnerability_categories: Record<string, VulnerabilityCategory>
  thresholds: {
    confidence_minimum: number
    severity_weights: Record<string, number>
  }
  report_settings: {
    max_findings_per_category: number
    include_code_snippets: boolean
    snippet_context_lines: number
    group_similar_findings: boolean
    include_remediation: boolean
    include_references: boolean
  }
  performance: {
    max_parallel_workers: number
    shard_size: number
    memory_limit_mb: number
    timeout_minutes: number
  }
  file_processing: {
    max_file_size_mb: number
    skip_binary_files: boolean
    supported_languages: string[]
  }
}

export interface ModelStatus {
  name: string
  type: string
  enabled: boolean
  available: boolean
  last_check: string
  error?: string
}

export interface SystemConfiguration {
  models: ModelsConfiguration
  model_status: ModelStatus[]
  system_info: {
    available_memory_gb: number
    cpu_cores: number
    ollama_running: boolean
    api_keys_configured: string[]
  }
}