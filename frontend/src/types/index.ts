export interface User {
  id: number
  username: string
  email?: string
}

export interface LoginRequest {
  username: string
  password: string
}

export interface LoginResponse {
  access_token: string
  token_type: string
  user_id: number
  username: string
}

export interface ScanRequest {
  github_url?: string
}

export interface ScanResponse {
  job_id: string
  status: JobStatus
  message: string
}

export type JobStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface ProgressUpdate {
  job_id: string
  stage: string
  files_scanned: number
  total_files: number
  active_models: string[]
  eta_seconds?: number
  status: JobStatus
  progress_percentage: number
  current_file?: string
}

export interface VulnerabilityFinding {
  file: string
  line: number
  category: string
  severity: SeverityLevel
  confidence: number
  explanation: string
  patch?: string
  code_snippet?: string
  references: string[]
  found_by: string[]
}

export interface ExecutiveSummary {
  total_findings: number
  severity_counts: Record<SeverityLevel, number>
  risk_score: number
  risk_level: string
  files_analyzed: number
  files_with_issues: number
  processing_time: number
  models_used: string[]
  top_categories: Array<[string, number]>
}

export interface AnalysisReport {
  job_id: string
  executive_summary: ExecutiveSummary
  detailed_findings: VulnerabilityFinding[]
  metadata: any
  generated_at: string
  markdown_report?: string
}

export interface Job {
  id: string
  source_type: string
  source_url?: string
  status: JobStatus
  progress: number
  files_total: number
  files_scanned: number
  created_at: string
  completed_at?: string
}