import axios from 'axios'

// Create axios instance
export const apiClient = axios.create({
  baseURL: '/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Token expired or invalid
      localStorage.removeItem('access_token')
      localStorage.removeItem('user_data')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

// Types
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
  status: string
  message: string
}

export interface JobProgressResponse {
  status: 'in_progress' | 'completed' | 'failed'
  progress?: number
  files_scanned?: number
  files_total?: number
  current_stage?: string
  message?: string
  data?: AnalysisReport
}

export interface ProgressUpdate {
  job_id: string
  stage: string
  files_scanned: number
  total_files: number
  active_models: string[]
  eta_seconds?: number
  status: string
  progress_percentage: number
  current_file?: string
}

export interface VulnerabilityFinding {
  file: string
  line: number
  category: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  confidence: number
  explanation: string
  patch?: string
  code_snippet?: string
  references: string[]
  found_by: string | string[]
}

export interface ExecutiveSummary {
  total_findings: number
  severity_counts: {
    critical: number
    high: number
    medium: number
    low: number
    info: number
  }
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
  model_reports?: { [key: string]: any }
  metadata: any
  generated_at: string
  markdown_report?: string
}


export interface Job {
  id: string
  source_type: string
  source_url?: string
  status: string
  progress: number
  files_total: number
  files_scanned: number
  created_at: string
  completed_at?: string
}

// API functions
export const authAPI = {
  login: (data: LoginRequest) => 
    apiClient.post<LoginResponse>('/auth/login', data),
}

export const scanAPI = {
  uploadFiles: (formData: FormData) => {
    // Increase the timeout to 5 minutes (300000ms)
    return apiClient.post<ScanResponse>('/scan/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data'
      },
      timeout: 300000, // 5 minutes - increase this for larger files
      onUploadProgress: (progressEvent) => {
        console.log('Upload progress:', progressEvent.loaded, 'of', progressEvent.total);
      }
    }).catch(error => {
      console.error('Upload error:', error);
      if (error.request) {
        console.error('Request:', error.request);
      }
      throw error;
    });
  },

  scanGitHub: (data: ScanRequest) =>
    apiClient.post<ScanResponse>('/scan/github', data),

  getProgress: (jobId: string) =>
    apiClient.get<ProgressUpdate>(`/progress/${jobId}`),

  // getReport: (jobId: string) => {
  //   console.log('Fetching report for job:', jobId)
  //   return apiClient.get<AnalysisReport>(`/api/reports/${jobId}`)
  //     .then(response => {
  //       console.log('API Response:', response)
  //       return response
  //     })
  //     .catch(error => {
  //       console.error('API Error:', error)
  //       throw error
  //     })
  // },


  getReport: async (jobId: string) => {
    console.log('Fetching report for job:', jobId)
    try {
      // Try the format that matches your getProgress endpoint pattern
      const response = await apiClient.get<AnalysisReport | JobProgressResponse>(`/report/${jobId}`)
      console.log('API Response:', response)
      return response.data
    } catch (error) {
      console.error('API Error:', error)
      throw error
    }
  },
}

export const jobsAPI = {
  list: (limit = 50, offset = 0) =>
    apiClient.get<{ jobs: Job[]; total: number }>('/jobs', {
      params: { limit, offset }
    }),

  cancel: (jobId: string) =>
    apiClient.delete(`/jobs/${jobId}`),
}

export const systemAPI = {
  health: () =>
    apiClient.get('/health'),
}