import React, { useState, useEffect, useRef } from 'react'
import { useParams, Link , useNavigate} from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { scanAPI } from '../services/api'
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Info, 
  Clock,
  Download,
  ExternalLink,
  ArrowLeft,
  FileText,
  TrendingUp,
  Users,
  Printer,
  Brain,
  Target,
  AlertCircle,
  Activity,
  BarChart3,
  Code,
  FileCode,
  Lock,
  Zap,
  Package,
  GitBranch,
  Database,
  Server,
  ChevronDown,
  ChevronRight,
  Eye,
  EyeOff,
  Loader2,
  Building,
  Globe,
  Layers,
  Settings,
  Award,
  Briefcase,
  Calendar,
  Gauge,
  History,
  MapPin,
  Network,
  Search,
  StarIcon,
  TestTube,
  Wrench,
  BookOpen,
  LineChart,
  PieChart,
  Cpu,
  HardDrive,
  Monitor,
  Cloud,
  Key,
  UserCheck,
  CheckSquare,
  XCircle,
  Timer,
  DollarSign,
  Scale,
  FileCheck,
  Bell,
  Flag
} from 'lucide-react'

// Comprehensive type definitions
interface VulnerabilityFinding {
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

interface EnhancedConsensusFinding {
  category: string
  display_name: string
  severity: string
  confidence: number
  confidence_level: string
  models_agreed: string[]
  consensus_strength: number
  findings_count: number
  
  threat_analysis?: {
    threat_actors: Array<{
      type: string
      motivation: string
      capability: string
      likelihood: string
    }>
    attack_vectors: Array<{
      vector: string
      description: string
      complexity: string
      detection_difficulty: string
    }>
    real_world_examples?: Array<{
      incident: string
      year: string
      impact: string
      description: string
    }>
  }
  
  attack_scenario?: {
    scenario_name: string
    attack_narrative: string
    technical_steps: string[]
    business_impact_timeline?: Record<string, string>
  }
  
  exploit_difficulty?: {
    difficulty: string
    skill_level: string
    tools_required: string[]
    time_to_exploit: string
    success_probability: string
    detection_likelihood: string
  }
  
  business_impact?: {
    financial_impact: {
      total_estimated_impact: string
      direct_costs: Record<string, string>
      indirect_costs: Record<string, string>
    }
    operational_impact: {
      service_availability: string
      recovery_time: string
      business_continuity: string
    }
    reputational_impact: {
      customer_trust: string
      recovery_timeline: Record<string, string>
    }
  }
  
  compliance_mapping?: {
    owasp_top_10: {
      category: string
      description: string
      risk_factor: string
      technical_impact: string
      references: string[]
    }
    cwe_mapping: {
      primary: {
        id: string
        name: string
        description: string
        url: string
      }
    }
    pci_dss?: {
      requirements: string[]
      applicability: string
    }
    gdpr_impact?: {
      articles: string[]
      risk_level: string
      breach_notification: {
        required: boolean
        timeline: string
      }
    }
  }
  
  regulatory_risks?: {
    overall_regulatory_risk: string
    high_risk_frameworks: string[]
    immediate_actions_required: string[]
  }
  
  technical_description?: {
    mechanism: string
    technical_details: {
      affected_languages?: string[]
      attack_vectors?: string[]
    }
    code_patterns: {
      vulnerable: string[]
      secure_alternatives: string[]
    }
  }
  
  remediation_roadmap?: {
    total_effort: string
    complexity: string
    phases: Array<{
      phase: string
      timeline: string
      effort: string
      tasks: string[]
      deliverables: string[]
    }>
  }
  
  immediate_actions?: string[]
  prevention_strategy?: {
    immediate_actions: string[]
    long_term_strategy: {
      architecture: string[]
      development_practices: string[]
    }
  }
  
  risk_metrics?: {
    severity: string
    confidence: number
    exploit_difficulty: any
  }
  cvss_estimation?: {
    base_score: number
    vector: string
    severity_rating: string
  }
  priority_score?: number
  
  critical_example?: {
    file: string
    line: number
    code_context: string
    explanation: string
  }
  affected_files?: string[]
}

interface ExecutiveSummary {
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
  generated_at: string
}

interface FileAnalysisSummary {
  file: string
  model: string
  risk_score: number
  summary: string
  key_issues: string[]
  code_quality_observations: string
  security_posture: string
  recommendations: string[]
}

interface ModelOverallAnalysis {
  model: string
  architecture_observations: string
  security_patterns: {
    positive_patterns?: string
    negative_patterns?: string
    authentication_handling?: string
    data_validation?: string
    error_handling?: string
    [key: string]: string | undefined;
  }
  code_flow_analysis: string
  systemic_issues: string[]
  strengths: string[]
  risk_areas: string[]
  recommendations: string[]
}

interface DepthAnalysis {
  synthesis_model: string
  executive_insights: string
  enhanced_consensus_findings?: EnhancedConsensusFinding[]
  critical_consensus_findings: Array<{
    issue: string
    severity: string
    models_agreed: string[]
    confidence: number
    impact: string
  }>
  unique_insights_by_model: Record<string, string[]>
  architectural_risks: string[]
  security_debt_assessment: string
  prioritized_action_items: Array<{
    action: string
    priority: number
    effort: string
    impact: string
    category: string
  }>
  risk_matrix: {
    high_impact_low_effort?: string[]
    high_impact_high_effort?: string[]
    low_impact_low_effort?: string[]
    low_impact_high_effort?: string[]
  }
  confidence_analysis: string
  generated_at: string
}

interface ModelReport {
  model: {
    name: string
    type: string
    weight: number
    enabled: boolean
    description: string
    specializations: string[]
  }
  findings: VulnerabilityFinding[]
  processed_files: number
  total_findings: number
  timestamp: string
}

interface AnalysisReport {
  job_id: string
  depth_analysis?: DepthAnalysis
  model_overall_analyses?: Record<string, ModelOverallAnalysis>
  file_summaries_by_model?: Record<string, FileAnalysisSummary[]>
  executive_summary: ExecutiveSummary
  detailed_findings: VulnerabilityFinding[]
  model_reports?: Record<string, ModelReport>
  metadata?: any
  generated_at: string
  markdown_report?: string
}

interface JobProgressResponse {
  status: 'in_progress' | 'completed' | 'failed'
  progress?: number
  files_scanned?: number
  files_total?: number
  current_stage?: string
  message?: string
  data?: AnalysisReport 
}

// Enhanced Badge Component
const Badge: React.FC<{
  children: React.ReactNode
  variant?: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'success' | 'warning' | 'default'
  className?: string
  size?: 'sm' | 'md' | 'lg'
}> = ({ children, variant = 'info', className = '', size = 'md' }) => {
  const variants = {
    critical: 'bg-red-900/50 text-red-300 border-red-700',
    high: 'bg-orange-900/50 text-orange-300 border-orange-700',
    medium: 'bg-yellow-900/50 text-yellow-300 border-yellow-700',
    low: 'bg-blue-900/50 text-blue-300 border-blue-700',
    info: 'bg-gray-900/50 text-gray-300 border-gray-700',
    success: 'bg-green-900/50 text-green-300 border-green-700',
    warning: 'bg-yellow-900/50 text-yellow-300 border-yellow-700',
    default: 'bg-gray-900/50 text-gray-300 border-gray-700'
  }

  const sizes = {
    sm: 'px-2 py-0.5 text-xs',
    md: 'px-2.5 py-0.5 text-xs',
    lg: 'px-3 py-1 text-sm'
  }

  return (
    <span className={`inline-flex items-center rounded-full font-medium border ${variants[variant]} ${sizes[size]} ${className}`}>
      {children}
    </span>
  )
}

// Enhanced Utility functions
const formatDuration = (seconds: number): string => {
  if (seconds < 60) return `${Math.round(seconds)}s`
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`
  return `${Math.round(seconds / 3600)}h ${Math.round((seconds % 3600) / 60)}m`
}

const getSeverityColor = (severity: string): string => {
  switch (severity.toLowerCase()) {
    case 'critical': return 'text-red-400'
    case 'high': return 'text-orange-400'
    case 'medium': return 'text-yellow-400'
    case 'low': return 'text-blue-400'
    default: return 'text-gray-400'
  }
}

const getSeverityBgColor = (severity: string): string => {
  switch (severity.toLowerCase()) {
    case 'critical': return 'bg-red-500'
    case 'high': return 'bg-orange-500'
    case 'medium': return 'bg-yellow-500'
    case 'low': return 'bg-blue-500'
    default: return 'bg-gray-500'
  }
}

const getRiskLevelColor = (level: string): string => {
  switch (level.toUpperCase()) {
    case 'CRITICAL': return 'text-red-400 bg-red-900/20'
    case 'HIGH': return 'text-orange-400 bg-orange-900/20'
    case 'MEDIUM': return 'text-yellow-400 bg-yellow-900/20'
    case 'LOW': return 'text-blue-400 bg-blue-900/20'
    default: return 'text-green-400 bg-green-900/20'
  }
}

const formatCurrency = (amount: number): string => {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 0,
    maximumFractionDigits: 0,
  }).format(amount)
}

const formatPercentage = (value: number): string => {
  return `${(value * 100).toFixed(1)}%`
}

const getConfidenceColor = (confidence: number): string => {
  if (confidence >= 0.9) return 'text-green-400';
  if (confidence >= 0.7) return 'text-blue-400';
  if (confidence >= 0.5) return 'text-yellow-400';
  if (confidence >= 0.3) return 'text-orange-400';
  return 'text-red-400';
}

// Calculate dynamic risk score based on findings
const calculateRiskScore = (findings: VulnerabilityFinding[], summary: ExecutiveSummary): number => {
  if (!findings || findings.length === 0) return 0;
  
  const severityWeights = {
    critical: 10,
    high: 7,
    medium: 4,
    low: 2,
    info: 1
  };
  
  const totalWeight = findings.reduce((sum, finding) => {
    return sum + (severityWeights[finding.severity] || 0) * finding.confidence;
  }, 0);
  
  const maxPossibleWeight = findings.length * 10; // All critical with 100% confidence
  const baseScore = Math.min((totalWeight / Math.max(maxPossibleWeight, 1)) * 100, 100);
  
  // Adjust based on files affected ratio
  const fileAffectedRatio = summary.files_with_issues / Math.max(summary.files_analyzed, 1);
  const adjustedScore = baseScore + (fileAffectedRatio * 20);
  
  return Math.min(Math.round(adjustedScore), 100);
}

// Professional Print Styles
const printStyles = `
  @media print {
    @page {
      size: A4;
      margin: 15mm;
    }
    
    body {
      print-color-adjust: exact !important;
      -webkit-print-color-adjust: exact !important;
      font-size: 10pt;
    }
    
    .no-print {
      display: none !important;
    }
    
    .page-break {
      page-break-before: always !important;
    }
    
    .avoid-break {
      page-break-inside: avoid !important;
    }
    
    .card {
      border: 1px solid #ccc !important;
      margin-bottom: 0.75rem !important;
      box-shadow: none !important;
    }

    .card-header {
      padding-bottom: 0.5rem !important;
    }
    
    .bg-gray-800, .bg-gray-800\\/50, .bg-gray-800\\/30, .bg-gray-900,
    .bg-red-900\\/10, .bg-green-900\\/10, .bg-blue-900\\/10, .bg-yellow-900\\/10, .bg-orange-900\\/10, .bg-purple-900\\/20, .bg-indigo-900\\/20 {
      background-color: #ffffff !important;
      border-color: #e5e7eb !important;
    }

    .bg-red-900\\/20, .bg-orange-900\\/20, .bg-yellow-900\\/20, .bg-blue-900\\/20, .bg-green-900\\/20 {
      background-color: #f0f0f0 !important;
    }
    
    .text-white, .text-gray-300, .text-gray-400, .text-red-300, .text-orange-300, .text-yellow-300, .text-blue-300, .text-green-300, .text-purple-300, .text-green-100 {
      color: #000000 !important;
    }

    .text-red-400 { color: #c00 !important; }
    .text-orange-400 { color: #f50 !important; }
    .text-yellow-400 { color: #a50 !important; }
    .text-blue-400 { color: #00c !important; }
    .text-green-400 { color: #080 !important; }
    .text-purple-400 { color: #808 !important; }
    .text-gray-500 { color: #555 !important; }

    .border-gray-700, .border-red-700, .border-green-700, .border-blue-700, .border-yellow-700, .border-orange-700, .border-purple-700, .border-purple-600, .border-red-800\\/50 {
      border-color: #ccc !important;
    }
    
    .prose-invert {
      --tw-prose-body: #000 !important;
      --tw-prose-headings: #000 !important;
      --tw-prose-lead: #000 !important;
      --tw-prose-links: #000 !important;
      --tw-prose-bold: #000 !important;
      --tw-prose-counters: #000 !important;
      --tw-prose-bullets: #000 !important;
      --tw-prose-hr: #ccc !important;
      --tw-prose-quotes: #000 !important;
      --tw-prose-quote-borders: #ccc !important;
      --tw-prose-captions: #000 !important;
      --tw-prose-code: #000 !important;
      --tw-prose-pre-code: #000 !important;
      --tw-prose-pre-bg: #f0f0f0 !important;
      --tw-prose-th-borders: #ccc !important;
      --tw-prose-td-borders: #ccc !important;
    }

    h1, h2, h3, h4 { font-weight: bold !important; }
    h1 { font-size: 18pt !important; }
    h2 { font-size: 16pt !important; }
    h3 { font-size: 14pt !important; }
    h4 { font-size: 12pt !important; }

    pre, code {
      font-family: 'Courier New', Courier, monospace !important;
      font-size: 9pt !important;
      background-color: #f0f0f0 !important;
      border: 1px solid #ddd !important;
      padding: 0.25rem 0.5rem !important;
      white-space: pre-wrap !important;
      word-break: break-all !important;
    }
  }
`

// Enhanced Expandable Section Component
const ExpandableSection: React.FC<{
  title: string
  icon?: React.ReactNode
  defaultExpanded?: boolean
  children: React.ReactNode
  className?: string
  badge?: React.ReactNode
}> = ({ title, icon, defaultExpanded = true, children, className = '', badge }) => {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded)

  return (
    <div className={`border border-gray-700 rounded-lg ${className}`}>
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full px-6 py-4 flex items-center justify-between hover:bg-gray-800 transition-colors rounded-t-lg no-print"
      >
        <div className="flex items-center space-x-3">
          {icon}
          <h3 className="text-lg font-medium text-white">{title}</h3>
          {badge}
        </div>
        {isExpanded ? (
          <ChevronDown className="h-5 w-5 text-gray-400" />
        ) : (
          <ChevronRight className="h-5 w-5 text-gray-400" />
        )}
      </button>
      <div className="print:block"> 
        {isExpanded && (
          <div className="px-6 py-4 border-t border-gray-700 print:border-t-0">
            {children}
          </div>
        )}
      </div>
    </div>
  )
}

// Enhanced Risk Score Visualization Component
const RiskScoreVisualization: React.FC<{ 
  score: number; 
  maxScore?: number;
  size?: 'sm' | 'md' | 'lg'
  showDetails?: boolean
}> = ({ score, maxScore = 100, size = 'md', showDetails = true }) => {
  const percentage = (score / maxScore) * 100
  const radius = size === 'sm' ? 35 : size === 'lg' ? 55 : 45
  const circumference = 2 * Math.PI * radius
  const strokeDashoffset = circumference - (percentage / 100) * circumference

  const getColor = () => {
    if (percentage >= 80) return '#ef4444' // red
    if (percentage >= 60) return '#f97316' // orange
    if (percentage >= 40) return '#eab308' // yellow
    if (percentage >= 20) return '#3b82f6' // blue
    return '#10b981' // green
  }

  const getRiskLevel = () => {
    if (percentage >= 80) return 'Critical'
    if (percentage >= 60) return 'High'
    if (percentage >= 40) return 'Medium'
    if (percentage >= 20) return 'Low'
    return 'Minimal'
  }

  const dimensions = size === 'sm' ? 'w-24 h-24' : size === 'lg' ? 'w-40 h-40' : 'w-32 h-32'

  return (
    <div className="relative inline-flex flex-col items-center justify-center">
      <svg className={`transform -rotate-90 ${dimensions}`} viewBox="0 0 128 128">
        <circle
          cx="64"
          cy="64"
          r={radius}
          stroke="currentColor"
          strokeWidth="8"
          fill="none"
          className="text-gray-700 print:text-gray-300"
        />
        <circle
          cx="64"
          cy="64"
          r={radius}
          stroke={getColor()}
          strokeWidth="8"
          fill="none"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          className="transition-all duration-1000 ease-out"
        />
      </svg>
      <div className="absolute text-center">
        <div className={`${size === 'sm' ? 'text-lg' : size === 'lg' ? 'text-4xl' : 'text-3xl'} font-bold text-white`}>
          {score}
        </div>
        <div className={`${size === 'sm' ? 'text-xs' : 'text-xs'} text-gray-400`}>
          Risk Score
        </div>
      </div>
      {showDetails && (
        <div className="mt-4 text-center">
          <div className={`text-sm font-medium ${getSeverityColor(getRiskLevel().toLowerCase())}`}>
            {getRiskLevel()} Risk
          </div>
          <div className="text-xs text-gray-500">
            {percentage.toFixed(1)}% of maximum
          </div>
        </div>
      )}
    </div>
  )
}

// Security Metrics Dashboard Component
// Security Metrics Dashboard Component
const SecurityMetricsDashboard: React.FC<{ 
  summary: ExecutiveSummary
  detailedFindings: VulnerabilityFinding[]
}> = ({ summary, detailedFindings }) => {
  const calculatedRiskScore = calculateRiskScore(detailedFindings, summary)

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Primary Risk Metrics */}
      <div className="lg:col-span-1">
        <div className="bg-gray-800 rounded-lg p-6 h-full">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
            <Gauge className="h-5 w-5 mr-2 text-blue-400" />
            Security Health Score
          </h3>
          <div className="flex items-center justify-center">
            <RiskScoreVisualization score={calculatedRiskScore} size="lg" />
          </div>
        </div>
      </div>

      {/* Detailed Metrics Grid */}
      <div className="lg:col-span-2">
        <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
          <div className="bg-gray-800 rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <div className="text-sm text-gray-400">Critical Issues</div>
              <AlertTriangle className="h-4 w-4 text-red-400" />
            </div>
            <div className="text-2xl font-bold text-white">{summary.severity_counts?.critical || 0}</div>
            <div className="text-xs text-red-400">Immediate attention</div>
          </div>

          <div className="bg-gray-800 rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <div className="text-sm text-gray-400">High Priority</div>
              <AlertCircle className="h-4 w-4 text-orange-400" />
            </div>
            <div className="text-2xl font-bold text-white">{summary.severity_counts?.high || 0}</div>
            <div className="text-xs text-orange-400">This week</div>
          </div>

          <div className="bg-gray-800 rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <div className="text-sm text-gray-400">Medium Risk</div>
              <Info className="h-4 w-4 text-yellow-400" />
            </div>
            <div className="text-2xl font-bold text-white">{summary.severity_counts?.medium || 0}</div>
            <div className="text-xs text-yellow-400">Next sprint</div>
          </div>

          <div className="bg-gray-800 rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <div className="text-sm text-gray-400">Coverage</div>
              <FileText className="h-4 w-4 text-blue-400" />
            </div>
            <div className="text-2xl font-bold text-white">{summary.files_analyzed || 0}</div>
            <div className="text-xs text-blue-400">Files scanned</div>
          </div>

          <div className="bg-gray-800 rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <div className="text-sm text-gray-400">Affected</div>
              <Target className="h-4 w-4 text-purple-400" />
            </div>
            <div className="text-2xl font-bold text-white">{summary.files_with_issues || 0}</div>
            <div className="text-xs text-purple-400">With issues</div>
          </div>

          <div className="bg-gray-800 rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <div className="text-sm text-gray-400">Analysis Time</div>
              <Clock className="h-4 w-4 text-green-400" />
            </div>
            <div className="text-2xl font-bold text-white">{formatDuration(summary.processing_time || 0)}</div>
            <div className="text-xs text-green-400">Processing</div>
          </div>
        </div>
      </div>
    </div>
  )
}

// Dynamic Compliance & Regulatory Section Component
const ComplianceSection: React.FC<{ 
  detailedFindings: VulnerabilityFinding[]
  enhancedFindings?: EnhancedConsensusFinding[]
}> = ({ detailedFindings }) => {
  const [activeFramework, setActiveFramework] = useState('owasp')

  const calculateComplianceMetrics = () => {
    const criticalCount = detailedFindings.filter(f => f.severity === 'critical').length
    const highCount = detailedFindings.filter(f => f.severity === 'high').length
    const mediumCount = detailedFindings.filter(f => f.severity === 'medium').length
    const totalFindings = detailedFindings.length
    
    // Dynamic calculation based on actual findings
    const injectionFindings = detailedFindings.filter(f => 
      f.category.toLowerCase().includes('injection') || 
      f.category.toLowerCase().includes('sql') ||
      f.category.toLowerCase().includes('xss')
    ).length
    
    const authFindings = detailedFindings.filter(f => 
      f.category.toLowerCase().includes('auth') || 
      f.category.toLowerCase().includes('session') ||
      f.category.toLowerCase().includes('password')
    ).length
    
    const cryptoFindings = detailedFindings.filter(f => 
      f.category.toLowerCase().includes('crypto') || 
      f.category.toLowerCase().includes('encryption') ||
      f.category.toLowerCase().includes('hash')
    ).length
    
    return {
      owasp: {
        compliance: Math.max(5, 100 - (criticalCount * 25 + highCount * 15 + mediumCount * 5)),
        status: criticalCount > 0 ? 'critical' : highCount > 3 ? 'warning' : 'good',
        issues: criticalCount + highCount,
        description: 'OWASP Top 10 2021 compliance assessment',
        categoryFindings: {
          injection: injectionFindings,
          authentication: authFindings,
          crypto: cryptoFindings
        }
      },
      pci: {
        compliance: Math.max(10, 100 - (criticalCount * 30 + highCount * 20)),
        status: criticalCount > 0 ? 'critical' : highCount > 2 ? 'warning' : 'good',
        issues: criticalCount + Math.ceil(highCount / 2),
        description: 'PCI DSS security requirements compliance'
      },
      gdpr: {
        compliance: Math.max(15, 100 - (criticalCount * 20 + highCount * 12 + mediumCount * 3)),
        status: criticalCount > 0 ? 'warning' : highCount > 5 ? 'warning' : 'good',
        issues: Math.floor((criticalCount * 2 + highCount) / 2),
        description: 'GDPR data protection compliance'
      },
      nist: {
        compliance: Math.max(20, 100 - (totalFindings * 2 + criticalCount * 15)),
        status: criticalCount > 0 || totalFindings > 20 ? 'warning' : 'good',
        issues: criticalCount + Math.floor(highCount / 2),
        description: 'NIST Cybersecurity Framework alignment'
      }
    }
  }

  const complianceData = calculateComplianceMetrics()

  const frameworks = [
    { id: 'owasp', name: 'OWASP Top 10', icon: Shield },
    { id: 'pci', name: 'PCI DSS', icon: Lock },
    { id: 'gdpr', name: 'GDPR', icon: Scale },
    { id: 'nist', name: 'NIST CSF', icon: Award }
  ]

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'good': return 'text-green-400 bg-green-900/20'
      case 'warning': return 'text-yellow-400 bg-yellow-900/20'
      case 'critical': return 'text-red-400 bg-red-900/20'
      default: return 'text-gray-400 bg-gray-900/20'
    }
  }

  const getOwaspCategoryDetails = () => {
    const owaspData = complianceData.owasp
    return [
      {
        category: 'A03:2021 - Injection',
        findings: owaspData.categoryFindings.injection,
        status: owaspData.categoryFindings.injection > 0 ? 'fail' : 'pass',
        description: 'SQL, NoSQL, OS injection vulnerabilities'
      },
      {
        category: 'A07:2021 - Authentication Failures',
        findings: owaspData.categoryFindings.authentication,
        status: owaspData.categoryFindings.authentication > 0 ? 'fail' : 'pass',
        description: 'Broken authentication and session management'
      },
      {
        category: 'A02:2021 - Cryptographic Failures',
        findings: owaspData.categoryFindings.crypto,
        status: owaspData.categoryFindings.crypto > 0 ? 'fail' : 'pass',
        description: 'Weak or missing encryption implementation'
      }
    ]
  }

  return (
    <div className="card avoid-break">
      <div className="card-header">
        <h2 className="card-title flex items-center text-xl">
          <Scale className="h-6 w-6 mr-2 text-blue-400" />
          Compliance & Regulatory Assessment
        </h2>
        <p className="text-sm text-gray-400 mt-1">
          Dynamic assessment against major security frameworks based on actual findings
        </p>
      </div>

      <div className="p-6">
        {/* Framework Selection */}
        <div className="flex flex-wrap gap-2 mb-6 no-print">
          {frameworks.map(framework => {
            const IconComponent = framework.icon
            const data = complianceData[framework.id as keyof typeof complianceData]
            return (
              <button
                key={framework.id}
                onClick={() => setActiveFramework(framework.id)}
                className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-colors ${
                  activeFramework === framework.id
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
                }`}
              >
                <IconComponent className="h-4 w-4" />
                <span className="text-sm font-medium">{framework.name}</span>
                <Badge 
                  variant={data.status as any} 
                  size="sm"
                  className="ml-2"
                >
                  {data.compliance}%
                </Badge>
              </button>
            )
          })}
        </div>

        {/* Compliance Overview Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          {frameworks.map(framework => {
            const data = complianceData[framework.id as keyof typeof complianceData]
            const IconComponent = framework.icon
            
            return (
              <div key={framework.id} className="bg-gray-800/50 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    <IconComponent className="h-4 w-4 text-blue-400" />
                    <span className="text-sm font-medium text-white">{framework.name}</span>
                  </div>
                  <span className={`text-xs px-2 py-1 rounded-full ${getStatusColor(data.status)}`}>
                    {data.status.toUpperCase()}
                  </span>
                </div>
                <div className="text-2xl font-bold text-white mb-1">{data.compliance}%</div>
                <div className="text-xs text-gray-400 mb-3">{data.description}</div>
                
                {/* Compliance Bar */}
                <div className="w-full bg-gray-700 rounded-full h-2">
                  <div 
                    className={`h-2 rounded-full transition-all duration-500 ${
                      data.status === 'good' ? 'bg-green-500' :
                      data.status === 'warning' ? 'bg-yellow-500' : 'bg-red-500'
                    }`}
                    style={{ width: `${data.compliance}%` }}
                  />
                </div>
                
                {data.issues > 0 && (
                  <div className="mt-2 text-xs text-red-400">
                    {data.issues} compliance issue{data.issues !== 1 ? 's' : ''}
                  </div>
                )}
              </div>
            )
          })}
        </div>

        {/* Detailed Framework Analysis */}
        <div className="bg-gray-800/30 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4">
            {frameworks.find(f => f.id === activeFramework)?.name} Detailed Analysis
          </h3>
          
          {activeFramework === 'owasp' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h4 className="font-medium text-white mb-2">Top 10 Categories Assessment</h4>
                  <div className="space-y-2">
                    {getOwaspCategoryDetails().map((category, index) => (
                      <div key={index} className="flex items-center justify-between p-3 bg-gray-900/50 rounded">
                        <div>
                          <span className="text-sm font-medium text-white">{category.category}</span>
                          <div className="text-xs text-gray-400">{category.description}</div>
                          <div className="text-xs text-gray-500">{category.findings} findings</div>
                        </div>
                        <Badge variant={category.status === 'pass' ? 'success' : 'critical'} size="sm">
                          {category.status.toUpperCase()}
                        </Badge>
                      </div>
                    ))}
                  </div>
                </div>
                
                <div>
                  <h4 className="font-medium text-white mb-2">Risk Assessment</h4>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-400">Injection Vulnerabilities</span>
                      <span className={`text-sm ${complianceData.owasp.categoryFindings.injection > 0 ? 'text-red-400' : 'text-green-400'}`}>
                        {complianceData.owasp.categoryFindings.injection > 0 ? 'High Risk' : 'Low Risk'}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-400">Authentication Issues</span>
                      <span className={`text-sm ${complianceData.owasp.categoryFindings.authentication > 0 ? 'text-orange-400' : 'text-green-400'}`}>
                        {complianceData.owasp.categoryFindings.authentication > 0 ? 'Medium Risk' : 'Low Risk'}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-400">Cryptographic Issues</span>
                      <span className={`text-sm ${complianceData.owasp.categoryFindings.crypto > 0 ? 'text-yellow-400' : 'text-green-400'}`}>
                        {complianceData.owasp.categoryFindings.crypto > 0 ? 'Medium Risk' : 'Low Risk'}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="mt-4 p-4 bg-blue-900/20 border border-blue-700 rounded-lg">
                <h4 className="font-medium text-blue-300 mb-2">Compliance Recommendations</h4>
                <ul className="text-sm text-gray-300 space-y-1">
                  <li>• Implement comprehensive input validation framework</li>
                  <li>• Deploy additional authentication security controls</li>
                  <li>• Establish secure software supply chain practices</li>
                  <li>• Regular security testing and code review processes</li>
                </ul>
              </div>
            </div>
          )}

          {/* Additional framework details would be similar but framework-specific */}
        </div>

        {/* Compliance Action Items */}
        <div className="mt-6 bg-gray-800/30 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
            <CheckSquare className="h-5 w-5 mr-2 text-green-400" />
            Compliance Action Plan
          </h3>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <h4 className="font-medium text-red-300 mb-2">Immediate (1-7 days)</h4>
              <ul className="text-sm text-gray-300 space-y-1">
                <li>• Address critical vulnerabilities</li>
                <li>• Review authentication mechanisms</li>
                <li>• Document security incidents</li>
              </ul>
            </div>
            
            <div>
              <h4 className="font-medium text-yellow-300 mb-2">Short-term (1-4 weeks)</h4>
              <ul className="text-sm text-gray-300 space-y-1">
                <li>• Implement input validation framework</li>
                <li>• Conduct security training</li>
                <li>• Update security policies</li>
              </ul>
            </div>
            
            <div>
              <h4 className="font-medium text-green-300 mb-2">Long-term (1-6 months)</h4>
              <ul className="text-sm text-gray-300 space-y-1">
                <li>• Regular compliance assessments</li>
                <li>• Security maturity improvement</li>
                <li>• Third-party security audits</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// Business Impact Assessment Component
const BusinessImpactSection: React.FC<{ 
  detailedFindings: VulnerabilityFinding[]
  summary: ExecutiveSummary
}> = ({ detailedFindings, summary }) => {
  const calculateBusinessMetrics = () => {
    const criticalCount = detailedFindings.filter(f => f.severity === 'critical').length
    const highCount = detailedFindings.filter(f => f.severity === 'high').length
    const totalRiskScore = calculateRiskScore(detailedFindings, summary)

    // Dynamic financial impact based on actual findings
    const baseImpact = {
      critical: 500000,
      high: 150000,
      medium: 50000,
      low: 10000
    }

    const estimatedCost = 
      criticalCount * baseImpact.critical +
      (summary.severity_counts?.high || 0) * baseImpact.high +
      (summary.severity_counts?.medium || 0) * baseImpact.medium +
      (summary.severity_counts?.low || 0) * baseImpact.low

    // Business risk assessment
    const businessRisk = totalRiskScore > 50 ? 'High' : totalRiskScore > 25 ? 'Medium' : 'Low'
    
    // Recovery time estimate
    const recoveryTime = criticalCount > 5 ? '2-4 weeks' : 
                        criticalCount > 0 ? '1-2 weeks' : 
                        highCount > 5 ? '3-7 days' : '1-3 days'

    return {
      estimatedCost,
      businessRisk,
      recoveryTime,
      customerImpact: criticalCount > 0 ? 'High' : highCount > 3 ? 'Medium' : 'Low',
      complianceRisk: criticalCount > 0 ? 'Critical' : 'Medium'
    }
  }

  const businessMetrics = calculateBusinessMetrics()

  const impactCategories = [
    {
      title: 'Financial Impact',
      icon: DollarSign,
      value: formatCurrency(businessMetrics.estimatedCost),
      description: 'Estimated total cost of security incidents',
      risk: businessMetrics.businessRisk,
      details: [
        'Incident response costs',
        'System recovery expenses', 
        'Regulatory fines potential',
        'Business disruption losses'
      ]
    },
    {
      title: 'Operational Impact',
      icon: Activity,
      value: businessMetrics.recoveryTime,
      description: 'Estimated recovery time from incidents',
      risk: businessMetrics.businessRisk,
      details: [
        'Service availability impact',
        'Resource allocation needs',
        'Recovery coordination effort',
        'Business continuity planning'
      ]
    },
    {
      title: 'Customer Impact',
      icon: Users,
      value: businessMetrics.customerImpact,
      description: 'Potential impact on customer trust',
      risk: businessMetrics.customerImpact,
      details: [
        'Customer data at risk',
        'Service reliability concerns',
        'Trust and reputation impact',
        'Customer retention risk'
      ]
    },
    {
      title: 'Compliance Risk',
      icon: Scale,
      value: businessMetrics.complianceRisk,
      description: 'Regulatory compliance exposure',
      risk: businessMetrics.complianceRisk,
      details: [
        'GDPR compliance risk',
        'PCI DSS violations',
        'SOX control failures',
        'Industry regulations'
      ]
    }
  ]

  return (
    <div className="card avoid-break">
      <div className="card-header">
        <h2 className="card-title flex items-center text-xl">
          <Briefcase className="h-6 w-6 mr-2 text-green-400" />
          Business Impact Assessment
        </h2>
        <p className="text-sm text-gray-400 mt-1">
          Comprehensive analysis of potential business consequences
        </p>
      </div>

      <div className="p-6 space-y-6">
        {/* Impact Overview Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {impactCategories.map((category, index) => {
            const IconComponent = category.icon
            const riskColor = category.risk === 'Critical' || category.risk === 'High' ? 'border-red-700 bg-red-900/10' :
                             category.risk === 'Medium' ? 'border-yellow-700 bg-yellow-900/10' :
                             'border-green-700 bg-green-900/10'
            
            return (
              <div key={index} className={`border rounded-lg p-4 ${riskColor}`}>
                <div className="flex items-center justify-between mb-3">
                  <IconComponent className="h-6 w-6 text-blue-400" />
                  <Badge 
                    variant={category.risk === 'Critical' ? 'critical' : 
                            category.risk === 'High' ? 'critical' :
                            category.risk === 'Medium' ? 'medium' : 'success'} 
                    size="sm"
                  >
                    {category.risk}
                  </Badge>
                </div>
                
                <h3 className="font-semibold text-white mb-1">{category.title}</h3>
                <div className="text-2xl font-bold text-white mb-2">{category.value}</div>
                <p className="text-xs text-gray-400 mb-3">{category.description}</p>
                
                <div className="space-y-1">
                  {category.details.map((detail, idx) => (
                    <div key={idx} className="text-xs text-gray-500 flex items-center">
                      <div className="w-1 h-1 bg-blue-400 rounded-full mr-2"></div>
                      {detail}
                    </div>
                  ))}
                </div>
              </div>
            )
          })}
        </div>

        {/* Additional impact analysis sections can be added here */}
      </div>
    </div>
  )
}

// Enhanced Depth Analysis Section
const DepthAnalysisSection: React.FC<{ depthAnalysis: DepthAnalysis }> = ({ depthAnalysis }) => {
  const [showAllFindings, setShowAllFindings] = useState(false)
  const [showAllActions, setShowAllActions] = useState(false)

  return (
    <div className="card border-2 border-purple-600 bg-gradient-to-br from-purple-900/20 to-indigo-900/20 avoid-break">
      <div className="card-header border-b border-purple-600/30">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="card-title flex items-center text-2xl">
              <Brain className="h-7 w-7 mr-3 text-purple-400" />
              AI-Synthesized Security Intelligence
            </h2>
            <p className="text-sm text-gray-400 mt-2 flex items-center">
              <Zap className="h-4 w-4 mr-1" />
              Synthesized by {depthAnalysis.synthesis_model} • {new Date(depthAnalysis.generated_at).toLocaleString()}
            </p>
          </div>
          <div className="flex items-center space-x-2">
            <Badge variant="critical" className="bg-purple-900/50 text-purple-300 no-print">
              Executive Analysis
            </Badge>
            <Badge variant="info" className="bg-indigo-900/50 text-indigo-300 no-print">
              AI Enhanced
            </Badge>
          </div>
        </div>
      </div>
      
      <div className="p-6 space-y-8">
        {/* Executive Insights */}
        <div className="bg-gray-800/30 backdrop-blur rounded-xl p-6 border border-gray-700">
          <h3 className="text-xl font-semibold text-white mb-4 flex items-center">
            <Target className="h-6 w-6 mr-2 text-blue-400" />
            Executive Security Insights
          </h3>
          <div className="prose prose-sm prose-invert max-w-none">
            {depthAnalysis.executive_insights.split('\n\n').map((paragraph, i: number) => (
              <p key={i} className="text-gray-300 leading-relaxed mb-4 text-base">
                {typeof paragraph === 'string' ? paragraph : String(paragraph)}
              </p>
            ))}
          </div>
        </div>

        {/* Critical Consensus Findings */}
        {depthAnalysis.critical_consensus_findings && depthAnalysis.critical_consensus_findings.length > 0 && (
          <div>
            <h3 className="text-xl font-semibold text-white mb-5 flex items-center">
              <AlertCircle className="h-6 w-6 mr-2 text-red-400" />
              Critical Consensus Findings
              <span className="ml-3 text-sm font-normal text-gray-400">
                ({depthAnalysis.critical_consensus_findings.length} issues with multi-model agreement)
              </span>
            </h3>
            <div className="grid gap-4">
              {depthAnalysis.critical_consensus_findings
                .slice(0, showAllFindings ? undefined : 5)
                .map((finding, i) => (
                <div key={i} className="bg-red-900/10 border border-red-800/50 rounded-lg p-5 hover:border-red-700 transition-all duration-200">
                  <div className="flex items-start justify-between mb-3">
                    <h4 className="font-medium text-white text-lg pr-4">{finding.issue}</h4>
                    <div className="flex items-center space-x-2 flex-shrink-0">
                      <Badge variant={finding.severity === 'critical' ? 'critical' : 'medium'}>
                        {finding.severity.toUpperCase()}
                      </Badge>
                      <span className="text-xs text-gray-400 bg-gray-800 px-3 py-1 rounded-full">
                        {Math.round(finding.confidence * 100)}% confidence
                      </span>
                    </div>
                  </div>
                  <p className="text-sm text-gray-300 mb-3 leading-relaxed">{finding.impact}</p>
                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center text-gray-400">
                      <Users className="h-4 w-4 mr-1" />
                      Identified by: <span className="ml-1 text-gray-300">{finding.models_agreed.join(', ')}</span>
                    </div>
                    <div className="flex items-center text-red-400">
                      <AlertTriangle className="h-4 w-4 mr-1" />
                      High Priority
                    </div>
                  </div>
                </div>
              ))}
            </div>
            {depthAnalysis.critical_consensus_findings.length > 5 && (
              <button
                onClick={() => setShowAllFindings(!showAllFindings)}
                className="mt-4 text-sm text-purple-400 hover:text-purple-300 flex items-center no-print"
              >
                {showAllFindings ? (
                  <>
                    <EyeOff className="h-4 w-4 mr-1" />
                    Show Less
                  </>
                ) : (
                  <>
                    <Eye className="h-4 w-4 mr-1" />
                    Show All {depthAnalysis.critical_consensus_findings.length} Findings
                  </>
                )}
              </button>
            )}
          </div>
        )}

        {/* Risk Matrix Visualization */}
        {depthAnalysis.risk_matrix && Object.keys(depthAnalysis.risk_matrix).length > 0 && (
          <div className="bg-gray-800/30 backdrop-blur rounded-xl p-6 border border-gray-700">
            <h3 className="text-xl font-semibold text-white mb-5 flex items-center">
              <BarChart3 className="h-6 w-6 mr-2 text-yellow-400" />
              Risk-Effort Matrix
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-green-900/20 border border-green-700 rounded-lg p-4">
                <h4 className="font-medium text-green-300 mb-2 flex items-center">
                  <Zap className="h-4 w-4 mr-1" />
                  Quick Wins (High Impact, Low Effort)
                </h4>
                <ul className="text-sm text-gray-300 space-y-1">
                  {(depthAnalysis.risk_matrix.high_impact_low_effort || []).slice(0, 3).map((item, i) => (
                    <li key={i} className="flex items-start">
                      <span className="text-green-400 mr-2 print:text-black">→</span>
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
              <div className="bg-orange-900/20 border border-orange-700 rounded-lg p-4">
                <h4 className="font-medium text-orange-300 mb-2 flex items-center">
                  <Target className="h-4 w-4 mr-1" />
                  Major Projects (High Impact, High Effort)
                </h4>
                <ul className="text-sm text-gray-300 space-y-1">
                  {(depthAnalysis.risk_matrix.high_impact_high_effort || []).slice(0, 3).map((item, i) => (
                    <li key={i} className="flex items-start">
                      <span className="text-orange-400 mr-2 print:text-black">→</span>
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        )}

        {/* Prioritized Action Items */}
        {depthAnalysis.prioritized_action_items && depthAnalysis.prioritized_action_items.length > 0 && (
          <div>
            <h3 className="text-xl font-semibold text-white mb-5 flex items-center">
              <CheckCircle className="h-6 w-6 mr-2 text-green-400" />
              Prioritized Action Plan
            </h3>
            <div className="space-y-3">
              {depthAnalysis.prioritized_action_items
                .slice(0, showAllActions ? undefined : 7)
                .map((item, i) => (
                <div key={i} className="flex items-center justify-between p-4 bg-gray-800/50 rounded-lg hover:bg-gray-800/70 transition-all duration-200 border border-gray-700">
                  <div className="flex items-start space-x-4">
                    <span className="text-2xl font-bold text-yellow-400 w-8 print:text-black">
                      {item.priority}
                    </span>
                    <div className="flex-1">
                      <p className="text-base font-medium text-white mb-1">{item.action}</p>
                      <p className="text-sm text-gray-400">{item.category}</p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2 ml-4 no-print">
                    <span className={`text-xs px-3 py-1 rounded-full font-medium ${
                      item.impact === 'high' ? 'bg-red-900/30 text-red-300' :
                      item.impact === 'medium' ? 'bg-yellow-900/30 text-yellow-300' :
                      'bg-blue-900/30 text-blue-300'
                    }`}>
                      Impact: {item.impact}
                    </span>
                    <span className={`text-xs px-3 py-1 rounded-full font-medium ${
                      item.effort === 'low' ? 'bg-green-900/30 text-green-300' :
                      item.effort === 'medium' ? 'bg-yellow-900/30 text-yellow-300' :
                      'bg-orange-900/30 text-orange-300'
                    }`}>
                      Effort: {item.effort}
                    </span>
                  </div>
                </div>
              ))}
            </div>
            {depthAnalysis.prioritized_action_items.length > 7 && (
              <button
                onClick={() => setShowAllActions(!showAllActions)}
                className="mt-4 text-sm text-purple-400 hover:text-purple-300 flex items-center no-print"
              >
                {showAllActions ? (
                  <>
                    <EyeOff className="h-4 w-4 mr-1" />
                    Show Less
                  </>
                ) : (
                  <>
                    <Eye className="h-4 w-4 mr-1" />
                    Show All {depthAnalysis.prioritized_action_items.length} Actions
                  </>
                )}
              </button>
            )}
          </div>
        )}

        {/* Two Column Layout for Remaining Sections */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Architectural Risks */}
          {depthAnalysis.architectural_risks && depthAnalysis.architectural_risks.length > 0 && (
            <div className="bg-orange-900/10 border border-orange-700 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                <GitBranch className="h-5 w-5 mr-2 text-orange-400" />
                Architectural Security Risks
              </h3>
              <ul className="space-y-3">
                {depthAnalysis.architectural_risks.map((risk, i) => (
                  <li key={i} className="flex items-start space-x-2 text-sm">
                    <AlertTriangle className="h-4 w-4 text-orange-400 mt-0.5 flex-shrink-0" />
                    <span className="text-gray-300">{risk}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Security Debt Assessment */}
          {depthAnalysis.security_debt_assessment && (
            <div className="bg-yellow-900/10 border border-yellow-700 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                <Database className="h-5 w-5 mr-2 text-yellow-400" />
                Security Debt Assessment
              </h3>
              <p className="text-sm text-gray-300 leading-relaxed">
                {depthAnalysis.security_debt_assessment}
              </p>
            </div>
          )}
        </div>

        {/* Confidence Analysis */}
        {depthAnalysis.confidence_analysis && (
          <div className="bg-blue-900/10 border border-blue-700 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
              <Activity className="h-5 w-5 mr-2 text-blue-400" />
              Analysis Confidence & Methodology
            </h3>
            <p className="text-sm text-gray-300 leading-relaxed">
              {depthAnalysis.confidence_analysis}
            </p>
          </div>
        )}
        
        {/* Unique Insights by Model */}
        {depthAnalysis.unique_insights_by_model && Object.keys(depthAnalysis.unique_insights_by_model).length > 0 && (
          <ExpandableSection
            title="Unique Model Insights"
            icon={<Users className="h-5 w-5 text-purple-400" />}
            defaultExpanded={false}
          >
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {Object.entries(depthAnalysis.unique_insights_by_model).map(([model, insights]: [string, string[]]) => (
                <div key={model} className="bg-gray-800/50 rounded-lg p-4">
                  <h4 className="font-medium text-white mb-2 flex items-center">
                    <div className="h-2 w-2 rounded-full bg-green-400 mr-2 print:bg-black"></div>
                    {model}
                  </h4>
                  <ul className="text-sm text-gray-300 space-y-1">
                    {insights.slice(0, 3).map((insight, i) => (
                      <li key={i} className="flex items-start">
                        <span className="text-purple-400 mr-1 print:text-black">•</span>
                        <span className="text-xs">{insight}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </ExpandableSection>
        )}
      </div>
    </div>
  )
}

// Main Report Page Component
export default function ReportPage({ jobId: propJobId, reportData: propReportData }: { jobId?: string, reportData?: AnalysisReport }) {
  const { jobId: paramJobId } = useParams<{ jobId: string }>()
  const effectiveJobId = propJobId || paramJobId
  const navigate = useNavigate();
  const [isExporting, setIsExporting] = useState(false)
  const [showDetailedFindings, setShowDetailedFindings] = useState(true)
  const [filterSeverity, setFilterSeverity] = useState<string>('all')
  const [searchTerm, setSearchTerm] = useState('')
  const [activeTab, setActiveTab] = useState<'overview' | 'technical' | 'compliance'>('overview')
  const reportRef = useRef<HTMLDivElement>(null)

  const { data: queryResponse, isLoading, error: queryError } = useQuery({
    queryKey: ['report', effectiveJobId],
    queryFn: async () => {
      const response = await scanAPI.getReport(effectiveJobId!);
      return response;
    },
    enabled: !!effectiveJobId && !propReportData,
    retry: 3,
    refetchInterval: (data: any) => {
      if (data && typeof data === 'object' && 'status' in data && data.status === 'in_progress') {
        return 3000;
      }
      return false;
    },
  });

  useEffect(() => {
    const styleElement = document.createElement('style')
    styleElement.innerHTML = printStyles
    document.head.appendChild(styleElement)
    return () => {
      document.head.removeChild(styleElement)
    }
  }, [])
  
  useEffect(() => {
    if (!effectiveJobId) {
      console.log('No job ID provided, redirecting to jobs list');
      navigate('/jobs');
    }
  }, [effectiveJobId, navigate]);

  const isAnalysisReport = (data: any): data is AnalysisReport => {
    return data && 
      typeof data === 'object' && 
      'job_id' in data && 
      'executive_summary' in data &&
      'detailed_findings' in data;
  };

  const isJobProgressResponse = (data: any): data is JobProgressResponse => {
    return data && 
      typeof data === 'object' && 
      'status' in data;
  };

  const handleExportPDF = async () => {
    if (!reportRef.current) return;
    setIsExporting(true);
    try {
      // Enhanced PDF export with better formatting
      const originalTitle = document.title;
      document.title = `Security Analysis Report - ${effectiveJobId}`;
      
      // Add print-specific styles
      const printClass = 'printing-report';
      document.body.classList.add(printClass);
      
      window.print();
      
      // Cleanup
      setTimeout(() => {
        document.body.classList.remove(printClass);
        document.title = originalTitle;
      }, 1000);
      
      console.log('PDF export initiated via browser print');
    } catch (err) {
      console.error('PDF export failed:', err);
    } finally {
      setIsExporting(false);
    }
  };
  
  const isInProgress = queryResponse && isJobProgressResponse(queryResponse) && queryResponse.status === 'in_progress';
  
  if (isInProgress) {
    const progressData = queryResponse as JobProgressResponse;
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-900">
        <div className="text-center max-w-md p-8 bg-gray-800 rounded-xl">
          <Loader2 className="h-12 w-12 text-blue-400 animate-spin mx-auto mb-4" />
          <h3 className="text-xl font-medium text-white mb-4">Analysis In Progress</h3>
          
          {progressData.progress !== undefined && (
            <div className="mb-4">
              <div className="w-full bg-gray-700 rounded-full h-2 mb-2">
                <div 
                  className="h-2 rounded-full transition-all duration-300 bg-blue-500"
                  style={{ width: `${progressData.progress * 100}%` }}
                />
              </div>
              <p className="text-sm text-gray-400">
                {progressData.files_scanned || 0} of {progressData.files_total || '?'} files analyzed
              </p>
              <p className="text-sm text-gray-400 mt-1">
                Current stage: {progressData.current_stage || 'initializing'}
              </p>
            </div>
          )}
          
          <p className="text-gray-400">Your security analysis is still running.</p>
          <p className="text-sm text-gray-500 mt-1">Job ID: {effectiveJobId}</p>
          
          <Link to="/jobs" className="mt-6 block w-full py-2 px-4 bg-blue-600 hover:bg-blue-700 rounded-lg text-white">
            <ArrowLeft className="h-4 w-4 mr-2 inline" />
            Back to Jobs
          </Link>
        </div>
      </div>
    );
  }

  if (isLoading && !propReportData) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-900">
        <div className="text-center">
          <div className="animate-spin rounded-full border-2 border-gray-300 border-t-blue-600 h-12 w-12 mx-auto mb-4" />
          <p className="text-gray-400">Generating comprehensive security report...</p>
          <p className="mt-2 text-sm text-gray-500">Job ID: {effectiveJobId}</p>
        </div>
      </div>
    )
  }

  let finalReportData: AnalysisReport | null = null;

  if (propReportData) {
    finalReportData = propReportData;
  } else if (queryResponse) {
    if (isAnalysisReport(queryResponse)) {
      finalReportData = queryResponse;
    } 
    else if (isJobProgressResponse(queryResponse) && queryResponse.data) {
      if (isAnalysisReport(queryResponse.data)) {
        finalReportData = queryResponse.data;
      }
    }
  }

  if (queryError) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-900">
        <div className="text-center max-w-md">
          <AlertTriangle className="mx-auto h-16 w-16 text-red-400 mb-4" />
          <h3 className="text-xl font-medium text-white mb-2">Error Loading Report</h3>
          <p className="text-gray-400 mb-6">
            {queryError.message || "An unknown error occurred while loading the report."}
          </p>
          <p className="text-xs text-gray-500 font-mono mb-6">Job ID: {effectiveJobId}</p>
          <Link to="/jobs" className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white">
            <ArrowLeft className="h-4 w-4 mr-2 inline" />
            Back to Jobs
          </Link>
        </div>
      </div>
    );
  }

  if (!finalReportData && !isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-900">
        <div className="text-center max-w-md">
          <AlertTriangle className="mx-auto h-16 w-16 text-red-400 mb-4" />
          <h3 className="text-xl font-medium text-white mb-2">Report Not Available</h3>
          <p className="text-gray-400 mb-6">
            Unable to load the security analysis report. The job may have failed or the report is not yet ready.
          </p>
          <Link to="/jobs" className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white">
            <ArrowLeft className="h-4 w-4 mr-2 inline" />
            Back to Jobs
          </Link>
        </div>
      </div>
    );
  }
  
  if (!finalReportData) { 
      return <div>Error: Report data is unexpectedly null.</div>;
  }

  // Filter findings
  const filteredFindings = finalReportData.detailed_findings?.filter((finding: VulnerabilityFinding) => {
    const matchesSeverity = filterSeverity === 'all' || finding.severity === filterSeverity
    const matchesSearch = !searchTerm || 
      finding.file.toLowerCase().includes(searchTerm.toLowerCase()) ||
      finding.category.toLowerCase().includes(searchTerm.toLowerCase()) ||
      finding.explanation.toLowerCase().includes(searchTerm.toLowerCase())
    return matchesSeverity && matchesSearch
  }) || []

  const summary = finalReportData.executive_summary || {}
  const depthAnalysis = finalReportData.depth_analysis

  return (
    <div className="min-h-screen bg-gray-900 print:bg-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8" ref={reportRef}>
        {/* Enhanced Header */}
        <div className="flex items-center justify-between mb-8 no-print">
          <div className="flex-1">
            <div className="flex items-center space-x-3 mb-2">
              <button 
                onClick={() => window.history.back()}
                className="text-gray-400 hover:text-white transition-colors p-2 hover:bg-gray-800 rounded-lg"
              >
                <ArrowLeft className="h-5 w-5" />
              </button>
              <h1 className="text-3xl font-bold text-white">Professional Security Analysis Report</h1>
              <Badge variant="success">AI-Enhanced</Badge>
            </div>
            <div className="flex items-center space-x-4 text-sm text-gray-400">
              <div className="flex items-center">
                <FileText className="h-4 w-4 mr-1" />
                Job ID: {effectiveJobId}
              </div>
              <div className="flex items-center">
                <Calendar className="h-4 w-4 mr-1" />
                Generated {new Date(finalReportData.generated_at || Date.now()).toLocaleString()}
              </div>
              <div className="flex items-center">
                <Clock className="h-4 w-4 mr-1" />
                Processing: {formatDuration(summary.processing_time || 0)}
              </div>
            </div>
          </div>
          
          <div className="flex items-center space-x-3">
            {/* Tab Navigation */}
            <div className="flex items-center space-x-1 bg-gray-800 rounded-lg p-1">
              <button 
                onClick={() => setActiveTab('overview')}
                className={`px-3 py-1 rounded text-sm font-medium transition-colors ${
                  activeTab === 'overview' 
                    ? 'bg-blue-600 text-white' 
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                Overview
              </button>
              <button 
                onClick={() => setActiveTab('technical')}
                className={`px-3 py-1 rounded text-sm font-medium transition-colors ${
                  activeTab === 'technical' 
                    ? 'bg-blue-600 text-white' 
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                Technical
              </button>
              <button 
                onClick={() => setActiveTab('compliance')}
                className={`px-3 py-1 rounded text-sm font-medium transition-colors ${
                  activeTab === 'compliance' 
                    ? 'bg-blue-600 text-white' 
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                Compliance
              </button>
            </div>
            
            <button 
              className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-white transition-colors flex items-center"
              onClick={handleExportPDF}
              disabled={isExporting}
            >
              <Download className={`h-4 w-4 mr-2 ${isExporting ? 'animate-spin' : ''}`} />
              {isExporting ? 'Exporting...' : 'Export PDF'}
            </button>
            <button 
              className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-white transition-colors flex items-center"
              onClick={() => window.print()}
            >
              <Printer className="h-4 w-4 mr-2" />
              Print
            </button>
          </div>
        </div>
        
        {/* Print Header */}
        <div className="hidden print:block mb-8 text-center border-b pb-4">
          <h1 className="text-3xl font-bold">Professional Security Analysis Report</h1>
          <div className="mt-2 space-y-1">
            <p className="text-sm">Job ID: {effectiveJobId}</p>
            <p className="text-sm">Generated: {new Date(finalReportData.generated_at || Date.now()).toLocaleString()}</p>
            <p className="text-sm">Models Used: {summary.models_used?.join(', ') || 'Multiple AI Models'}</p>
          </div>
          {/* AI Disclaimer */}
          <div className="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded">
            <p className="text-xs text-yellow-800 font-medium">
              ⚠️ AI-GENERATED REPORT DISCLAIMER: This report was generated using AI analysis tools and is intended for informational purposes only. 
              Results may contain false positives or miss certain vulnerabilities. This report is not legally binding and should not be considered 
              as professional security advice. Always validate findings with manual security assessment and consult security professionals for 
              critical systems.
            </p>
          </div>
        </div>

        {/* AI Disclaimer for screen */}
        <div className="mb-6 p-4 bg-yellow-900/20 border border-yellow-700 rounded-lg no-print">
          <div className="flex items-start space-x-3">
            <AlertTriangle className="h-5 w-5 text-yellow-400 mt-0.5 flex-shrink-0" />
            <div>
              <h3 className="text-sm font-medium text-yellow-300 mb-1">AI-Generated Report Disclaimer</h3>
              <p className="text-xs text-yellow-200/80 leading-relaxed">
                This report was generated using AI analysis tools and is intended for informational purposes only. 
                Results may contain false positives or miss certain vulnerabilities. This report is not legally binding 
                and should not be considered as professional security advice. Always validate findings with manual 
                security assessment and consult security professionals for critical systems.
              </p>
            </div>
          </div>
        </div>

        {/* Security Metrics Dashboard */}
        <SecurityMetricsDashboard 
          summary={summary} 
          detailedFindings={finalReportData.detailed_findings} 
        />
        
        {/* Depth Analysis - Top Priority */}
        {depthAnalysis && (
          <div className="mt-8">
            <DepthAnalysisSection depthAnalysis={depthAnalysis} />
          </div>
        )}

        {/* Business Impact Assessment */}
        {activeTab === 'overview' && (
          <div className="mt-8">
            <BusinessImpactSection 
              detailedFindings={finalReportData.detailed_findings}
              summary={summary}
            />
          </div>
        )}

        {/* Compliance & Regulatory Assessment */}
        {activeTab === 'compliance' && (
          <div className="mt-8">
            <ComplianceSection 
              detailedFindings={finalReportData.detailed_findings}
            />
          </div>
        )}

        {/* Detailed Findings Section */}
        <div className="card avoid-break mt-8">
          <div className="card-header">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="card-title flex items-center text-xl">
                  <FileCode className="h-6 w-6 mr-2 text-orange-400" />
                  Detailed Vulnerability Findings
                </h2>
                <p className="mt-1 text-gray-400">
                  Comprehensive analysis of security issues with remediation guidance
                </p>
              </div>
              <button
                onClick={() => setShowDetailedFindings(!showDetailedFindings)}
                className="btn btn-ghost btn-sm no-print"
              >
                {showDetailedFindings ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                {showDetailedFindings ? 'Hide' : 'Show'}
              </button>
            </div>
          </div>

          {/* For print, always show detailed findings */}
          <div className="print:block">
            {showDetailedFindings && (
              <div className="p-6">
                {/* Enhanced Filters */}
                <div className="flex flex-col sm:flex-row gap-4 mb-6 no-print">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-2.5 h-4 w-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search findings..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                    />
                  </div>
                  <div className="flex space-x-2">
                    <select
                      value={filterSeverity}
                      onChange={(e) => setFilterSeverity(e.target.value)}
                      className="px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                    >
                      <option value="all">All Severities</option>
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                      <option value="info">Info</option>
                    </select>
                  </div>
                </div>

                {/* Findings List */}
                {filteredFindings.length > 0 ? (
                  <div className="space-y-4">
                    {filteredFindings.map((finding: VulnerabilityFinding, index: number) => (
                      <div 
                        key={index} 
                        className={`border border-gray-700 rounded-lg p-6 hover:border-gray-600 transition-all duration-200 avoid-break ${getRiskLevelColor(finding.severity)}`}
                      >
                        <div className="flex items-start justify-between mb-4">
                          <div className="flex-1">
                            <div className="flex items-center space-x-3 mb-2">
                              <AlertTriangle className={`h-5 w-5 ${getSeverityColor(finding.severity)}`} />
                              <h3 className="text-lg font-medium text-white">
                                {finding.category.replace(/_/g, ' ').replace(/\b\w/g, (l: string) => l.toUpperCase())}
                              </h3>
                            </div>
                            <p className="text-sm text-gray-400 flex items-center">
                              <FileText className="h-4 w-4 mr-1" />
                              {finding.file}:{finding.line}
                            </p>
                          </div>
                          <div className="flex items-center space-x-2 ml-4">
                            <Badge 
                              variant={
                                finding.severity === 'critical' ? 'critical' : 
                                finding.severity === 'high' ? 'high' : 
                                finding.severity === 'medium' ? 'medium' : 
                                finding.severity === 'low' ? 'low' : 
                                'info'
                              }
                            >
                              {finding.severity.toUpperCase()}
                            </Badge>
                            <span className={`text-xs bg-gray-800 px-3 py-1 rounded-full no-print ${getConfidenceColor(finding.confidence)}`}>
                              {Math.round(finding.confidence * 100)}% confidence
                            </span>
                          </div>
                        </div>

                        <div className="space-y-4">
                          <div>
                            <h4 className="text-sm font-medium text-white mb-2 flex items-center">
                              <Info className="h-4 w-4 mr-1 text-blue-400" />
                              Description
                            </h4>
                            <p className="text-sm text-gray-300 leading-relaxed">{finding.explanation}</p>
                          </div>

                          {finding.code_snippet && (
                            <div>
                              <h4 className="text-sm font-medium text-white mb-2 flex items-center">
                                <Code className="h-4 w-4 mr-1 text-purple-400" />
                                Code Snippet
                              </h4>
                              <div className="bg-gray-900 border border-gray-700 rounded-lg p-4 overflow-x-auto">
                                <pre className="text-sm text-gray-300 font-mono">
                                  <code>{finding.code_snippet}</code>
                                </pre>
                              </div>
                            </div>
                          )}

                          {finding.patch && (
                            <div>
                              <h4 className="text-sm font-medium text-white mb-2 flex items-center">
                                <Zap className="h-4 w-4 mr-1 text-green-400" />
                                Recommended Fix
                              </h4>
                              <div className="bg-green-900/10 border border-green-700 rounded-lg p-4">
                                <p className="text-sm text-green-100">{finding.patch}</p>
                              </div>
                            </div>
                          )}

                          <div className="flex items-center justify-between pt-4 border-t border-gray-700">
                            <div className="text-xs text-gray-400 flex items-center">
                              <Users className="h-4 w-4 mr-1" />
                              Found by: {Array.isArray(finding.found_by) ? finding.found_by.join(', ') : finding.found_by || 'Unknown'}
                            </div>
                            {finding.references && finding.references.length > 0 && (
                              <div className="flex items-center space-x-3">
                                {finding.references.slice(0, 2).map((ref: string, refIndex: number) => (
                                  <a
                                    key={refIndex}
                                    href={ref}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-xs text-blue-400 hover:text-blue-300 flex items-center transition-colors no-print"
                                  >
                                    Reference <ExternalLink className="h-3 w-3 ml-1" />
                                  </a>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-12">
                    <CheckCircle className="mx-auto h-16 w-16 text-green-400 mb-4" />
                    <h3 className="text-xl font-medium text-white mb-2">No Findings Found</h3>
                    <p className="text-gray-400">
                      No security vulnerabilities match your current filter criteria.
                    </p>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="text-center py-8 border-t border-gray-700 mt-8">
          <p className="text-sm text-gray-400">
            Generated by SecureFlow AI Security Analysis Platform
          </p>
          <p className="text-xs text-gray-500 mt-2">
            This report is confidential and should be handled according to your organization's security policies
          </p>
          <div className="mt-4 p-3 bg-amber-900/20 border border-amber-700 rounded-lg mx-auto max-w-2xl">
            <p className="text-xs text-amber-200 leading-relaxed">
              <strong>Important:</strong> This AI-generated security analysis is provided for informational purposes only. 
              While our advanced AI models strive for accuracy, this report may contain false positives, miss certain 
              vulnerabilities, or provide incomplete analysis. Always validate critical findings through manual review 
              and professional security assessment. This report does not constitute professional security advice and 
              should not be the sole basis for security decisions.
            </p>
          </div>
          <div className="mt-6 no-print">
            <button 
              onClick={() => window.history.back()}
              className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-white transition-colors flex items-center mx-auto"
            >
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to Analysis Jobs
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}