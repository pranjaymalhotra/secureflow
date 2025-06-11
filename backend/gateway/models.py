"""
SecureFlow Pydantic Models

Data models for API requests and responses.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum

from pydantic import BaseModel, Field, validator
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func

Base = declarative_base()

# SQLAlchemy Models
class User(Base):
    """User model for database."""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True)
    hashed_password = Column(String(100), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class Job(Base):
    """Analysis job model for database."""
    __tablename__ = "jobs"
    
    id = Column(String(36), primary_key=True, index=True)  # UUID
    user_id = Column(Integer, nullable=False)
    source_type = Column(String(20), nullable=False)  # 'upload' or 'github'
    source_url = Column(String(500))  # GitHub URL if applicable
    status = Column(String(20), default="queued")  # queued, running, completed, failed, cancelled
    progress = Column(Float, default=0.0)
    files_total = Column(Integer, default=0)
    files_scanned = Column(Integer, default=0)
    current_stage = Column(String(50), default="initializing")
    active_models = Column(Text)  # JSON string of active model names
    eta_seconds = Column(Integer)
    error_message = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    completed_at = Column(DateTime(timezone=True))

# Pydantic Models
class JobStatus(str, Enum):
    """Job status enumeration."""
    QUEUED = "queued"
    RUNNING = "running"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class SeverityLevel(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class LoginRequest(BaseModel):
    """Login request model."""
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)

class LoginResponse(BaseModel):
    """Login response model."""
    access_token: str
    token_type: str = "bearer"
    user_id: int
    username: str

class ScanRequest(BaseModel):
    """Scan request model."""
    github_url: Optional[str] = None
    
    @validator('github_url')
    def validate_github_url(cls, v):
        if v and not v.startswith('https://github.com/'):
            raise ValueError('Invalid GitHub URL')
        return v

class ScanResponse(BaseModel):
    """Scan response model."""
    job_id: str
    status: JobStatus
    message: str

class ProgressUpdate(BaseModel):
    """Real-time progress update model."""
    job_id: str
    stage: str
    files_scanned: int
    total_files: int
    active_models: List[str]
    eta_seconds: Optional[int] = None
    status: JobStatus
    progress_percentage: float = Field(..., ge=0, le=100)
    current_file: Optional[str] = None
    
    class Config:
        use_enum_values = True

class VulnerabilityFinding(BaseModel):
    """Individual vulnerability finding."""
    worker: str
    file: str
    line: int
    category: str
    severity: SeverityLevel
    confidence: float = Field(..., ge=0, le=1)
    explanation: str
    patch: Optional[str] = None
    code_snippet: Optional[str] = None
    references: List[str] = []

class ExecutiveSummary(BaseModel):
    """Executive summary of findings."""
    total_files_analyzed: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    analysis_duration_seconds: int
    models_used: List[str]

class DetailedFinding(BaseModel):
    """Detailed vulnerability finding after merge."""
    file: str
    line: int
    category: str
    severity: SeverityLevel
    confidence: float
    explanation: str
    patch: Optional[str] = None
    code_snippet: Optional[str] = None
    references: List[str] = []
    found_by: List[str]  # List of models that found this

class AnalysisReport(BaseModel):
    """Complete analysis report."""
    job_id: str
    executive_summary: ExecutiveSummary
    detailed_findings: List[DetailedFinding]
    metadata: Dict[str, Any]
    generated_at: datetime
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class JobListItem(BaseModel):
    """Job list item for listing user jobs."""
    id: str
    source_type: str
    source_url: Optional[str]
    status: JobStatus
    progress: float
    files_total: int
    files_scanned: int
    created_at: datetime
    completed_at: Optional[datetime]
    
    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class WorkerResult(BaseModel):
    """Worker analysis result."""
    worker: str
    findings: List[VulnerabilityFinding]
    metadata: Dict[str, Any]
    processing_time_seconds: float

class ModelConfig(BaseModel):
    """LLM model configuration."""
    name: str
    type: str  # 'ollama', 'gemini', 'openai'
    weight: float
    enabled: bool
    description: str
    specializations: List[str]
    api_key_env: Optional[str] = None

class SystemStatus(BaseModel):
    """System status information."""
    status: str
    active_jobs: int
    queued_jobs: int
    completed_jobs_today: int
    available_models: List[str]
    system_load: Dict[str, Any]

class ErrorResponse(BaseModel):
    """Error response model."""
    detail: str
    error_code: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class FileAnalysisSummary(BaseModel):
    """Per-file analysis summary from a model."""
    file: str
    model: str
    risk_score: float = Field(..., ge=0, le=10)
    summary: str
    key_issues: List[str]
    code_quality_observations: str
    security_posture: str
    recommendations: List[str]

class ModelOverallAnalysis(BaseModel):
    """Overall analysis from a single model."""
    model: str
    architecture_observations: str
    security_patterns: Dict[str, str]  # pattern -> observation
    code_flow_analysis: str
    systemic_issues: List[str]
    strengths: List[str]
    risk_areas: List[str]
    recommendations: List[str]

class DepthAnalysis(BaseModel):
    """Main LLM synthesis of all model analyses."""
    synthesis_model: str
    executive_insights: str
    critical_consensus_findings: List[Dict[str, Any]]  # Issues agreed by multiple models
    unique_insights_by_model: Dict[str, List[str]]  # Model -> unique findings
    architectural_risks: List[str]
    security_debt_assessment: str
    prioritized_action_items: List[Dict[str, Any]]  # With priority scores
    risk_matrix: Dict[str, Any]
    confidence_analysis: str
    generated_at: datetime

class EnhancedAnalysisReport(BaseModel):
    """Enhanced analysis report with depth analysis."""
    job_id: str
    depth_analysis: DepthAnalysis
    model_overall_analyses: Dict[str, ModelOverallAnalysis]
    file_summaries_by_model: Dict[str, List[FileAnalysisSummary]]
    executive_summary: ExecutiveSummary
    detailed_findings: List[DetailedFinding]
    metadata: Dict[str, Any]
    generated_at: datetime