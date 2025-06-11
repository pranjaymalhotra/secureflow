"""
SecureFlow Database Management

Handles database initialization, connections, and basic operations.
"""

import os
import logging
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger(__name__)

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./secureflow.db")

# Create engine
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        echo=os.getenv("DEBUG", "false").lower() == "true"
    )
else:
    engine = create_engine(
        DATABASE_URL,
        echo=os.getenv("DEBUG", "false").lower() == "true"
    )

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@contextmanager
def get_database_session() -> Generator[Session, None, None]:
    """Get database session with automatic cleanup."""
    session = SessionLocal()
    try:
        yield session
    except SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Database error: {e}")
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Unexpected error: {e}")
        raise
    finally:
        session.close()

def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for database sessions."""
    with get_database_session() as session:
        yield session

def init_db() -> None:
    """Initialize database tables and default data."""
    try:
        # Import here to avoid circular imports
        from ..gateway.models import Base, User
        from ..gateway.auth import init_default_user
        
        # Create all tables
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
        
        # Initialize default user
        with get_database_session() as db:
            init_default_user(db)
            
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise

class DatabaseManager:
    """Database operations manager."""
    
    def __init__(self):
        self.engine = engine
        self.SessionLocal = SessionLocal
    
    def create_job_record(self, job_data: dict) -> str:
        """Create a new job record in database."""
        try:
            with get_database_session() as db:
                from ..gateway.models import Job
                
                job = Job(**job_data)
                db.add(job)
                db.commit()
                db.refresh(job)
                return job.id
                
        except Exception as e:
            logger.error(f"Failed to create job record: {e}")
            raise
    
    def update_job_progress(self, job_id: str, progress_data: dict) -> bool:
        """Update job progress in database."""
        try:
            with get_database_session() as db:
                from ..gateway.models import Job
                
                job = db.query(Job).filter(Job.id == job_id).first()
                if not job:
                    return False
                
                for key, value in progress_data.items():
                    setattr(job, key, value)
                
                db.commit()
                return True
                
        except Exception as e:
            logger.error(f"Failed to update job progress: {e}")
            return False
    
    def get_job_by_id(self, job_id: str, user_id: int = None) -> dict:
        """Get job by ID with optional user filtering."""
        try:
            with get_database_session() as db:
                from ..gateway.models import Job
                
                query = db.query(Job).filter(Job.id == job_id)
                if user_id:
                    query = query.filter(Job.user_id == user_id)
                
                job = query.first()
                if not job:
                    return None
                
                return {
                    "id": job.id,
                    "user_id": job.user_id,
                    "source_type": job.source_type,
                    "source_url": job.source_url,
                    "status": job.status,
                    "progress": job.progress,
                    "files_total": job.files_total,
                    "files_scanned": job.files_scanned,
                    "current_stage": job.current_stage,
                    "active_models": job.active_models,
                    "eta_seconds": job.eta_seconds,
                    "error_message": job.error_message,
                    "created_at": job.created_at,
                    "updated_at": job.updated_at,
                    "completed_at": job.completed_at
                }
                
        except Exception as e:
            logger.error(f"Failed to get job: {e}")
            return None
    
    def list_user_jobs(self, user_id: int, limit: int = 50, offset: int = 0) -> list:
        """List jobs for a specific user."""
        try:
            with get_database_session() as db:
                from ..gateway.models import Job
                
                jobs = db.query(Job)\
                    .filter(Job.user_id == user_id)\
                    .order_by(Job.created_at.desc())\
                    .offset(offset)\
                    .limit(limit)\
                    .all()
                
                return [
                    {
                        "id": job.id,
                        "source_type": job.source_type,
                        "source_url": job.source_url,
                        "status": job.status,
                        "progress": job.progress,
                        "files_total": job.files_total,
                        "files_scanned": job.files_scanned,
                        "created_at": job.created_at,
                        "completed_at": job.completed_at
                    }
                    for job in jobs
                ]
                
        except Exception as e:
            logger.error(f"Failed to list user jobs: {e}")
            return []
    
    def delete_job(self, job_id: str, user_id: int) -> bool:
        """Delete a job record."""
        try:
            with get_database_session() as db:
                from ..gateway.models import Job
                
                job = db.query(Job)\
                    .filter(Job.id == job_id, Job.user_id == user_id)\
                    .first()
                
                if not job:
                    return False
                
                db.delete(job)
                db.commit()
                return True
                
        except Exception as e:
            logger.error(f"Failed to delete job: {e}")
            return False
    
    def get_system_stats(self) -> dict:
        """Get system statistics."""
        try:
            with get_database_session() as db:
                from ..gateway.models import Job, User
                from sqlalchemy import func
                from datetime import datetime, timedelta
                
                today = datetime.utcnow().date()
                
                stats = {
                    "total_jobs": db.query(Job).count(),
                    "active_jobs": db.query(Job).filter(Job.status.in_(["queued", "running"])).count(),
                    "completed_today": db.query(Job).filter(
                        Job.status == "completed",
                        func.date(Job.completed_at) == today
                    ).count(),
                    "failed_jobs": db.query(Job).filter(Job.status == "failed").count(),
                    "total_users": db.query(User).count()
                }
                
                return stats
                
        except Exception as e:
            logger.error(f"Failed to get system stats: {e}")
            return {}

# Global database manager instance
db_manager = DatabaseManager()