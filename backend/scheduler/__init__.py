"""
SecureFlow Scheduler Package

Contains job scheduling, file processing, and database management functionality.
"""
from .job_manager import JobManager
from .database import get_database_session, init_db, db_manager
from .file_processor import FileProcessor
import os
import asyncio
import logging
from pathlib import Path
from typing import Dict
from concurrent.futures import ThreadPoolExecutor

from .job_manager import JobManager
from .database import get_database_session, init_db, db_manager
from .file_processor import FileProcessor
logger = logging.getLogger(__name__)

__all__ = ['JobManager', 'get_database_session', 'init_db', 'db_manager', 'FileProcessor']

def __init__(self):
    self.active_jobs: Dict[str, Dict] = {}
    self.file_processor = FileProcessor()
    self.max_workers = int(os.getenv("MAX_CONCURRENT_WORKERS", "4"))
    self.worker_timeout = int(os.getenv("WORKER_TIMEOUT", "1800"))  # 30 minutes
    self.progress_interval = int(os.getenv("PROGRESS_UPDATE_INTERVAL", "30"))
    
    # Create necessary directories
    self.reports_dir = Path(os.getenv("REPORTS_DIR", "./reports"))
    self.temp_dir = Path(os.getenv("TEMP_DIR", "./temp"))
    self.reports_dir.mkdir(exist_ok=True)
    self.temp_dir.mkdir(exist_ok=True)
    
    # Thread pool for worker management
    self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
    
    # Background tasks tracker
    self._background_tasks = {}
    
    # Start recovery task
    asyncio.create_task(self._recover_incomplete_jobs())
    
    logger.info(f"JobManager initialized - Reports: {self.reports_dir}, Temp: {self.temp_dir}")

async def _recover_incomplete_jobs(self):
    """Recover jobs that were interrupted."""
    await asyncio.sleep(5)  # Wait for system to stabilize
    try:
        # Get all running/queued jobs from database
        with db_manager.get_session() as db:
            from ..gateway.models import Job
            incomplete_jobs = db.query(Job).filter(
                Job.status.in_(["queued", "running"])
            ).all()
            
        for job in incomplete_jobs:
            logger.info(f"Found incomplete job {job.id}, attempting recovery")
            # Check if job is already being processed
            if job.id not in self._background_tasks:
                logger.info(f"Restarting job {job.id}")
                task = asyncio.create_task(self._process_job_wrapper(job.id))
                self._background_tasks[job.id] = task
                
    except Exception as e:
        logger.error(f"Failed to recover incomplete jobs: {e}")