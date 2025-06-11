"""
SecureFlow Gateway API

Main FastAPI application that serves as the gateway for all API requests.
Handles authentication, file uploads, job management, and WebSocket connections.
"""

import os
import logging
from contextlib import asynccontextmanager
from typing import List
import json
from fastapi import HTTPException
from fastapi.responses import FileResponse

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from fastapi.responses import JSONResponse
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, WebSocket, WebSocketDisconnect, BackgroundTasks
from sqlalchemy import text
import uvicorn

from .auth import get_current_user, create_access_token, verify_password, get_user_by_username
from .models import User, ScanRequest, ScanResponse, ProgressUpdate, LoginRequest , JobStatus
from .models_routes import router as models_router
from ..scheduler.job_manager import JobManager
from ..scheduler.database import init_db, get_database_session
from ..scheduler.websocket_manager import manager


# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO")),
    format=os.getenv("LOG_FORMAT", "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
)
logger = logging.getLogger(__name__)


# # WebSocket connection manager
# class ConnectionManager:
#     """Manages WebSocket connections for real-time progress updates."""
    
#     def __init__(self):
#         self.active_connections: dict[str, WebSocket] = {}
    
#     async def connect(self, websocket: WebSocket, job_id: str):
#         await websocket.accept()
#         self.active_connections[job_id] = websocket
#         logger.info(f"WebSocket connected for job {job_id}")
    
#     def disconnect(self, job_id: str):
#         if job_id in self.active_connections:
#             del self.active_connections[job_id]
#             logger.info(f"WebSocket disconnected for job {job_id}")
    
#     async def send_progress(self, job_id: str, progress: ProgressUpdate):
#         if job_id in self.active_connections:
#             try:
#                 await self.active_connections[job_id].send_json(progress.model_dump())
#             except Exception as e:
#                 logger.error(f"Error sending progress for job {job_id}: {e}")
#                 self.disconnect(job_id)

# # manager = ConnectionManager()

# Add in the lifespan function
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup
    logger.info("Starting SecureFlow Gateway API")
    init_db()
    
    # Load model configuration
    from ..worker.llm_client import load_model_config
    app.state.model_config = load_model_config()
    logger.info(f"Loaded model config: Primary={app.state.model_config.get('primary_model')}")
    
    yield
    # Shutdown
    logger.info("Shutting down SecureFlow Gateway API")

# Create FastAPI app
app = FastAPI(
    title="SecureFlow API",
    description="AI-driven security analysis platform with federated LLM ensemble",
    version="1.0.0",
    lifespan=lifespan
)

# Configure CORS
cors_origins = os.getenv("CORS_ORIGINS", "").split(",") if os.getenv("CORS_ORIGINS") else [
    "http://localhost:5173",
    "http://127.0.0.1:5173"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this to your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Initialize job manager
job_manager = JobManager()

# Include routers
app.include_router(models_router)  # Add this line

@app.get("/")
async def root():
    """Health check endpoint."""
    return {
        "message": "SecureFlow API is running",
        "version": "1.0.0",
        "status": "healthy"
    }

@app.post("/auth/login")
async def login(request: LoginRequest):
    """Authenticate user and return access token."""
    try:
        # Get user from database
        with get_database_session() as db:
            user = get_user_by_username(db, request.username)
            if not user or not verify_password(request.password, user.hashed_password):
                raise HTTPException(
                    status_code=401,
                    detail="Incorrect username or password"
                )
        
        # Create access token
        access_token = create_access_token(data={"sub": user.username})
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user_id": user.id,
            "username": user.username
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# Replace your current upload_files function with this:
@app.post("/scan/upload", response_model=ScanResponse)
async def upload_files(
    files: List[UploadFile] = File(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    current_user: User = Depends(get_current_user)
):
    try:
        logger.info(f"Upload request from user {current_user.id} with {len(files)} files")
        
        # Create job but don't start processing yet
        job_id = await job_manager.create_job_sync(  
            user_id=current_user.id,
            files=files,
            source_type="upload"
        )
        
        # Add background task using FastAPI's system
        background_tasks.add_task(job_manager.process_job_background, job_id)
        
        logger.info(f"Created job {job_id} successfully")
        
        return ScanResponse(
            job_id=job_id,
            status=JobStatus.QUEUED,
            message="Analysis job created successfully"
        )
        
    except Exception as e:
        logger.error(f"Upload failed: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create analysis job: {str(e)}"
        )

# Then delete the unused scan_upload function
async def scan_upload(
    files: List[UploadFile] = File(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),  
    current_user: User = Depends(get_current_user)
):
    try:
        logger.info(f"Upload request from user {current_user.id} with {len(files)} files")
        
        # Create job but don't start processing yet
        job_id = await job_manager.create_job_sync(  
            user_id=current_user.id,
            files=files,
            source_type="upload"
        )
        
        # Add background task using FastAPI's system
        background_tasks.add_task(job_manager.process_job_background, job_id)
        
        logger.info(f"Created job {job_id} successfully")
        
        return ScanResponse(
            job_id=job_id,
            status=JobStatus.QUEUED,
            message="Analysis job created successfully"
        )
        
    except Exception as e:
        logger.error(f"Upload failed: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create analysis job: {str(e)}"
        )

# Update the scan_github function to use background tasks:

@app.post("/scan/github", response_model=ScanResponse)
async def scan_github(
    request: ScanRequest,
    background_tasks: BackgroundTasks = BackgroundTasks(),
    current_user: User = Depends(get_current_user)
):
    """Analyze GitHub repository."""
    try:
        # Validate GitHub URL
        if not request.github_url or not request.github_url.startswith("https://github.com/"):
            raise HTTPException(status_code=400, detail="Invalid GitHub URL")
        
        # Create job but don't start processing yet
        job_id = await job_manager.create_job_sync(
            user_id=current_user.id,
            github_url=request.github_url,
            source_type="github"
        )
        
        # Add background task using FastAPI's system
        background_tasks.add_task(job_manager.process_job_background, job_id)
        
        logger.info(f"Created GitHub job {job_id} successfully")
        
        return ScanResponse(
            job_id=job_id,
            status=JobStatus.QUEUED,
            message="Analysis job created successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"GitHub scan error: {e}")
        raise HTTPException(status_code=500, detail="Failed to create analysis job")

@app.get("/progress/{job_id}")
async def get_progress(
    job_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get analysis progress for a job."""
    try:
        progress = await job_manager.get_progress(job_id, current_user.id)
        if not progress:
            raise HTTPException(status_code=404, detail="Job not found")
        
        return progress
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Progress error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get progress")


# @app.get("/api/reports/{job_id}")
# async def get_analysis_report(job_id: str, current_user: User = Depends(get_current_user)):
#     """Get analysis report for a job with proper status checks"""
#     try:
#         # First check if job exists and belongs to user
#         job_status = await job_manager.get_progress(job_id, current_user.id)
#         if not job_status:
#             raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
        
#         # If job is still running, return status with progress information
#         if job_status["status"] in ["queued", "running"]:
#             return {
#                 "status": "in_progress",
#                 "message": f"Analysis is {job_status['status']}",
#                 "progress": job_status.get("progress", 0),
#                 "current_stage": job_status.get("current_stage", "initializing"),
#                 "files_scanned": job_status.get("files_scanned", 0),
#                 "files_total": job_status.get("files_total", 0),
#                 "eta_seconds": job_status.get("eta_seconds")
#             }
        
#         # For completed jobs, look for the report file
#         report_path = f"reports/{job_id}/analysis_report.json"
        
#         # Check if report file exists
#         if not os.path.exists(report_path):
#             if job_status["status"] == "failed":
#                 return {
#                     "status": "failed",
#                     "message": job_status.get("error_message", "Analysis failed"),
#                     "error": True
#                 }
#             else:
#                 # Job completed but no report found
#                 raise HTTPException(
#                     status_code=404, 
#                     detail=f"Report not found for job {job_id}. The analysis may have failed."
#                 )
        
#         # Read and return the report
#         with open(report_path, 'r', encoding='utf-8') as f:
#             report_data = json.load(f)
        
#         return {"data": report_data}
        
#     except json.JSONDecodeError as e:
#         raise HTTPException(
#             status_code=500, 
#             detail=f"Invalid JSON in report file: {str(e)}"
#         )
#     except HTTPException:
#         raise
#     except Exception as e:
#         logger.error(f"Error reading report: {str(e)}")
#         raise HTTPException(
#             status_code=500, 
#             detail=f"Error accessing report: {str(e)}"
#         )

@app.get("/api/reports/{job_id}")
async def get_analysis_report(job_id: str, current_user: User = Depends(get_current_user)):
    """Get analysis report for a job with proper status checks"""
    try:
        # First check if job exists and belongs to user
        job_status = await job_manager.get_progress(job_id, current_user.id)
        if not job_status:
            raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
        
        # If job is still running, return status with progress information
        if job_status["status"] in ["queued", "running"]:
            return {
                "status": "in_progress",
                "progress": job_status.get("progress", 0),
                "current_stage": job_status.get("current_stage", "initializing"),
                "files_scanned": job_status.get("files_scanned", 0),
                "files_total": job_status.get("files_total", 0),
            }
        
        # For completed jobs, look for the report file
        report_path = f"reports/{job_id}/analysis_report.json"
        
        # Check if report file exists
        if not os.path.exists(report_path):
            return {"status": "failed", "message": "Report not found"}
        
        # Read and return the report
        with open(report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
        
        return {"data": report_data, "status": "completed"}
    except Exception as e:
        logger.error(f"Error reading report: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail=f"Error accessing report: {str(e)}"
        )
    
@app.get("/reports/{job_id}/analysis_report.json")
async def serve_report_file(job_id: str, current_user: User = Depends(get_current_user)):
    """Serve report file directly with authentication and status check"""
    try:
        # Verify job belongs to user
        job_status = await job_manager.get_progress(job_id, current_user.id)
        if not job_status:
            raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
        
        # If job is still running, return a JSON error instead of file
        if job_status["status"] in ["queued", "running"]:
            return JSONResponse(
                status_code=202,
                content={
                    "status": "in_progress",
                    "message": f"Analysis is {job_status['status']}",
                    "progress": job_status.get("progress", 0)
                }
            )
            
        report_path = f"reports/{job_id}/analysis_report.json"
        
        if not os.path.exists(report_path):
            if job_status["status"] == "failed":
                return JSONResponse(
                    status_code=500,
                    content={
                        "status": "failed",
                        "message": job_status.get("error_message", "Analysis failed")
                    }
                )
            else:
                raise HTTPException(status_code=404, detail="Report file not found")
        
        return FileResponse(
            report_path, 
            media_type="application/json",
            filename=f"analysis_report_{job_id}.json"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error serving report file: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error accessing report file: {str(e)}")
    
@app.get("/report/{job_id}")
async def get_report(
    job_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get analysis report for a job using job manager."""
    try:
        # First check job status
        job_status = await job_manager.get_progress(job_id, current_user.id)
        if not job_status:
            raise HTTPException(status_code=404, detail="Job not found")
        
        # If job is not completed, return status info
        if job_status["status"] in ["queued", "running"]:
            return {
                "status": "in_progress",
                "message": f"Analysis is {job_status['status']}",
                "progress": job_status.get("progress", 0),
                "current_stage": job_status.get("current_stage", "initializing"),
                "files_scanned": job_status.get("files_scanned", 0),
                "files_total": job_status.get("files_total", 0)
            }
            
        # For completed jobs, get the report
        report = await job_manager.get_report(job_id, current_user.id)
        
        if not report:
            if job_status["status"] == "failed":
                return {
                    "status": "failed",
                    "message": job_status.get("error_message", "Analysis failed"),
                    "error": True
                }
            else:
                raise HTTPException(status_code=404, detail="Report not found")
        
        return report
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Report error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get report")

###############

@app.websocket("/ws/{job_id}")
async def websocket_job_endpoint(websocket: WebSocket, job_id: str):
    """WebSocket endpoint for individual job progress updates."""
    try:
        await manager.connect(websocket, job_id)
        while True:
            # Keep connection alive by waiting for messages
            try:
                data = await websocket.receive_text()
                # Handle any client messages if needed
                if data.startswith("pong:"):
                    # Client responded to ping
                    logger.debug(f"Received pong from job {job_id}")
                else:
                    # Echo back for ping/pong
                    await websocket.send_text(f"pong: {data}")
            except WebSocketDisconnect:
                logger.info(f"Job WebSocket {job_id} disconnected normally")
                break
    except WebSocketDisconnect:
        logger.info(f"Job WebSocket {job_id} disconnected")
    except Exception as e:
        logger.error(f"Job WebSocket error for {job_id}: {e}")
    finally:
        manager.disconnect(job_id)

# Update your monitor WebSocket endpoint:

@app.websocket("/ws/monitor")
async def websocket_monitor_endpoint(websocket: WebSocket):
    """WebSocket endpoint for monitoring all job updates."""
    client_id = f"monitor_{id(websocket)}"
    try:
        # Log before connection attempt
        logger.info(f"Monitor WebSocket connection attempt from {websocket.client.host}:{websocket.client.port}")
        
        # Accept the connection with proper error handling
        await manager.connect_monitor(websocket, client_id)
        logger.info(f"Monitor WebSocket connected: {client_id}")
        
        # Send welcome message to confirm connection
        try:
            await websocket.send_json({
                "type": "welcome",
                "message": "Connected to SecureFlow monitor"
            })
            logger.info(f"Sent welcome message to {client_id}")
        except Exception as e:
            logger.error(f"Error sending welcome message: {e}")
        
        # Keep connection open with better error handling
        while True:
            try:
                data = await websocket.receive_text()
                logger.debug(f"Received from monitor {client_id}: {data}")
                # Handle monitor client messages if needed
                if data.startswith("pong:"):
                    logger.debug(f"Received pong from monitor {client_id}")
            except WebSocketDisconnect:
                logger.info(f"Monitor WebSocket {client_id} disconnected normally")
                break
            except Exception as e:
                logger.error(f"Error in monitor receive loop for {client_id}: {e}")
                break
                
    except WebSocketDisconnect:
        logger.info(f"Monitor WebSocket {client_id} disconnected during handshake")
    except Exception as e:
        logger.error(f"Monitor WebSocket error for {client_id}: {e}", exc_info=True)
    finally:
        manager.disconnect_monitor(client_id)

@app.get("/ws/status")
async def websocket_status():
    """Get WebSocket connection status."""
    return {
        "active_job_connections": manager.get_connection_count(),
        "monitor_connections": manager.get_monitor_count(),
        "status": "running"
    }

@app.get("/jobs")
async def list_jobs(
    current_user: User = Depends(get_current_user),
    limit: int = 50,
    offset: int = 0
):
    """List user's analysis jobs."""
    try:
        jobs = await job_manager.list_jobs(current_user.id, limit, offset)
        return {"jobs": jobs, "total": len(jobs)}
        
    except Exception as e:
        logger.error(f"List jobs error: {e}")
        raise HTTPException(status_code=500, detail="Failed to list jobs")

@app.delete("/jobs/{job_id}")
async def cancel_job(
    job_id: str,
    current_user: User = Depends(get_current_user)
):
    """Cancel a running analysis job."""
    try:
        success = await job_manager.cancel_job(job_id, current_user.id)
        if not success:
            raise HTTPException(status_code=404, detail="Job not found or cannot be cancelled")
        
        return {"message": "Job cancelled successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Cancel job error: {e}")
        raise HTTPException(status_code=500, detail="Failed to cancel job")

@app.get("/health")
async def health_check():
    """Detailed health check endpoint."""
    try:
        # Check database connection using proper SQLAlchemy 2.0 syntax
        with get_database_session() as db:
            db.execute(text("SELECT 1"))
        
        # Check job manager status
        manager_status = job_manager.get_status()
        
        return {
            "status": "healthy",
            "database": "connected",
            "job_manager": manager_status,
            "active_connections": len(manager.active_connections),
            "monitor_connections": len(manager.monitor_connections)
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e)
            }
        )

if __name__ == "__main__":
    uvicorn.run(
        "backend.gateway.main:app",
        host="0.0.0.0",
        port=8000,
        reload=os.getenv("RELOAD", "false").lower() == "true",
        reload_excludes=["**/temp/**", "**/reports/**", "**/*.db"]  # Add this line
    )