"""
SecureFlow WebSocket Manager - Fixed for stability
"""

import logging
import asyncio
import json
from typing import Dict
from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

class ConnectionManager:
    """Manages WebSocket connections for real-time progress updates."""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.ping_intervals: Dict[str, asyncio.Task] = {}
        self.monitor_connections: Dict[str, WebSocket] = {}
        self.connect_count: Dict[str, int] = {}  # Track connection attempts
        
    async def connect(self, websocket: WebSocket, job_id: str):
        try:
            await websocket.accept()
            self.active_connections[job_id] = websocket
            self.connect_count[job_id] = 0  # Reset connection count
            logger.info(f"WebSocket connected for job {job_id}")
            
            # Start ping/pong to keep connection alive
            async def ping_client():
                while job_id in self.active_connections:
                    try:
                        await websocket.send_text(f"ping:{job_id}")
                        await asyncio.sleep(15)  # Send ping every 15 seconds
                    except WebSocketDisconnect:
                        logger.info(f"WebSocket disconnected normally for job {job_id}")
                        self.disconnect(job_id)
                        break
                    except Exception as e:
                        logger.error(f"Ping error for {job_id}: {e}")
                        self.disconnect(job_id)
                        break
            
            # Start ping task with proper error handling
            try:
                self.ping_intervals[job_id] = asyncio.create_task(ping_client())
            except Exception as e:
                logger.error(f"Error creating ping task for {job_id}: {e}")
            
        except Exception as e:
            logger.error(f"Error connecting WebSocket for job {job_id}: {e}")
            raise
    
    def disconnect(self, job_id: str):
        """Disconnect a job WebSocket and clean up resources."""
        if job_id in self.active_connections:
            if job_id in self.ping_intervals:
                self.ping_intervals[job_id].cancel()
                del self.ping_intervals[job_id]
            del self.active_connections[job_id]
            logger.info(f"WebSocket disconnected for job {job_id}")
    
    async def connect_monitor(self, websocket: WebSocket, client_id: str = "monitor"):
        try:
            await websocket.accept()
            self.monitor_connections[client_id] = websocket
            logger.info(f"WebSocket connected for job monitor: {client_id}")
            
            # Keep monitor connection alive with proper JSON formatting for non-ping messages
            async def ping_monitor():
                while client_id in self.monitor_connections:
                    try:
                        # Send a simple text ping - frontend will handle this specially
                        await websocket.send_text("ping:monitor")
                        await asyncio.sleep(15)
                    except WebSocketDisconnect:
                        logger.info(f"Monitor WebSocket disconnected normally: {client_id}")
                        self.disconnect_monitor(client_id)
                        break
                    except Exception as e:
                        logger.error(f"Monitor ping error for {client_id}: {e}")
                        self.disconnect_monitor(client_id)
                        break
            
            # Start ping task with proper error handling
            try:
                asyncio.create_task(ping_monitor())
            except Exception as e:
                logger.error(f"Error creating monitor ping task for {client_id}: {e}")
            
        except Exception as e:
            logger.error(f"Error connecting monitor WebSocket for {client_id}: {e}")
            raise
    
    def disconnect_monitor(self, client_id: str = "monitor"):
        """Disconnect a monitor WebSocket and clean up resources."""
        if client_id in self.monitor_connections:
            del self.monitor_connections[client_id]
            logger.info(f"Monitor WebSocket disconnected for {client_id}")
    
    async def broadcast_job_update(self, job_data: dict):
        """Broadcast job updates to all monitor connections with proper JSON."""
        if not self.monitor_connections:
            logger.debug("No monitor connections to broadcast to")
            return
            
        disconnected = []
        message = {
            "type": "job_update",
            "data": job_data
        }
        
        logger.info(f"Broadcasting job update to {len(self.monitor_connections)} monitors: {job_data.get('id', 'unknown')}")
        
        for client_id, websocket in self.monitor_connections.items():
            try:
                # Always send job updates as proper JSON
                await websocket.send_json(message)
                logger.debug(f"Sent job update to monitor {client_id}")
            except WebSocketDisconnect:
                logger.info(f"Monitor {client_id} disconnected during broadcast")
                disconnected.append(client_id)
            except Exception as e:
                logger.error(f"Error broadcasting to monitor {client_id}: {e}")
                disconnected.append(client_id)
        
        # Clean up disconnected monitors
        for client_id in disconnected:
            self.disconnect_monitor(client_id)
            
    def get_monitor_count(self) -> int:
        """Get number of monitor connections."""
        return len(self.monitor_connections)
        
    def get_connection_count(self) -> int:
        """Get number of active job connections."""
        return len(self.active_connections)

# Global instance
manager = ConnectionManager()