"""
SecureFlow Models API Routes

Handles dynamic model configuration and status endpoints.
"""

import os
import json
import yaml
import logging
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from .auth import get_current_user
from .models import User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/models", tags=["models"])

class ModelConfig(BaseModel):
    name: str
    type: str
    weight: float
    enabled: bool
    description: str
    specializations: List[str]
    api_key_env: str = None

class ModelStatus(BaseModel):
    name: str
    type: str
    enabled: bool
    available: bool
    last_check: str
    error: str = None

class SystemInfo(BaseModel):
    available_memory_gb: float
    cpu_cores: int
    ollama_running: bool
    api_keys_configured: List[str]

class SystemConfiguration(BaseModel):
    models: Dict[str, Any]
    model_status: List[ModelStatus]
    system_info: SystemInfo

def load_models_config() -> Dict[str, Any]:
    """Load models configuration from YAML file."""
    try:
        config_path = Path(__file__).parent.parent.parent / "config" / "models.yaml"
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Failed to load models config: {e}")
        raise HTTPException(status_code=500, detail="Failed to load models configuration")

def save_models_config(config: Dict[str, Any]) -> None:
    """Save models configuration to YAML file."""
    try:
        config_path = Path(__file__).parent.parent.parent / "config" / "models.yaml"
        with open(config_path, "w") as f:
            yaml.dump(config, f, default_flow_style=False)
    except Exception as e:
        logger.error(f"Failed to save models config: {e}")
        raise HTTPException(status_code=500, detail="Failed to save models configuration")

def check_model_availability(model_name: str, model_type: str) -> ModelStatus:
    """Check if a model is available and working."""
    try:
        if model_type == "ollama":
            import httpx
            try:
                response = httpx.get(f"http://localhost:11434/api/tags", timeout=5)
                if response.status_code == 200:
                    models = response.json().get("models", [])
                    available = any(m["name"] == model_name for m in models)
                    return ModelStatus(
                        name=model_name,
                        type=model_type,
                        enabled=True,
                        available=available,
                        last_check=str(datetime.utcnow()),
                        error=None if available else "Model not found in Ollama"
                    )
                else:
                    return ModelStatus(
                        name=model_name,
                        type=model_type,
                        enabled=True,
                        available=False,
                        last_check=str(datetime.utcnow()),
                        error="Ollama service not responding"
                    )
            except Exception as e:
                return ModelStatus(
                    name=model_name,
                    type=model_type,
                    enabled=True,
                    available=False,
                    last_check=str(datetime.utcnow()),
                    error=f"Ollama connection failed: {str(e)}"
                )
        
        elif model_type in ["gemini", "openai"]:
            # Check if API key is configured
            api_key_env = f"{model_type.upper()}_API_KEY"
            api_key = os.getenv(api_key_env)
            
            return ModelStatus(
                name=model_name,
                type=model_type,
                enabled=True,
                available=bool(api_key),
                last_check=str(datetime.utcnow()),
                error=None if api_key else f"{api_key_env} not configured"
            )
        
        else:
            return ModelStatus(
                name=model_name,
                type=model_type,
                enabled=True,
                available=False,
                last_check=str(datetime.utcnow()),
                error=f"Unknown model type: {model_type}"
            )
            
    except Exception as e:
        logger.error(f"Error checking model {model_name}: {e}")
        return ModelStatus(
            name=model_name,
            type=model_type,
            enabled=True,
            available=False,
            last_check=str(datetime.utcnow()),
            error=str(e)
        )

def get_system_info() -> SystemInfo:
    """Get system information."""
    try:
        import psutil
        
        # Check available memory
        memory = psutil.virtual_memory()
        available_memory_gb = memory.available / (1024**3)
        
        # Check CPU cores
        cpu_cores = psutil.cpu_count()
        
        # Check if Ollama is running
        ollama_running = False
        try:
            import httpx
            response = httpx.get("http://localhost:11434/api/version", timeout=2)
            ollama_running = response.status_code == 200
        except:
            pass
        
        # Check configured API keys
        api_keys_configured = []
        for key in ["GEMINI_API_KEY", "OPENAI_API_KEY"]:
            if os.getenv(key):
                api_keys_configured.append(key)
        
        return SystemInfo(
            available_memory_gb=round(available_memory_gb, 1),
            cpu_cores=cpu_cores,
            ollama_running=ollama_running,
            api_keys_configured=api_keys_configured
        )
        
    except Exception as e:
        logger.error(f"Error getting system info: {e}")
        return SystemInfo(
            available_memory_gb=0,
            cpu_cores=1,
            ollama_running=False,
            api_keys_configured=[]
        )

@router.get("/config")
async def get_models_configuration(current_user: User = Depends(get_current_user)):
    """Get current models configuration."""
    return load_models_config()

@router.put("/config")
async def update_models_configuration(
    config: Dict[str, Any],
    current_user: User = Depends(get_current_user)
):
    """Update models configuration."""
    # Validate and save configuration
    current_config = load_models_config()
    
    # Merge with current config (you might want more sophisticated merging)
    current_config.update(config)
    
    save_models_config(current_config)
    return current_config

@router.get("/system")
async def get_system_configuration(current_user: User = Depends(get_current_user)):
    """Get complete system configuration including model status."""
    config = load_models_config()
    
    # Check status for all worker models
    model_status = []
    for model in config.get("worker_models", []):
        status = check_model_availability(model["name"], model["type"])
        status.enabled = model["enabled"]
        model_status.append(status)
    
    system_info = get_system_info()
    
    return SystemConfiguration(
        models=config,
        model_status=model_status,
        system_info=system_info
    )

@router.get("/status/{model_name}")
async def get_model_status(
    model_name: str,
    current_user: User = Depends(get_current_user)
):
    """Get status for a specific model."""
    config = load_models_config()
    
    # Find the model in configuration
    model = None
    for m in config.get("worker_models", []):
        if m["name"] == model_name:
            model = m
            break
    
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
    
    return check_model_availability(model["name"], model["type"])

@router.post("/test/{model_name}")
async def test_model(
    model_name: str,
    current_user: User = Depends(get_current_user)
):
    """Test if a model is working properly."""
    import time
    start_time = time.time()
    
    try:
        # This would actually test the model
        # For now, just check availability
        config = load_models_config()
        model = None
        for m in config.get("worker_models", []):
            if m["name"] == model_name:
                model = m
                break
        
        if not model:
            raise HTTPException(status_code=404, detail="Model not found")
        
        status = check_model_availability(model["name"], model["type"])
        response_time_ms = int((time.time() - start_time) * 1000)
        
        return {
            "success": status.available,
            "response_time_ms": response_time_ms,
            "error": status.error
        }
        
    except Exception as e:
        return {
            "success": False,
            "response_time_ms": int((time.time() - start_time) * 1000),
            "error": str(e)
        }

@router.patch("/{model_name}/toggle")
async def toggle_model(
    model_name: str,
    enabled: bool,
    current_user: User = Depends(get_current_user)
):
    """Enable or disable a model."""
    config = load_models_config()
    
    # Find and update the model
    for model in config.get("worker_models", []):
        if model["name"] == model_name:
            model["enabled"] = enabled
            save_models_config(config)
            
            return check_model_availability(model["name"], model["type"])
    
    raise HTTPException(status_code=404, detail="Model not found")

@router.get("/metrics")
async def get_model_metrics(current_user: User = Depends(get_current_user)):
    """Get model performance metrics."""
    # This would return actual metrics from a metrics store
    # For now, return mock data
    return {
        "models": [
            {
                "name": "deepseek-coder-v2:16b",
                "avg_response_time_ms": 2500,
                "success_rate": 0.95,
                "total_requests": 142,
                "last_used": "2024-06-08T10:30:00Z"
            }
        ]
    }
