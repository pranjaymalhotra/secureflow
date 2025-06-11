"""
SecureFlow LLM Client

Unified client interface for different LLM providers (Ollama, Gemini, OpenAI).
"""

import os
import json
import logging
import time
from typing import Dict, List, Optional, Any
from abc import ABC, abstractmethod

import httpx
import google.generativeai as genai
import yaml
from pathlib import Path

logger = logging.getLogger(__name__)

def load_model_config():
    """Load model configuration from YAML file."""
    config_path = Path(os.getenv("CONFIG_DIR", "./config")) / "models.yaml"
    try:
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Error loading model config: {e}")
        return {"primary_model": "deepseek-coder-v2:16b"}

MODEL_CONFIG = load_model_config()


class BaseLLMClient(ABC):
    """Abstract base class for LLM clients."""
    
    def __init__(self, model_name: str, timeout: int = 300):
        self.model_name = model_name or MODEL_CONFIG.get("primary_model")
        self.timeout = timeout
    
    @abstractmethod
    async def generate(self, prompt: str, **kwargs) -> str:
        """Generate response from the model."""
        pass
    
    @abstractmethod
    def generate_sync(self, prompt: str, **kwargs) -> str:
        """Synchronous generate response from the model."""
        pass

class OllamaClient(BaseLLMClient):
    """Ollama LLM client."""
    
    def __init__(self, model_name: str, timeout: int = 300):
        super().__init__(model_name, timeout)
        self.base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.client = httpx.Client(timeout=timeout)
    
    def generate_sync(self, prompt: str, **kwargs) -> str:
        """Generate response using Ollama API."""
        try:
            payload = {
                "model": self.model_name,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": kwargs.get("temperature", 0.1),
                    "top_p": kwargs.get("top_p", 0.9),
                    "num_ctx": kwargs.get("num_ctx", 4096),
                    "repeat_penalty": kwargs.get("repeat_penalty", 1.1)
                }
            }
            
            response = self.client.post(
                f"{self.base_url}/api/generate",
                json=payload
            )
            
            response.raise_for_status()
            result = response.json()
            
            return result.get("response", "")
            
        except Exception as e:
            logger.error(f"Ollama generation error: {e}")
            raise
    
    async def generate(self, prompt: str, **kwargs) -> str:
        """Async generate response using Ollama API."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                payload = {
                    "model": self.model_name,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": kwargs.get("temperature", 0.1),
                        "top_p": kwargs.get("top_p", 0.9),
                        "num_ctx": kwargs.get("num_ctx", 4096),
                        "repeat_penalty": kwargs.get("repeat_penalty", 1.1)
                    }
                }
                
                response = await client.post(
                    f"{self.base_url}/api/generate",
                    json=payload
                )
                
                response.raise_for_status()
                result = response.json()
                
                return result.get("response", "")
                
        except Exception as e:
            logger.error(f"Ollama async generation error: {e}")
            raise

class GeminiClient(BaseLLMClient):
    """Google Gemini LLM client."""
    
    def __init__(self, model_name: str, api_key_env: str, timeout: int = 60):
        super().__init__(model_name, timeout)
        api_key = os.getenv(api_key_env)
        if not api_key:
            raise ValueError(f"API key not found in environment variable: {api_key_env}")
        
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(model_name)
    
    def generate_sync(self, prompt: str, **kwargs) -> str:
        """Generate response using Gemini API."""
        try:
            generation_config = {
                "temperature": kwargs.get("temperature", 0.1),
                "max_output_tokens": kwargs.get("max_tokens", 2048),
                "top_p": kwargs.get("top_p", 0.9),
                "top_k": kwargs.get("top_k", 40)
            }
            
            response = self.model.generate_content(
                prompt,
                generation_config=generation_config
            )
            
            return response.text
            
        except Exception as e:
            logger.error(f"Gemini generation error: {e}")
            raise
    
    async def generate(self, prompt: str, **kwargs) -> str:
        """Async generate response using Gemini API."""
        # Gemini doesn't have native async support, so we use sync version
        return self.generate_sync(prompt, **kwargs)

class OpenAIClient(BaseLLMClient):
    """OpenAI LLM client."""
    
    def __init__(self, model_name: str, api_key_env: str, timeout: int = 60):
        super().__init__(model_name, timeout)
        self.api_key = os.getenv(api_key_env)
        if not self.api_key:
            raise ValueError(f"API key not found in environment variable: {api_key_env}")
        
        self.client = httpx.Client(
            base_url="https://api.openai.com/v1",
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=timeout
        )
    
    def generate_sync(self, prompt: str, **kwargs) -> str:
        """Generate response using OpenAI API."""
        try:
            payload = {
                "model": self.model_name,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": kwargs.get("temperature", 0.1),
                "max_tokens": kwargs.get("max_tokens", 2048),
                "top_p": kwargs.get("top_p", 0.9)
            }
            
            response = self.client.post("/chat/completions", json=payload)
            response.raise_for_status()
            
            result = response.json()
            return result["choices"][0]["message"]["content"]
            
        except Exception as e:
            logger.error(f"OpenAI generation error: {e}")
            raise
    
    async def generate(self, prompt: str, **kwargs) -> str:
        """Async generate response using OpenAI API."""
        try:
            async with httpx.AsyncClient(
                base_url="https://api.openai.com/v1",
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=self.timeout
            ) as client:
                payload = {
                    "model": self.model_name,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": kwargs.get("temperature", 0.1),
                    "max_tokens": kwargs.get("max_tokens", 2048),
                    "top_p": kwargs.get("top_p", 0.9)
                }
                
                response = await client.post("/chat/completions", json=payload)
                response.raise_for_status()
                
                result = response.json()
                return result["choices"][0]["message"]["content"]
                
        except Exception as e:
            logger.error(f"OpenAI async generation error: {e}")
            raise

class LLMClientFactory:
    """Factory for creating LLM clients."""
    
    @staticmethod
    def create_client(
        model_name: str,
        model_type: str,
        api_key_env: Optional[str] = None,
        timeout: int = 300
    ) -> BaseLLMClient:
        """Create appropriate LLM client based on type."""
        
        if model_type == "ollama":
            return OllamaClient(model_name, timeout)
        elif model_type == "gemini":
            if not api_key_env:
                raise ValueError("API key environment variable required for Gemini")
            return GeminiClient(model_name, api_key_env, timeout)
        elif model_type == "openai":
            if not api_key_env:
                raise ValueError("API key environment variable required for OpenAI")
            return OpenAIClient(model_name, api_key_env, timeout)
        else:
            raise ValueError(f"Unsupported model type: {model_type}")

# Convenience function for backward compatibility
def LLMClient(model_name: str, model_type: str, api_key_env: Optional[str] = None, timeout: int = 300):
    """Create LLM client using factory."""
    return LLMClientFactory.create_client(model_name, model_type, api_key_env, timeout)