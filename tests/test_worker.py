"""
Tests for SecureFlow Worker
"""

import pytest
from backend.worker.vulnerability_detector import VulnerabilityDetector
from backend.worker.llm_client import LLMClientFactory

def test_vulnerability_patterns():
    """Test vulnerability pattern detection."""
    # Mock LLM client for testing
    class MockLLMClient:
        def __init__(self):
            self.model_name = "test-model"
        
        def generate_sync(self, prompt, **kwargs):
            return "[]"  # Empty JSON array
    
    detector = VulnerabilityDetector(MockLLMClient())
    
    # Test SQL injection detection
    code = "query = 'SELECT * FROM users WHERE id = ' + user_id"
    findings = detector._pattern_based_detection(
        Path("test.py"), code, {"language": "python"}
    )
    
    assert len(findings) > 0
    assert any(f.category == "sql_injection" for f in findings)

def test_llm_client_factory():
    """Test LLM client factory."""
    # Test Ollama client creation
    client = LLMClientFactory.create_client("test-model", "ollama")
    assert client.model_name == "test-model"
    
    # Test error for missing API key
    with pytest.raises(ValueError):
        LLMClientFactory.create_client("test-model", "gemini")
