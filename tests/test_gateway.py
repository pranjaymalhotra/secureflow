"""
Tests for SecureFlow Gateway API
"""

import pytest
from fastapi.testclient import TestClient
from backend.gateway.main import app

client = TestClient(app)

def test_root():
    """Test root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    assert "SecureFlow API is running" in response.json()["message"]

def test_health():
    """Test health endpoint."""
    response = client.get("/health")
    assert response.status_code in [200, 503]

def test_login_invalid():
    """Test login with invalid credentials."""
    response = client.post("/auth/login", json={
        "username": "invalid",
        "password": "invalid"
    })
    assert response.status_code == 401