"""
SecureFlow Backend Package

AI-driven security analysis platform with federated LLM ensemble.
"""

# Add the backend directory to Python path
import sys
from pathlib import Path

backend_dir = Path(__file__).parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

__version__ = "1.0.0"
__author__ = "Pranjay Malhotra"