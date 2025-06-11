"""
Tests for SecureFlow Scheduler
"""

import pytest
from pathlib import Path
from backend.scheduler.file_processor import FileProcessor

def test_file_processor():
    """Test file processor functionality."""
    processor = FileProcessor()
    
    # Test language detection
    assert processor._detect_language(Path("test.py")) == "python"
    assert processor._detect_language(Path("test.js")) == "javascript"
    assert processor._detect_language(Path("test.java")) == "java"

def test_file_sharding():
    """Test file sharding functionality."""
    processor = FileProcessor()
    files = [Path(f"file_{i}.py") for i in range(10)]
    
    shards = processor.create_shards(files, shard_size=3)
    assert len(shards) == 4  # 3 shards of 3 files + 1 shard of 1 file
