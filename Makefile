path: Makefile

.PHONY: help install install-dev run run-backend run-frontend test lint format clean setup-db

# Default target
help:
	@echo "SecureFlow - AI Security Analysis Platform"
	@echo ""
	@echo "Available commands:"
	@echo "  install      - Install all dependencies (Python + Node.js)"
	@echo "  install-dev  - Install development dependencies"
	@echo "  run          - Run both backend and frontend"
	@echo "  run-backend  - Run backend only"
	@echo "  run-frontend - Run frontend only"
	@echo "  test         - Run all tests"
	@echo "  lint         - Run linting checks"
	@echo "  format       - Format code"
	@echo "  setup-db     - Initialize database"
	@echo "  clean        - Clean build artifacts"

# Installation
install:
	@echo "Installing Python dependencies..."
	pip install -r requirements.txt
	@echo "Installing Node.js dependencies..."
	cd frontend && npm install
	@echo "Setting up environment..."
	cp .env.example .env 2>/dev/null || true
	@echo "Installation complete!"

install-dev: install
	@echo "Installing development dependencies..."
	pip install -e ".[dev]"

# Database setup
setup-db:
	@echo "Initializing database..."
	python -c "from backend.scheduler.database import init_db; init_db()"
	@echo "Database initialized!"

# Running services
run: setup-db
	@echo "Starting SecureFlow platform..."
	@echo "Backend will start on http://127.0.0.1:8000"
	@echo "Frontend will start on http://127.0.0.1:5173"
	@echo "Press Ctrl+C to stop all services"
	@make -j2 run-backend run-frontend
# run:
# 	@echo "Starting backend without auto-reload..."
# 	python -m uvicorn backend.gateway.main:app --host 0.0.0.0 --port 8000 &
# 	@echo "Starting frontend..."
# 	cd frontend && npm run dev

run-backend:
	@echo "Starting backend server..."
	python -m uvicorn backend.gateway.main:app --host 0.0.0.0 --port 8000 --reload

run-frontend:
	@echo "Starting frontend server..."
	cd frontend && npm run dev

# Testing
test:
	@echo "Running Python tests..."
	pytest tests/ -v --cov=backend --cov-report=term-missing
	@echo "Running frontend tests..."
	cd frontend && npm run test

test-integration:
	@echo "Running integration tests..."
	pytest tests/ -v -m "integration"

# Code quality
lint:
	@echo "Running Python linting..."
	ruff check backend/ tests/
	mypy backend/
	@echo "Running frontend linting..."
	cd frontend && npm run lint

format:
	@echo "Formatting Python code..."
	black backend/ tests/
	ruff --fix backend/ tests/
	@echo "Formatting frontend code..."
	cd frontend && npm run format

# Cleanup
clean:
	@echo "Cleaning build artifacts..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ *.egg-info/ 2>/dev/null || true
	cd frontend && npm run clean 2>/dev/null || true
	@echo "Cleanup complete!"

# Development helpers
dev-setup: install-dev setup-db
	@echo "Development environment ready!"

# Generate requirements.txt from requirements.in
compile-deps:
	pip-compile requirements.in

run-dev:
	@echo "Starting backend with auto-reload..."
	uvicorn backend.gateway.main:app --host 0.0.0.0 --port 8000 --reload
	@echo "Starting frontend..."
	cd frontend && npm run dev

