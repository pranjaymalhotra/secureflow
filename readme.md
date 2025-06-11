# 🛡️ SecureFlow - AI-Driven Security Analysis Platform

[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://python.org)
[![React](https://img.shields.io/badge/React-18+-61dafb.svg)](https://reactjs.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688.svg)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**SecureFlow** is a comprehensive AI-driven security analysis platform that uses a federated ensemble of Large Language Models (LLMs) to detect vulnerabilities in source code. It combines multiple AI models including DeepSeek Coder, CodeLlama, QWen, Gemma, and optional OpenAI models to provide highly accurate security assessments.

> **Note**: This project is currently in proof of concept phase. Some components were developed with the assistance of AI and may contain bugs or limitations.

## 🌟 Features

- **🤖 Multi-LLM Ensemble**: 5+ AI models working in parallel for maximum accuracy
- **📊 Real-time Progress**: WebSocket-based live updates during analysis
- **📁 Multiple Input Sources**: File upload or GitHub repository analysis
- **🔍 Comprehensive Detection**: OWASP Top 10, CWE categories, 15+ vulnerability types
- **📋 Detailed Reports**: Executive summaries, code snippets, remediation guidance
- **🌍 Multi-language Support**: Python, JavaScript, Java, C++, PHP, Go, Rust, and more
- **⚡ Professional UI**: Modern, responsive design with dark theme
- **🔐 Secure**: JWT authentication, input validation, CORS protection

## 🚀 Quick Start

### Prerequisites

- **Python 3.12+** 
- **Node.js 18+**
- **Ollama** (for local AI models)
- **Git**
- **16GB RAM** recommended for large models (8GB minimum with configuration adjustments)

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/pranjaymalhotra/secureflow.git
cd secureflow

# Create and activate virtual environment
python -m venv .venv

# Linux/Mac
source .venv/bin/activate

# Windows
.venv\Scripts\activate

# Install all dependencies
make install
```

### 2. Environment Setup

```bash
# Copy environment template
cp .env.example .env

# Edit .env file with your settings
nano .env
```

Here's an updated version of the environment variables section with a warning about API costs:

**Required environment variables:**
```bash
# Add your API keys (optional but recommended)
GEMINI_API_KEY=your-gemini-api-key-here
OPENAI_API_KEY=your-openai-api-key-here  # Added but not fully tested

# JWT Secret (change in production!)
SECRET_KEY=your-secure-secret-key-here
```

> ⚠️ **API Cost Warning**: Cloud API usage (Gemini/OpenAI) can incur significant costs. We recommend first running with local models only. 
If using cloud models, carefully monitor your API usage as the system is not yet optimized for token efficiency.

### 3. Install AI Models

```bash
# Install Ollama first
curl -fsSL https://ollama.ai/install.sh | sh

# Pull recommended models (this will take time - 20-30GB total)
ollama pull deepseek-coder:1.3b     # Fast starter model
ollama pull qwen2.5-coder:7b        # Good balance of speed and accuracy
ollama pull codellama:7b            # Strong code understanding
ollama pull deepseek-coder-v2:16b   # More accurate for larger codebases
ollama pull codegemma:7b            # Strong on multi-file context
ollama pull gemma2:2b               # Fast lightweight option

# Start Ollama service
ollama serve
```

### 4. Initialize Database

```bash
make setup-db
```

### 5. Start Application

```bash
# Start both backend and frontend
make run
```

**Access the application:**
- 🌐 **Frontend**: http://localhost:5173
- 🔧 **Backend API**: http://localhost:8000
- 📚 **API Docs**: http://localhost:8000/docs

**Default login:**
- **Username**: `admin`
- **Password**: `admin123`

> ⚠️ **Important**: Change the default credentials in production!

## 📖 User Guide

### Starting Your First Analysis

1. **Login** with the default credentials
2. **Navigate** to "New Analysis" in the sidebar
3. **Choose** your input method:
   - **File Upload**: Drag & drop files or browse
   - **GitHub Repository**: Enter a public repo URL
4. **Start Analysis** and monitor real-time progress
5. **View Reports** when analysis completes

> ⚠️ **Note**: The Models page (http://localhost:5173/models) currently displays static/dummy values and is still under development. We're working on making it show dynamic real-time model status and configuration.

> ⚠️ **First-Time Analysis Notes**:
> - Start with a single file for your first analysis to gauge performance
> - Initial analysis may take 5-20 minutes depending on your system specs and model size
> - Processing time varies based on file complexity and the number of models enabled

### Supported File Types

- **Python**: `.py`
- **JavaScript/TypeScript**: `.js`, `.ts`, `.jsx`, `.tsx`
- **Java**: `.java`
- **C/C++**: `.c`, `.cpp`, `.h`, `.hpp`
- **C#**: `.cs`
- **PHP**: `.php`
- **Ruby**: `.rb`
- **Go**: `.go`
- **Rust**: `.rs`
- **Kotlin**: `.kt`
- **Swift**: `.swift`
- **Scala**: `.scala`

### Understanding Reports

**Executive Summary**:
- 🎯 **Risk Level**: Overall security assessment
- 📊 **Severity Breakdown**: Findings by criticality
- 📈 **Statistics**: Files analyzed, processing time

**Detailed Findings**:
- 📍 **Location**: Exact file and line number
- 🏷️ **Category**: Vulnerability type (SQL injection, XSS, etc.)
- ⚡ **Severity**: Critical, High, Medium, Low, Info
- 🎯 **Confidence**: AI confidence level (0-100%)
- 💡 **Remediation**: Suggested fixes and best practices
- 🤖 **Attribution**: Which AI models found the issue

## 🏗️ Architecture

### System Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Gateway API   │    │   Scheduler     │
│   (React)       │◄──►│   (FastAPI)     │◄──►│   (AsyncIO)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                       │
                       ┌────────▼────────┐    ┌────────▼────────┐
                       │   Database      │    │   Workers       │
                       │ (SQLite/Postgres)│    │ (Multi-LLM)     │
                       └─────────────────┘    └─────────────────┘
                                                       │
                                              ┌────────▼────────┐
                                              │   Sentinel      │
                                              │   (Merger)      │
                                              └─────────────────┘
```

### AI Model Ensemble

- **Local Models** (via Ollama):
  - DeepSeek Coder 1.3B - Fast starter model
  - QWen 2.5 Coder 7B - Good balance of speed and accuracy
  - CodeLlama 7B - Strong code understanding
  - DeepSeek Coder v2 16B - More accurate for larger codebases
  - CodeGemma 7B - Strong on multi-file context
  - Gemma2 2B - Fast lightweight option

- **Cloud APIs** (optional):
  - Google Gemini Pro - High quality
  - OpenAI GPT-4 - Premium analysis (integration added but not fully tested)

### Processing Flow

1. **Input Processing** (gateway):
   - File uploads or GitHub repo URLs are validated and processed
   - Files are saved to temporary storage for analysis

2. **Job Scheduling** (scheduler):
   - Analysis jobs are created and queued for processing
   - Files are divided into shards for parallel processing
   - Progress updates are sent through WebSockets

3. **Worker Execution** (worker):
   - Multiple worker processes analyze code shards in parallel
   - Each AI model examines the code for vulnerabilities
   - Results are stored in individual JSON files in `/temp/{job_id}`

4. **Result Aggregation** (`/backend/security`):
   - Results from all models are merged and deduplicated
   - Consensus findings are highlighted based on multi-model agreement
   - Final analysis reports are generated and stored in `/reports/{job_id}`

5. **Report Presentation** (ReportPage.tsx):
   - Interactive reports are displayed with filtering and sorting options
   - Findings are visualized with severity distribution charts
   - Detailed view shows code snippets, explanations, and remediation advice

## ⚙️ Configuration

### Model Configuration

Edit models.yaml to customize AI models:

```yaml
worker_models:
  - name: "deepseek-coder:1.3b"
    type: "ollama"
    weight: 1.0
    enabled: true
    
  - name: "qwen2.5-coder:7b"
    type: "ollama"
    weight: 1.0
    enabled: true
    
  - name: "codellama:7b"
    type: "ollama"
    weight: 1.0
    enabled: true
    
  - name: "deepseek-coder-v2:16b"
    type: "ollama"
    weight: 1.0
    enabled: true
    
  - name: "codegemma:7b"
    type: "ollama"
    weight: 1.0
    enabled: true
    
  - name: "gemma2:2b"
    type: "ollama"
    weight: 1.0
    enabled: true
    
  - name: "gemini-pro"
    type: "gemini"
    weight: 1.0
    enabled: true
    api_key_env: "GEMINI_API_KEY"
    
  - name: "gpt-4"
    type: "openai"
    weight: 1.0
    enabled: false  # Disabled by default as not fully tested
    api_key_env: "OPENAI_API_KEY"
```

### Performance Tuning

**For systems with limited RAM** (8GB):
```bash
# Use smaller models only
ollama pull deepseek-coder:1.3b
ollama pull gemma2:2b

# Reduce concurrent workers in .env
MAX_CONCURRENT_WORKERS=2
DEFAULT_SHARD_SIZE=50
```

**For high-performance systems** (32GB+):
```bash
# Use all models including larger ones
MAX_CONCURRENT_WORKERS=6
DEFAULT_SHARD_SIZE=100
```

## 🔧 Development

### Available Commands

```bash
# Development setup
make install-dev          # Install with dev dependencies
make setup-db             # Initialize database
make run                  # Start both backend and frontend

# Backend only
make run-backend          # Start FastAPI server

# Frontend only
make run-frontend         # Start React development server

# Code quality
make test                 # Run all tests
make lint                 # Run linting
make format               # Format code

# Cleanup
make clean                # Remove build artifacts
```

### Project Structure

```
secureflow/
├── 📁 backend/           # Python FastAPI backend
│   ├── 🔧 gateway/       # API endpoints and auth
│   ├── 📋 scheduler/     # Job management
│   ├── 🤖 worker/        # LLM clients and analysis
│   ├── 🎯 sentinel/      # Result merging
│   └── 📊 report/        # Report generation
├── 📁 frontend/          # React TypeScript frontend
│   ├── 📄 src/pages/     # Main application pages
│   │   ├── ReportPage.tsx  # Security analysis report display
│   │   ├── AnalysisPage.tsx # File upload and analysis UI
│   │   └── ...          # Other pages
│   ├── 🧩 src/components/# Reusable UI components
│   ├── 🔌 src/services/  # API and WebSocket clients
│   └── 🎨 src/contexts/  # React contexts
├── 📁 config/            # Configuration files
│   ├── models.yaml       # AI model configurations
│   └── ports.yaml        # Service port configurations
├── 📁 monitor/           # System monitoring
│   ├── logs/             # System and analysis logs
│   └── secureflow_monitor.py # Health monitoring service
├── 📁 reports/           # Generated security reports
│   └── {job_id}/         # Report files by job ID
├── 📁 temp/              # Temporary analysis files
│   └── {job_id}/         # Temporary files by job ID
├── 📁 tests/             # Test suites
└── 📁 examples/          # Example files and outputs
```

### Known Limitations and Issues

> ⚠️ **As this is a proof of concept, please be aware of the following limitations:**

1. **Job Scheduling Inconsistencies**:
   - Occasionally jobs may be properly scheduled in the backend but not immediately appear in the UI jobs list
   - This synchronization issue typically resolves after refreshing or waiting for the next polling interval

2. **Request Handling Limitations**:
   - The system currently processes analysis requests sequentially per worker
   - During intensive analysis operations, other requests may experience delayed response times until current operations complete
   - This is an architectural limitation that will be addressed in future releases

3. **File Counting Accuracy**:
   - The file count displayed during upload may occasionally differ from the actual number of files processed
   - This visual discrepancy does not affect the actual analysis as all uploaded files are properly processed

4. **Initial Analysis Performance**:
   - First-time analysis can be significantly slower as models are loaded into memory
   - Subsequent analyses benefit from cached models and tend to be much faster
   - Performance varies greatly based on hardware specifications and model selection

5. **OpenAI Integration**:
   - OpenAI integration has been implemented but not extensively tested
   - Users should exercise caution when enabling this feature and may need to adjust rate limits and API usage

6. **Models Page**:
   - The Models page (http://localhost:5173/models) currently displays placeholder data
   - Real-time model status, configuration and metrics are planned for future releases
   
## 🚀 Production Deployment

### Environment Setup

```bash
# Use PostgreSQL for production
DATABASE_URL=postgresql://user:password@localhost/secureflow

# Set secure secret key
SECRET_KEY=$(openssl rand -hex 32)

# Configure CORS for your domain
CORS_ORIGINS=["https://your-domain.com"]

# Disable debug mode
DEBUG=false
RELOAD=false
```


### Security Considerations

- ✅ Change default admin credentials
- ✅ Use HTTPS in production
- ✅ Set secure JWT secret key
- ✅ Configure proper CORS origins
- ✅ Set up rate limiting
- ✅ Enable audit logging
- ✅ Regular security updates

## 🐛 Troubleshooting

### Common Issues

**Ollama not responding**:
```bash
# Check if Ollama is running
ollama list

# Restart Ollama service
pkill ollama
ollama serve

# Test model availability
ollama run deepseek-coder:1.3b "Hello"
```

**Database errors**:
```bash
# Reset database
rm secureflow.db
make setup-db
```

**Frontend build errors**:
```bash
# Clear cache and reinstall
cd frontend
rm -rf node_modules package-lock.json
npm install
```

**Memory issues**:
```bash
# Use smaller models
ollama pull deepseek-coder:1.3b
ollama pull gemma2:2b
# Edit config/models.yaml to disable large models
```

**Port conflicts**:
```bash
# Check what's using the ports
lsof -i :8000  # Backend
lsof -i :5173  # Frontend
lsof -i :11434 # Ollama

# Kill processes or change ports in .env
```

**Jobs not showing in UI**:
```bash
# Check the monitor logs
cat monitor/logs/analysis_report_*.md

# Restart the backend services
make run-backend
```

### Performance Optimization

**Slow analysis**:
- Reduce file count or use smaller models
- Increase `MAX_CONCURRENT_WORKERS` if you have more CPU cores
- Use SSD storage for better I/O performance

**High memory usage**:
- Use smaller models (1.3B/2B instead of 7B/16B)
- Reduce `DEFAULT_SHARD_SIZE`
- Monitor with `htop` or `nvidia-smi`

**WebSocket connection issues**:
- Check firewall settings
- Verify proxy configuration
- Ensure ports are accessible

## ⚠️ Disclaimer

**Important**: This AI-generated security analysis is provided for informational purposes only. While our advanced AI models strive for accuracy, this report may contain false positives, miss certain vulnerabilities, or provide incomplete analysis. Always validate critical findings through manual review and professional security assessment. This report does not constitute professional security advice and should not be the sole basis for security decisions.

## 📸 Screenshots

### Dashboard & Analysis
![Login](screenshots/LoginPage.png)
*Login Page*

### Dashboard & Analysis

![Dashboard Overview](screenshots/dashboard.png)
*The main dashboard showing recent analyses and security metrics.*

![New Analysis Page](screenshots/New_Security_Analysis.png)
*File upload interface for starting new security scans.*

![New Analysis Page Local Files and Folder](screenshots/New_Security_Analysis_file_folder.png)

![New Analysis Github](screenshots/New_Security_Analysis_github.png)

![Jobs Analysis page](screenshots/Analysis_Jobs.png)

![Models Page (currently displays placeholder data)](screenshots/Models_Page.png)

### Security Reports
![Executive Summary](screenshots/Report1.png)
*High-level overview of security findings and risk assessment.*

![Executive Summary](screenshots/Report2.png)

![Executive Summary](screenshots/Report3.png)

![Executive Summary](screenshots/Report4.png)
*High-level overview of security findings and risk assessment.*

![Report](screenshots/Report5.png)

![Report](screenshots/Report6.png)

![Report](screenshots/Report7.png)

![Report](screenshots/Report8.png)


## 🤝 Contributing

We welcome contributions! Please see our Contributing Guide for details.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **Ollama** for local LLM hosting
- **DeepSeek** for excellent code models
- **Meta** for CodeLlama models
- **Google** for Gemma models
- **Zhipu AI** for QWen models
- **OpenAI** for GPT models
- **FastAPI** for the excellent web framework
- **React** team for the UI framework

---

**⭐ Star this repository if you find it helpful!**

**Developed by [Pranjay Malhotra](https://github.com/pranjaymalhotra)**
