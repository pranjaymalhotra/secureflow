# SecureFlow Monitor

Independent monitoring tool for SecureFlow operations.

## Features

- 📊 Real-time job progress monitoring
- 🤖 LLM interaction tracking
- 🔍 Debug information display
- 📝 Prompt preview and analysis
- 💾 Data export and logging
- 🌐 WebSocket monitoring

## Usage

### Basic Monitoring
```bash
# Install monitor dependencies
pip install -r monitor/requirements.txt

# Run the monitor
python monitor/secureflow_monitor.py
```

### Options
```bash
# Run once (for testing)
python monitor/secureflow_monitor.py --once

# Export analysis report
python monitor/secureflow_monitor.py --export

# Custom database path
python monitor/secureflow_monitor.py --db /path/to/secureflow.db

# Custom API URL
python monitor/secureflow_monitor.py --api http://localhost:8000
```

### What You'll See

1. **System Status** - Shows if backend, database, Ollama, and frontend are running
2. **Active Jobs** - Real-time progress of analysis jobs
3. **LLM Activity** - Which models are processing what files
4. **Debug Information** - Prompt previews and processing details

### Log Files

Monitor creates log files in `monitor/logs/`:
- `monitor_YYYYMMDD_HHMMSS.log` - General monitoring logs
- `jobs_YYYYMMDD_HHMMSS.json` - Job status snapshots
- `workers_YYYYMMDD_HHMMSS.json` - Worker output data
- `analysis_report_YYYYMMDD_HHMMSS.md` - Comprehensive reports

## Display Layout

```
┌─ System Status ─────────────────┐
│ Backend API: ✅ Running         │
│ Database: ✅ Connected          │
│ Ollama: ✅ Running              │
│ Frontend: ✅ Running            │
└─────────────────────────────────┘

┌─ Active Jobs ───────────────────┐
│ Job ID   Status   Progress      │
│ abc123   running  ████░░ 45%    │
│ def456   queued   ░░░░░░ 0%     │
└─────────────────────────────────┘

┌─ LLM Activity ──┐ ┌─ Debug Info ──┐
│ 🤖 deepseek     │ │ 📝 Prompts    │
│ ├─ Job abc123   │ │ ⏰ 14:32:15   │
│ │  └─ 3 findings│ │ 🎯 Model: ... │
│ └─ Job def456   │ │ 📁 File: ... │
└─────────────────┘ └───────────────┘
```

## Monitoring LLM Interactions

The monitor shows:
- Which models are active
- What files are being processed
- Prompt previews (first 200 chars)
- Processing times
- Finding counts
- Confidence scores

This helps you understand:
- If models are working properly
- Which files take longest to process
- What prompts are being sent to LLMs
- How many vulnerabilities are found

---

path: monitor/run_monitor.sh

#!/bin/bash
# Quick start script for SecureFlow Monitor

echo "🔍 Starting SecureFlow Monitor..."

# Check if running from correct directory
if [ ! -f "monitor/secureflow_monitor.py" ]; then
    echo "❌ Please run from the secureflow project root directory"
    exit 1
fi

# Check if monitor dependencies are installed
python -c "import rich, websockets, requests" 2>/dev/null || {
    echo "📦 Installing monitor dependencies..."
    pip install -r monitor/requirements.txt
}

# Check if SecureFlow is running
if ! curl -s http://localhost:8000/health > /dev/null; then
    echo "⚠️  SecureFlow backend doesn't seem to be running"
    echo "   Start it with: make run-backend"
    echo "   Continuing anyway..."
fi

# Start monitor
python monitor/secureflow_monitor.py "$@"