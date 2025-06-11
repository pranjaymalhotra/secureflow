#!/usr/bin/env python3
"""
SecureFlow Independent Monitor

A standalone monitoring tool that shows:
- Real-time job progress
- LLM inputs/outputs
- Processing stages
- Time estimates
- Debug information

Run independently: python monitor/secureflow_monitor.py
"""

import os
import sys
import json
import time
import sqlite3
import asyncio
import logging
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import subprocess
import threading
from dataclasses import dataclass, asdict
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree
import websockets
import requests

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

console = Console()

@dataclass
class JobInfo:
    """Job information structure."""
    id: str
    status: str
    progress: float
    files_total: int
    files_scanned: int
    current_stage: str
    active_models: List[str]
    created_at: str
    eta_seconds: Optional[int] = None
    error_message: Optional[str] = None

@dataclass
class LLMInteraction:
    """LLM interaction data."""
    timestamp: str
    model: str
    input_prompt: str
    output_response: str
    file_path: str
    processing_time: float
    confidence_scores: List[float]

class SecureFlowMonitor:
    """Independent monitor for SecureFlow operations."""
    
    def __init__(self, db_path: str = "secureflow.db", api_url: str = "http://localhost:8000"):
        self.db_path = db_path
        self.api_url = api_url
        self.console = Console()
        self.running = True
        self.jobs: Dict[str, JobInfo] = {}
        self.llm_interactions: List[LLMInteraction] = []
        self.start_time = datetime.now()
        
        # Create logs directory
        self.logs_dir = Path("monitor/logs")
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup logging
        self.setup_logging()
    
    def setup_logging(self):
        """Setup logging for the monitor."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.logs_dir / f"monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("SecureFlowMonitor")
    
    def check_system_status(self) -> Dict[str, Any]:
        """Check if SecureFlow systems are running."""
        status = {
            "backend_api": False,
            "database": False,
            "ollama": False,
            "frontend": False
        }
        
        # Check backend API
        try:
            response = requests.get(f"{self.api_url}/health", timeout=5)
            status["backend_api"] = response.status_code == 200
        except:
            pass
        
        # Check database
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("SELECT 1")
            conn.close()
            status["database"] = True
        except:
            pass
        
        # Check Ollama
        try:
            result = subprocess.run(["ollama", "list"], capture_output=True, timeout=5)
            status["ollama"] = result.returncode == 0
        except:
            pass
        
        # Check frontend
        try:
            response = requests.get("http://localhost:5173", timeout=5)
            status["frontend"] = response.status_code == 200
        except:
            pass
        
        return status
    
    def get_jobs_from_db(self) -> List[JobInfo]:
        """Get jobs directly from database."""
        jobs = []
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, status, progress, files_total, files_scanned, 
                       current_stage, active_models, created_at, eta_seconds, error_message
                FROM jobs 
                ORDER BY created_at DESC 
                LIMIT 50
            """)
            
            for row in cursor.fetchall():
                active_models = json.loads(row['active_models'] or '[]')
                job = JobInfo(
                    id=row['id'],
                    status=row['status'],
                    progress=row['progress'] or 0.0,
                    files_total=row['files_total'] or 0,
                    files_scanned=row['files_scanned'] or 0,
                    current_stage=row['current_stage'] or 'unknown',
                    active_models=active_models,
                    created_at=row['created_at'],
                    eta_seconds=row['eta_seconds'],
                    error_message=row['error_message']
                )
                jobs.append(job)
            
            conn.close()
        except Exception as e:
            self.logger.error(f"Database error: {e}")
        
        return jobs
    
    def scan_temp_directories(self) -> Dict[str, Any]:
        """Scan temp directories for worker outputs and LLM interactions."""
        temp_dir = Path("temp")
        interactions = []
        worker_outputs = []
        
        if not temp_dir.exists():
            return {"interactions": [], "worker_outputs": []}
        
        # Scan for job directories
        for job_dir in temp_dir.iterdir():
            if not job_dir.is_dir():
                continue
            
            # Look for shard outputs
            shards_dir = job_dir / "shards"
            if shards_dir.exists():
                for shard_dir in shards_dir.iterdir():
                    if not shard_dir.is_dir():
                        continue
                    
                    # Look for worker JSON outputs
                    for json_file in shard_dir.glob("*.json"):
                        try:
                            with open(json_file, 'r') as f:
                                worker_data = json.load(f)
                                worker_outputs.append({
                                    "job_id": job_dir.name,
                                    "shard": shard_dir.name,
                                    "worker": worker_data.get("worker", "unknown"),
                                    "findings_count": len(worker_data.get("findings", [])),
                                    "processing_time": worker_data.get("metadata", {}).get("processing_time_seconds", 0),
                                    "file": str(json_file)
                                })
                        except Exception as e:
                            self.logger.error(f"Error reading worker output {json_file}: {e}")
        
        return {
            "interactions": interactions,
            "worker_outputs": worker_outputs
        }
    
    def monitor_llm_prompts(self, job_id: str) -> List[Dict[str, Any]]:
        """Monitor LLM prompts for a specific job."""
        prompts = []
        
        # This would be enhanced to actually intercept LLM calls
        # For now, we'll create mock data based on patterns
        temp_dir = Path("temp") / job_id
        if temp_dir.exists():
            # Look for files being processed
            for file_path in temp_dir.rglob("*.py"):
                prompt_data = {
                    "timestamp": datetime.now().isoformat(),
                    "file": str(file_path),
                    "model": "deepseek-coder:1.3b",
                    "prompt_preview": self.generate_prompt_preview(file_path),
                    "status": "processing"
                }
                prompts.append(prompt_data)
        
        return prompts
    
    def generate_prompt_preview(self, file_path: Path) -> str:
        """Generate a preview of what would be sent to LLM."""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Simulate the actual prompt that would be sent
            prompt = f"""You are a senior security researcher analyzing code for vulnerabilities.

Analyze the following Python code file for security vulnerabilities:

File: {file_path}
Language: python

Code:
```python
{content[:500]}{'...' if len(content) > 500 else ''}
```

Please identify ALL potential security vulnerabilities...
[TRUNCATED - Full prompt would be ~2000 characters]"""
            
            return prompt
        except:
            return "Error reading file"
    
    def create_status_table(self, system_status: Dict[str, bool]) -> Table:
        """Create system status table."""
        table = Table(title="🔍 System Status")
        table.add_column("Component", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("Details")
        
        status_emoji = {True: "✅", False: "❌"}
        
        table.add_row("Backend API", f"{status_emoji[system_status['backend_api']]} {'Running' if system_status['backend_api'] else 'Offline'}", self.api_url)
        table.add_row("Database", f"{status_emoji[system_status['database']]} {'Connected' if system_status['database'] else 'Offline'}", self.db_path)
        table.add_row("Ollama", f"{status_emoji[system_status['ollama']]} {'Running' if system_status['ollama'] else 'Offline'}", "Local LLM Server")
        table.add_row("Frontend", f"{status_emoji[system_status['frontend']]} {'Running' if system_status['frontend'] else 'Offline'}", "http://localhost:5173")
        
        return table
    
    def create_jobs_table(self, jobs: List[JobInfo]) -> Table:
        """Create jobs monitoring table."""
        table = Table(title="📊 Active Jobs")
        table.add_column("Job ID", style="cyan", width=12)
        table.add_column("Status", style="bold", width=12)
        table.add_column("Progress", width=15)
        table.add_column("Stage", width=20)
        table.add_column("Files", width=10)
        table.add_column("Models", width=15)
        table.add_column("ETA", width=10)
        
        for job in jobs[:10]:  # Show top 10
            # Progress bar
            progress_bar = "█" * int(job.progress / 5) + "░" * (20 - int(job.progress / 5))
            progress_text = f"{progress_bar} {job.progress:.1f}%"
            
            # Status color
            status_color = {
                "queued": "yellow",
                "running": "blue",
                "completed": "green",
                "failed": "red",
                "cancelled": "dim"
            }.get(job.status, "white")
            
            # ETA formatting
            eta_text = "N/A"
            if job.eta_seconds:
                eta_text = f"{job.eta_seconds // 60}m {job.eta_seconds % 60}s"
            
            table.add_row(
                job.id[:8] + "...",
                f"[{status_color}]{job.status}[/{status_color}]",
                progress_text,
                job.current_stage[:18] + "..." if len(job.current_stage) > 18 else job.current_stage,
                f"{job.files_scanned}/{job.files_total}",
                f"{len(job.active_models)} active",
                eta_text
            )
        
        return table
    
    def create_llm_activity_panel(self, worker_outputs: List[Dict[str, Any]]) -> Panel:
        """Create LLM activity monitoring panel."""
        tree = Tree("🤖 LLM Activity")
        
        # Group by job
        jobs_tree = {}
        for output in worker_outputs[-20:]:  # Last 20 outputs
            job_id = output["job_id"]
            if job_id not in jobs_tree:
                jobs_tree[job_id] = tree.add(f"Job: {job_id[:8]}...")
            
            job_node = jobs_tree[job_id]
            worker_info = f"{output['worker']} - {output['findings_count']} findings ({output['processing_time']:.1f}s)"
            job_node.add(worker_info)
        
        if not worker_outputs:
            tree.add("No LLM activity detected")
        
        return Panel(tree, title="🧠 LLM Processing", border_style="blue")
    
    def create_debug_panel(self, prompts: List[Dict[str, Any]]) -> Panel:
        """Create debug information panel."""
        debug_text = Text()
        
        debug_text.append("📝 Recent LLM Prompts:\n", style="bold yellow")
        
        if prompts:
            for prompt in prompts[-5:]:  # Last 5 prompts
                debug_text.append(f"⏰ {prompt['timestamp'][:19]}\n", style="dim")
                debug_text.append(f"🎯 Model: {prompt['model']}\n", style="cyan")
                debug_text.append(f"📁 File: {prompt['file']}\n", style="green")
                debug_text.append(f"💬 Prompt Preview:\n{prompt['prompt_preview'][:200]}...\n\n", style="white")
        else:
            debug_text.append("No recent prompts detected\n", style="dim")
        
        return Panel(debug_text, title="🐛 Debug Information", border_style="magenta")
    
    def save_monitoring_data(self, jobs: List[JobInfo], worker_outputs: List[Dict[str, Any]]):
        """Save monitoring data to files."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save jobs data
        jobs_file = self.logs_dir / f"jobs_{timestamp}.json"
        with open(jobs_file, 'w') as f:
            json.dump([asdict(job) for job in jobs], f, indent=2)
        
        # Save worker outputs
        worker_file = self.logs_dir / f"workers_{timestamp}.json"
        with open(worker_file, 'w') as f:
            json.dump(worker_outputs, f, indent=2)
    
    def run_monitoring_loop(self):
        """Main monitoring loop."""
        with Live(console=self.console, refresh_per_second=1) as live:
            while self.running:
                try:
                    # Gather data
                    system_status = self.check_system_status()
                    jobs = self.get_jobs_from_db()
                    scan_data = self.scan_temp_directories()
                    
                    # Get prompts for active jobs
                    active_jobs = [job for job in jobs if job.status in ["running", "queued"]]
                    prompts = []
                    for job in active_jobs[:3]:  # Monitor top 3 active jobs
                        job_prompts = self.monitor_llm_prompts(job.id)
                        prompts.extend(job_prompts)
                    
                    # Create layout
                    layout = Layout()
                    layout.split_column(
                        Layout(self.create_status_table(system_status), name="status", size=8),
                        Layout(self.create_jobs_table(jobs), name="jobs"),
                        Layout(name="bottom", size=15)
                    )
                    
                    layout["bottom"].split_row(
                        Layout(self.create_llm_activity_panel(scan_data["worker_outputs"]), name="llm"),
                        Layout(self.create_debug_panel(prompts), name="debug")
                    )
                    
                    # Update display
                    live.update(layout)
                    
                    # Save data periodically
                    if datetime.now().second % 30 == 0:  # Every 30 seconds
                        self.save_monitoring_data(jobs, scan_data["worker_outputs"])
                    
                    time.sleep(1)
                    
                except KeyboardInterrupt:
                    self.running = False
                    break
                except Exception as e:
                    self.logger.error(f"Monitoring error: {e}")
                    time.sleep(5)
    
    def run_websocket_monitor(self):
        """Monitor WebSocket connections for real-time updates."""
        async def websocket_listener():
            try:
                # Try to connect to WebSocket endpoint
                uri = "ws://localhost:8000/ws/monitor"  # Special monitoring endpoint
                async with websockets.connect(uri) as websocket:
                    self.logger.info("Connected to WebSocket monitor")
                    async for message in websocket:
                        data = json.loads(message)
                        self.logger.info(f"WebSocket update: {data}")
            except Exception as e:
                self.logger.warning(f"WebSocket monitoring not available: {e}")
        
        # Run in background
        threading.Thread(target=lambda: asyncio.run(websocket_listener()), daemon=True).start()
    
    def export_analysis_report(self):
        """Export comprehensive analysis report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.logs_dir / f"analysis_report_{timestamp}.md"
        
        jobs = self.get_jobs_from_db()
        scan_data = self.scan_temp_directories()
        system_status = self.check_system_status()
        
        report = f"""# SecureFlow Analysis Report
Generated: {datetime.now().isoformat()}
Duration: {datetime.now() - self.start_time}

## System Status
- Backend API: {'✅ Running' if system_status['backend_api'] else '❌ Offline'}
- Database: {'✅ Connected' if system_status['database'] else '❌ Offline'}
- Ollama: {'✅ Running' if system_status['ollama'] else '❌ Offline'}
- Frontend: {'✅ Running' if system_status['frontend'] else '❌ Offline'}

## Job Summary
Total Jobs: {len(jobs)}
Active Jobs: {len([j for j in jobs if j.status in ['running', 'queued']])}
Completed Jobs: {len([j for j in jobs if j.status == 'completed'])}
Failed Jobs: {len([j for j in jobs if j.status == 'failed'])}

## Worker Activity
Total Worker Outputs: {len(scan_data['worker_outputs'])}
Active Models: {len(set(w['worker'] for w in scan_data['worker_outputs']))}

## Recent Jobs
"""
        
        for job in jobs[:10]:
            report += f"""
### Job {job.id}
- Status: {job.status}
- Progress: {job.progress:.1f}%
- Files: {job.files_scanned}/{job.files_total}
- Stage: {job.current_stage}
- Models: {', '.join(job.active_models)}
"""
        
        with open(report_file, 'w') as f:
            f.write(report)
        
        self.console.print(f"[green]Report exported to: {report_file}[/green]")

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="SecureFlow Independent Monitor")
    parser.add_argument("--db", default="secureflow.db", help="Database path")
    parser.add_argument("--api", default="http://localhost:8000", help="API URL")
    parser.add_argument("--export", action="store_true", help="Export report and exit")
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    
    args = parser.parse_args()
    
    monitor = SecureFlowMonitor(db_path=args.db, api_url=args.api)
    
    if args.export:
        monitor.export_analysis_report()
        return
    
    if args.once:
        # Run once for testing
        system_status = monitor.check_system_status()
        jobs = monitor.get_jobs_from_db()
        scan_data = monitor.scan_temp_directories()
        
        console.print(monitor.create_status_table(system_status))
        console.print(monitor.create_jobs_table(jobs))
        console.print(monitor.create_llm_activity_panel(scan_data["worker_outputs"]))
        return
    
    console.print("[bold blue]🔍 SecureFlow Monitor Starting...[/bold blue]")
    console.print("[dim]Press Ctrl+C to stop[/dim]")
    
    # Start WebSocket monitoring in background
    monitor.run_websocket_monitor()
    
    # Start main monitoring loop
    try:
        monitor.run_monitoring_loop()
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitor stopped by user[/yellow]")
    finally:
        console.print("[green]Exporting final report...[/green]")
        monitor.export_analysis_report()

if __name__ == "__main__":
    main()