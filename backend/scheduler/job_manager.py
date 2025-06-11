"""
SecureFlow Job Manager

Orchestrates analysis jobs, manages worker processes, and tracks progress.
"""

import os
import json
import asyncio
import logging
import uuid
import yaml
import subprocess
import tempfile
import git
import shutil
from datetime import datetime,timedelta
from typing import List, Dict, Optional, Any
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import time
import traceback

import git
from fastapi import UploadFile

from .websocket_manager import manager
from .database import db_manager
from .file_processor import FileProcessor
from .websocket_manager import manager as websocket_manager
from ..worker.compliance_checker import ComplianceChecker



os.environ["WORKER_TIMEOUT"] = "1800"
os.environ["MAX_CONCURRENT_WORKERS"] = "4"
os.environ["PROGRESS_UPDATE_INTERVAL"] = "30"

logger = logging.getLogger(__name__)

class JobManager:
    """Manages analysis jobs and worker orchestration."""
    
    def __init__(self):
        self.active_jobs: Dict[str, Dict] = {}
        self.file_processor = FileProcessor()
        self.max_workers = int(os.getenv("MAX_CONCURRENT_WORKERS", "4"))
        self.worker_timeout = int(os.getenv("WORKER_TIMEOUT", "1800"))  # 30 minutes
        self.progress_interval = int(os.getenv("PROGRESS_UPDATE_INTERVAL", "30"))
        
        # Create necessary directories
        self.reports_dir = Path(os.getenv("REPORTS_DIR", "./reports"))
        self.temp_dir = Path(os.getenv("TEMP_DIR", "./temp"))
        self.reports_dir.mkdir(exist_ok=True)
        self.temp_dir.mkdir(exist_ok=True)
        
        # Thread pool for worker management
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        
        logger.info(f"JobManager initialized - Reports: {self.reports_dir}, Temp: {self.temp_dir}")
    
    async def create_job(
        self,
        user_id: int,
        files: Optional[List[UploadFile]] = None,
        github_url: Optional[str] = None,
        source_type: str = "upload"
    ) -> str:
        """Create a new analysis job with immediate broadcasting."""
        try:
            job_id = str(uuid.uuid4())
            logger.info(f"Creating job {job_id} for user {user_id}, source_type: {source_type}")
            
            # Create job directory
            job_dir = self.temp_dir / job_id
            job_dir.mkdir(exist_ok=True, parents=True)
            logger.info(f"Created job directory: {job_dir}")
            
            # Process input files
            if source_type == "upload" and files:
                file_paths = await self._save_uploaded_files(files, job_dir)
                logger.info(f"Saved {len(file_paths)} uploaded files")
            elif source_type == "github" and github_url:
                file_paths = await self._clone_github_repo(github_url, job_dir)
                logger.info(f"Cloned repo with {len(file_paths)} files")
            else:
                raise ValueError(f"Invalid source type '{source_type}' or missing files/URL")
            
            if not file_paths:
                # If no supported files, create a dummy file for testing
                logger.warning("No valid files found, creating test file")
                test_file = job_dir / "test.py"
                test_file.write_text("# Test file\nprint('Hello World')")
                file_paths = [test_file]
            
            # Create job record in database
            job_data = {
                "id": job_id,
                "user_id": user_id,
                "source_type": source_type,
                "source_url": github_url,
                "status": "queued",
                "progress": 0.0,
                "files_total": len(file_paths),
                "files_scanned": 0,
                "current_stage": "initializing",
                "active_models": json.dumps([]),
                "created_at": datetime.utcnow()
            }
            
            db_manager.create_job_record(job_data)
            logger.info(f"Created database record for job {job_id}")
            
            # Store job metadata
            self.active_jobs[job_id] = {
                "user_id": user_id,
                "job_dir": job_dir,
                "file_paths": file_paths,
                "status": "queued",
                "created_at": datetime.utcnow(),
                "progress": 0.0,
                "file_count": len(file_paths)
            }
            
            # CRITICAL: Immediately broadcast job creation to monitors
            await self._broadcast_job_created(job_data)
            
            # Start job processing in background
            task = asyncio.create_task(self._process_job_wrapper(job_id))
            if not hasattr(self, '_background_tasks'):
                self._background_tasks = {}
            self._background_tasks[job_id] = task
            logger.info(f"Background task created for job {job_id}")

            logger.info(f"Job {job_id} created successfully with {len(file_paths)} files")
            return job_id
            
        except Exception as e:
            logger.error(f"Failed to create job: {e}")
            logger.error(traceback.format_exc())
            if 'job_dir' in locals() and job_dir.exists():
                shutil.rmtree(job_dir, ignore_errors=True)
            raise

    async def _broadcast_job_created(self, job_data: dict):
        """Broadcast job creation to WebSocket monitors."""
        try:
            # Import here to avoid circular import
            from .websocket_manager import manager as websocket_manager
            
            broadcast_data = {
                "id": job_data["id"],
                "user_id": job_data["user_id"],
                "source_type": job_data["source_type"],
                "source_url": job_data.get("source_url"),
                "status": job_data["status"],
                "progress": job_data["progress"],
                "files_total": job_data["files_total"],
                "files_scanned": job_data["files_scanned"],
                "created_at": job_data["created_at"].isoformat() if isinstance(job_data["created_at"], datetime) else job_data["created_at"],
                "action": "created"
            }
            
            await websocket_manager.broadcast_job_created(broadcast_data)
            logger.info(f"Broadcasted job creation for {job_data['id']}")
            
        except Exception as e:
            logger.error(f"Failed to broadcast job creation: {e}")


    async def _process_job(self, job_id: str):
        """Process analysis job through the pipeline."""
        try:

            job_info = self.active_jobs[job_id]
            file_paths = job_info["file_paths"]
            job_dir = self.temp_dir / job_id
            
            # Create proper temp structure
            models_dir = job_dir / "models"
            models_dir.mkdir(exist_ok=True)
            
            # Load models config
            models_config = self._load_models_config()
            worker_models = models_config.get("worker_models", [])
            enabled_models = [m for m in worker_models if m.get("enabled", True)]
            
            if not enabled_models:
                raise Exception("No enabled models found")
            
            # Update job status
            await self._update_job_status(job_id, "running", "analyzing_files")
            
            total_files = len(file_paths)
            files_processed = 0
            
            # Process each model
            model_reports = {}
            for model in enabled_models:
                model_name = model["name"]
                await self._update_job_status(
                    job_id, "running", f"processing_with_{model_name}",
                    active_models=[model_name]
                )
                
                # Create model-specific directory
                model_dir = models_dir / model_name.replace(":", "_")
                model_dir.mkdir(exist_ok=True)
                
                # Process files with this model
                model_findings = []
                for i, file_path in enumerate(file_paths):
                    try:
                        # Read file content
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        # Call real LLM
                        findings = await self._analyze_file_with_model(
                            file_path, content, model, job_id
                        )
                        model_findings.extend(findings)
                        
                        # Update progress
                        files_processed += 1
                        progress = (files_processed / (total_files * len(enabled_models))) * 100
                        await self._update_job_status(
                            job_id, "running", f"processing_with_{model_name}",
                            progress=progress,
                            files_scanned=files_processed,
                            active_models=[model_name]
                        )
                        
                        # Send WebSocket update
                        if hasattr(self, 'websocket_manager'):
                            await self.websocket_manager.send_progress(job_id, {
                                "job_id": job_id,
                                "stage": f"processing_with_{model_name}",
                                "files_scanned": files_processed,
                                "total_files": total_files * len(enabled_models),
                                "progress_percentage": progress,
                                "current_file": str(file_path),
                                "active_models": [model_name],
                                "status": "running"
                            })
                        
                    except Exception as e:
                        logger.error(f"Error processing {file_path} with {model_name}: {e}")
                        continue
                
                # Save model report
                model_report = {
                    "model": model,
                    "findings": model_findings,
                    "processed_files": len(file_paths),
                    "total_findings": len(model_findings),
                    "timestamp": datetime.now().isoformat()
                }
                
                # Save to JSON
                report_file = model_dir / "findings.json"
                with open(report_file, 'w') as f:
                    json.dump(model_report, f, indent=2, default=str)
                
                model_reports[model_name] = model_report
                logger.info(f"Model {model_name} completed: {len(model_findings)} findings")
            
            # Combine all model reports
            await self._update_job_status(job_id, "running", "combining_results")
            final_report = await self._combine_model_reports(model_reports, job_id)
            
            # Generate final report
            await self._update_job_status(job_id, "running", "generating_report")
            await self._generate_final_report(final_report, job_id)
            
            # Complete job
            await self._update_job_status(job_id, "completed", "analysis_complete")
            
        except Exception as e:
            logger.error(f"Job {job_id} failed: {e}")
            await self._update_job_status(job_id, "failed", "error", str(e))
            raise


    async def _analyze_file_with_model(self, file_path: Path, content: str, model: dict, job_id: str):
        """Analyze a single file with a specific model."""
        try:
            # Import here to avoid circular imports
            from ..worker.llm_client import LLMClientFactory
            from ..worker.vulnerability_detector import VulnerabilityDetector
            
            # Create LLM client
            client = LLMClientFactory.create_client(
                model["name"], 
                model["type"], 
                model.get("api_key_env"),
                timeout=300
            )
            
            # Create detector
            detector = VulnerabilityDetector(client)
            
            # Get file info
            file_info = {
                "language": self.file_processor._detect_language(file_path),
                "size": len(content),
                "lines": content.count('\n') + 1
            }
            
            # Analyze file
            findings = detector.analyze_file(file_path, content, file_info)
            
            # Convert findings to dict format
            findings_dict = []
            for finding in findings:
                findings_dict.append({
                    "file": str(finding.file),
                    "line": finding.line,
                    "category": finding.category,
                    "severity": finding.severity.value if hasattr(finding.severity, 'value') else finding.severity,
                    "confidence": finding.confidence,
                    "explanation": finding.explanation,
                    "code_snippet": getattr(finding, 'code_snippet', ''),
                    "found_by": model["name"]
                })
            
            return findings_dict
            
        except Exception as e:
            logger.error(f"Error analyzing {file_path} with {model['name']}: {e}")
            return []

    async def _combine_model_reports(self, model_reports: dict, job_id: str):
        """Combine reports from all models with enhanced synthesis."""
        all_findings = []
        models_used = []
        all_file_summaries = {}
        all_overall_analyses = {}
        
        for model_name, report in model_reports.items():
            all_findings.extend(report["findings"])
            models_used.append(model_name)
            
            # Collect enhanced data
            if "file_summaries" in report:
                all_file_summaries[model_name] = report["file_summaries"]
            if "overall_analysis" in report:
                all_overall_analyses[model_name] = report["overall_analysis"]
        
        # Deduplicate similar findings
        deduplicated_findings = self._deduplicate_findings(all_findings)
        
        # Calculate statistics
        severity_counts = {}
        for finding in deduplicated_findings:
            severity = finding["severity"]
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Perform main LLM synthesis
        depth_analysis = await self._synthesize_with_main_llm(model_reports, job_id)
        
        combined_report = {
            "job_id": job_id,
            "depth_analysis": depth_analysis,
            "model_overall_analyses": all_overall_analyses,
            "file_summaries_by_model": all_file_summaries,
            "executive_summary": {
                "total_findings": len(deduplicated_findings),
                "severity_counts": severity_counts,
                "models_used": models_used,
                "files_analyzed": len(self.active_jobs[job_id]["file_paths"]),
                "processing_time": 0,  # Calculate if needed
                "generated_at": datetime.now().isoformat()
            },
            "detailed_findings": deduplicated_findings,
            "model_reports": model_reports
        }
        
        return combined_report
    
    def _deduplicate_findings(self, findings: list):
        """Simple deduplication based on file, line, and category."""
        seen = set()
        deduplicated = []
        
        for finding in findings:
            key = (finding["file"], finding["line"], finding["category"])
            if key not in seen:
                seen.add(key)
                deduplicated.append(finding)
        
        return deduplicated

    async def _process_job_wrapper(self, job_id: str):
        """Wrapper to handle the async processing."""
        try:
            await self._process_job(job_id)
        except Exception as e:
            logger.error(f"Job wrapper failed for {job_id}: {e}")
            await self._update_job_status(job_id, "failed", "error", str(e))

    # async def _generate_final_report(self, report: dict, job_id: str):
    #     """Generate and save final report."""
    #     # Save combined report to temp
    #     temp_report_file = self.temp_dir / job_id / "combined_report.json"
    #     with open(temp_report_file, 'w') as f:
    #         json.dump(report, f, indent=2, default=str)
        
    #     # Save final report to reports directory
    #     reports_job_dir = self.reports_dir / job_id
    #     reports_job_dir.mkdir(exist_ok=True)
        
    #     final_report_file = reports_job_dir / "analysis_report.json"
    #     with open(final_report_file, 'w') as f:
    #         json.dump(report, f, indent=2, default=str)
        
    #     # Generate markdown report (simplified)
    #     markdown_content = self._generate_markdown_report(report)
    #     markdown_file = reports_job_dir / "analysis_report.md"
    #     with open(markdown_file, 'w') as f:
    #         f.write(markdown_content)
        
    #     logger.info(f"Final reports saved to {reports_job_dir}")

# Replace the _generate_final_report method:

    async def _generate_final_report(self, report: dict, job_id: str):
        """Generate and save final report."""
        try:
            # Save combined report to temp
            temp_report_file = self.temp_dir / job_id / "combined_report.json"
            with open(temp_report_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            # Save final report to reports directory
            reports_job_dir = self.reports_dir / job_id
            reports_job_dir.mkdir(exist_ok=True)
            
            # Extract findings from the report for compliance checking
            raw_findings = report.get("detailed_findings", [])
            
            # Convert dictionary findings to DetailedFinding objects
            from ..gateway.models import DetailedFinding, SeverityLevel
            
            findings = []
            for finding_dict in raw_findings:
                try:
                    # Convert severity string to SeverityLevel enum
                    severity_value = finding_dict.get("severity", "medium")
                    try:
                        severity = SeverityLevel(severity_value)
                    except (ValueError, TypeError):
                        # Default to medium if conversion fails
                        severity = SeverityLevel.MEDIUM
                    
                    # Create DetailedFinding object
                    finding = DetailedFinding(
                        id=finding_dict.get("id"),
                        file=finding_dict.get("file", ""),
                        line=finding_dict.get("line", 0),
                        category=finding_dict.get("category", "unknown"),
                        severity=severity,
                        confidence=finding_dict.get("confidence", 0.5),
                        explanation=finding_dict.get("explanation", ""),
                        code_snippet=finding_dict.get("code_snippet", "")
                    )
                    findings.append(finding)
                except Exception as e:
                    logger.warning(f"Failed to convert finding to DetailedFinding object: {e}")
                    continue
            
            logger.info(f"Converting {len(raw_findings)} findings to DetailedFinding objects, got {len(findings)}")
            
            # Generate compliance reports
            compliance_checker = ComplianceChecker()
            compliance_report = compliance_checker.generate_compliance_report(findings)
            compliance_markdown = compliance_checker.generate_compliance_report_markdown(findings)
            
            # Add compliance analysis to the main report
            report["compliance_analysis"] = compliance_report
            
            # Save the enhanced report with compliance data
            final_report_file = reports_job_dir / "analysis_report.json"
            with open(final_report_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            # Save the compliance markdown report separately
            compliance_md_file = reports_job_dir / "compliance_report.md"
            with open(compliance_md_file, 'w') as f:
                f.write(compliance_markdown)
            
            # Generate markdown report (simplified)
            markdown_content = self._generate_markdown_report(report)
            markdown_file = reports_job_dir / "analysis_report.md"
            with open(markdown_file, 'w') as f:
                f.write(markdown_content)
            
            logger.info(f"Final reports saved to {reports_job_dir}")
        
        except Exception as e:
            logger.error(f"Failed to generate final report: {e}", exc_info=True)
            # Create a basic report if compliance generation fails
            final_report_file = reports_job_dir / "analysis_report.json"
            if not final_report_file.exists():
                with open(final_report_file, 'w') as f:
                    json.dump(report, f, indent=2, default=str)
            
            # Generate basic markdown without compliance
            markdown_content = self._generate_markdown_report(report)
            markdown_file = reports_job_dir / "analysis_report.md"
            with open(markdown_file, 'w') as f:
                f.write(markdown_content)
            
            logger.info(f"Basic report saved after error to {reports_job_dir}")

    # def _generate_markdown_report(self, report: dict) -> str:
    #     """Generate a simple markdown report."""
    #     summary = report["executive_summary"]
    #     findings = report["detailed_findings"]
        
    #     md = f"""# Security Analysis Report

    # ## Executive Summary
    # - **Total Findings**: {summary['total_findings']}
    # - **Models Used**: {', '.join(summary['models_used'])}
    # - **Files Analyzed**: {summary['files_analyzed']}
    # - **Generated**: {summary['generated_at']}

    # ## Severity Breakdown
    # """
        
    #     for severity, count in summary["severity_counts"].items():
    #         md += f"- **{severity.upper()}**: {count}\n"
        
    #     md += "\n## Detailed Findings\n\n"
        
    #     for i, finding in enumerate(findings[:20], 1):  # Limit to first 20
    #         md += f"""### {i}. {finding['category']} ({finding['severity'].upper()})
    # - **File**: {finding['file']}
    # - **Line**: {finding['line']}
    # - **Confidence**: {finding['confidence']:.2f}
    # - **Found by**: {finding['found_by']}
    # - **Explanation**: {finding['explanation']}

    # """
        
    #     return md   
    
# Replace the _generate_markdown_report method with this enhanced version:

    def _generate_markdown_report(self, report: dict) -> str:
        """Generate an enhanced markdown report with improved formatting."""
        summary = report["executive_summary"]
        findings = report["detailed_findings"]
        
        # Improved Executive Summary Dashboard
        md = f"""# Security Analysis Report

    ## Executive Summary Dashboard

    **Security Status**: {self._determine_security_status(summary)}

    | Metric | Value |
    |--------|-------|
    | Total Findings | {summary['total_findings']} |
    | Files Analyzed | {summary['files_analyzed']} |
    | Models Used | {len(summary['models_used'])} |
    | Generated | {summary['generated_at']} |

    ### Severity Distribution

    """
        
        # Add severity breakdown with emoji indicators
        severity_emojis = {
            "critical": "🔴",
            "high": "🟠", 
            "medium": "🟡",
            "low": "🔵",
            "info": "⚪"
        }
        
        for severity, count in summary.get("severity_counts", {}).items():
            emoji = severity_emojis.get(severity.lower(), "•")
            md += f"- **{severity.upper()}**: {emoji} {count}\n"
        
        # Add AI synthesis if available
        if "depth_analysis" in report and isinstance(report["depth_analysis"], dict):
            depth = report["depth_analysis"]
            
            md += f"\n## AI-Synthesized Security Intelligence\n\n{depth.get('executive_insights', '')}\n"
            
            # Add prioritized actions with solutions
            if "prioritized_action_items" in depth and depth["prioritized_action_items"]:
                md += "\n### Prioritized Action Plan\n\n"
                
                for i, action in enumerate(depth["prioritized_action_items"][:7], 1):
                    md += f"**{i}. {action.get('action', '')}**\n"
                    if "impact" in action:
                        md += f"   - **Impact**: {action['impact']}\n"
                    if "solution" in action:
                        md += f"   - **Solution**: {action['solution']}\n"
                    md += "\n"
            
            # Add architectural risks if available
            if "architectural_risks" in depth and depth["architectural_risks"]:
                md += "\n### Architectural Risk Areas\n\n"
                for risk in depth["architectural_risks"][:5]:
                    md += f"- {risk}\n"
        
        # Add top model findings
        md += "\n## Model-Specific Insights\n\n"
        for model in summary["models_used"][:5]:  # Limit to first 5 models
            model_findings = [f for f in findings if f.get("found_by") == model]
            
            md += f"### {model}\n"
            md += f"- **Findings**: {len(model_findings)}\n"
            
            # Count by severity
            severities = {}
            for f in model_findings:
                sev = f.get("severity", "unknown").lower()
                severities[sev] = severities.get(sev, 0) + 1
            
            # Show severity breakdown
            sev_str = ", ".join([f"{count} {sev}" for sev, count in severities.items()])
            md += f"- **Severity Breakdown**: {sev_str}\n\n"
        
        # Add detailed findings (limited to first 20)
        md += "\n## Key Security Findings\n\n"
        
        # Group findings by category
        findings_by_category = {}
        for finding in findings:
            category = finding.get("category", "unknown")
            if category not in findings_by_category:
                findings_by_category[category] = []
            findings_by_category[category].append(finding)
        
        # Sort categories by highest severity and count
        sorted_categories = sorted(
            findings_by_category.items(), 
            key=lambda x: (
                max([{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(f.get("severity", "low").lower(), 0) for f in x[1]]),
                len(x[1])
            ),
            reverse=True
        )
        
        # Show top categories with examples
        for category, category_findings in sorted_categories[:10]:
            md += f"### {category.replace('_', ' ').title()}\n\n"
            md += f"**Count**: {len(category_findings)}\n\n"
            
            # Show top 3 examples
            top_findings = sorted(
                category_findings, 
                key=lambda x: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(x.get("severity", "low").lower(), 0),
                reverse=True
            )[:3]
            
            for i, finding in enumerate(top_findings, 1):
                severity = finding.get("severity", "").upper()
                emoji = severity_emojis.get(finding.get("severity", "").lower(), "•")
                
                md += f"**Example {i}**: {emoji} {severity}\n"
                md += f"- **File**: `{finding.get('file', '')}`\n"
                md += f"- **Line**: {finding.get('line', 'N/A')}\n"
                md += f"- **Found by**: {finding.get('found_by', 'N/A')}\n"
                
                explanation = finding.get('explanation', '')
                if len(explanation) > 200:
                    explanation = explanation[:200] + "..."
                md += f"- **Issue**: {explanation}\n\n"
        
        # Add compliance section if available
        if "compliance_analysis" in report:
            md += "\n## Compliance Impact\n\n"
            compliance = report["compliance_analysis"]
            
            if "overall_compliance_score" in compliance:
                md += f"**Overall Compliance Score**: {compliance['overall_compliance_score']}%\n\n"
            
            if "executive_summary" in compliance and "status" in compliance["executive_summary"]:
                md += f"**Status**: {compliance['executive_summary']['status']}\n\n"
                
            if "recommendations" in compliance and "items" in compliance["recommendations"]:
                md += "**Key Recommendations**:\n\n"
                for rec in compliance["recommendations"]["items"][:5]:
                    md += f"- {rec.get('recommendation', '')}\n"
        
        return md

    def _determine_security_status(self, summary):
        """Determine the security status based on findings."""
        severity_counts = summary.get("severity_counts", {})
        critical = severity_counts.get("critical", 0)
        high = severity_counts.get("high", 0)
        
        if critical > 0:
            return "CRITICAL RISK"
        elif high > 5:
            return "HIGH RISK"
        elif high > 0:
            return "MODERATE RISK"
        else:
            return "LOW RISK"

    async def _save_uploaded_files(self, files: List[UploadFile], job_dir: Path) -> List[Path]:
        """Save uploaded files to job directory and get supported files."""
        all_saved_files = []
        
        for i, file in enumerate(files):
            try:
                if not file.filename:
                    continue
                
                logger.info(f"Processing uploaded file: {file.filename}")
                
                # Create file path maintaining directory structure
                safe_filename = file.filename.replace('../', '').replace('..\\', '')
                file_path = job_dir / safe_filename
                file_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Save file content
                content = await file.read()
                logger.info(f"Read {len(content)} bytes from {file.filename}")
                
                with open(file_path, "wb") as f:
                    f.write(content)
                
                all_saved_files.append(file_path)
                await file.seek(0)  # Reset file pointer
                
                logger.info(f"Saved file: {file_path}")
                
            except Exception as e:
                logger.error(f"Error processing file {file.filename}: {e}")
                continue
        
        # Filter supported files
        supported_files = []
        for file_path in all_saved_files:
            if self.file_processor._should_include_file(file_path):
                supported_files.append(file_path)
                logger.info(f"Including supported file: {file_path}")
            else:
                logger.info(f"Excluding unsupported file: {file_path}")
        
        return supported_files

    async def _clone_github_repo(self, github_url: str, job_dir: Path) -> List[Path]:
        """Clone GitHub repository and return file paths."""
        try:
            logger.info(f"Cloning repository: {github_url}")
            repo_dir = job_dir / "repo"
            
            # Clone repository with error handling
            try:
                repo = git.Repo.clone_from(github_url, repo_dir, depth=1)  # Shallow clone
                logger.info(f"Successfully cloned repository to {repo_dir}")
            except git.exc.GitCommandError as e:
                logger.error(f"Git clone failed: {e}")
                raise ValueError(f"Failed to clone repository: {e}")
            
            # Get all supported files
            file_paths = self.file_processor.get_supported_files(repo_dir)
            logger.info(f"Found {len(file_paths)} supported files in repository")
            
            return file_paths
            
        except Exception as e:
            logger.error(f"Failed to clone repository {github_url}: {e}")
            raise
    
    async def create_job_sync(
        self,
        user_id: int,
        files: Optional[List[UploadFile]] = None,
        github_url: Optional[str] = None,
        source_type: str = "upload"
    ) -> str:
        """Create a new analysis job without starting background processing."""
        try:
            job_id = str(uuid.uuid4())
            logger.info(f"Creating job {job_id} for user {user_id}, source_type: {source_type}")
            
            # Create job directory
            job_dir = self.temp_dir / job_id
            job_dir.mkdir(exist_ok=True, parents=True)
            logger.info(f"Created job directory: {job_dir}")
            
            # Process input files
            if source_type == "upload" and files:
                file_paths = await self._save_uploaded_files(files, job_dir)
                logger.info(f"Saved {len(file_paths)} uploaded files")
            elif source_type == "github" and github_url:
                file_paths = await self._clone_github_repo(github_url, job_dir)
                logger.info(f"Cloned repo with {len(file_paths)} files")
            else:
                raise ValueError(f"Invalid source type '{source_type}' or missing files/URL")
            
            if not file_paths:
                logger.warning("No valid files found, creating test file")
                test_file = job_dir / "test.py"
                test_file.write_text("# Test file\nprint('Hello World')")
                file_paths = [test_file]
            
            # Create job record in database
            job_data = {
                "id": job_id,
                "user_id": user_id,
                "source_type": source_type,
                "source_url": github_url,
                "status": "queued",
                "progress": 0.0,
                "files_total": len(file_paths),
                "files_scanned": 0,
                "current_stage": "initializing",
                "active_models": json.dumps([]),
                "created_at": datetime.utcnow()
            }
            
            db_manager.create_job_record(job_data)
            logger.info(f"Created database record for job {job_id}")
            
            # Store job metadata
            self.active_jobs[job_id] = {
                "user_id": user_id,
                "job_dir": job_dir,
                "file_paths": file_paths,
                "status": "queued",
                "created_at": datetime.utcnow(),
                "progress": 0.0,
                "file_count": len(file_paths)
            }
            
            # CRITICAL: Immediately broadcast job creation
            await self._broadcast_job_created(job_data)
            
            logger.info(f"Job {job_id} created successfully with {len(file_paths)} files (sync mode)")
            return job_id
            
        except Exception as e:
            logger.error(f"Failed to create job: {e}")
            logger.error(traceback.format_exc())
            if 'job_dir' in locals() and job_dir.exists():
                shutil.rmtree(job_dir, ignore_errors=True)
            raise

    def process_job_background(self, job_id: str):
        """Background job processor with status broadcasting."""
        try:
            logger.info(f"Starting background processing for job {job_id}")
            
            # Broadcast that job is starting
            asyncio.run(self._broadcast_job_status_change(job_id, "running", {
                "current_stage": "initializing"
            }))
            
            # Update job status in database
            db_manager.update_job_progress(job_id, {
                "status": "running", 
                "current_stage": "initializing"
            })
            
            # Run the async processing in a new event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(self._process_job(job_id))
                loop.close()
            finally:
                asyncio.set_event_loop(None)
                
        except Exception as e:
            logger.error(f"Background job processing failed for {job_id}: {e}")
            logger.error(traceback.format_exc())
            # Update status to failed on error and broadcast
            db_manager.update_job_progress(job_id, {
                "status": "failed",
                "error_message": str(e)
            })
            
            # Broadcast failure
            try:
                asyncio.run(self._broadcast_job_status_change(job_id, "failed", {
                    "error_message": str(e)
                }))
            except Exception as broadcast_error:
                logger.error(f"Failed to broadcast failure for {job_id}: {broadcast_error}")

    async def _update_job_status(
        self, 
        job_id: str, 
        status: str, 
        stage: str, 
        error_message: Optional[str] = None,
        progress: float = None,
        files_scanned: int = None,
        active_models: List[str] = None
    ):
        """Update job status in database and broadcast changes."""
        try:
            if job_id in self.active_jobs:
                job_info = self.active_jobs[job_id]
                job_info["status"] = status
                job_info["current_stage"] = stage
                if progress is not None:
                    job_info["progress"] = progress
                if files_scanned is not None:
                    job_info["files_scanned"] = files_scanned
                if active_models is not None:
                    job_info["active_models"] = active_models
                if error_message:
                    job_info["error_message"] = error_message
            
            # Update database
            update_data = {
                "status": status,
                "current_stage": stage,
                "progress": progress or 0,
                "files_scanned": files_scanned or 0,
                "active_models": json.dumps(active_models or []),
                "error_message": error_message
            }
            
            if status == "completed":
                update_data["completed_at"] = datetime.utcnow()
            
            db_manager.update_job_progress(job_id, update_data)
            
            # Broadcast status change to monitors
            await self._broadcast_job_status_change(job_id, status, {
                "current_stage": stage,
                "progress": progress or 0,
                "files_scanned": files_scanned or 0,
                "active_models": active_models or [],
                "error_message": error_message
            })
            
        except Exception as e:
            logger.error(f"Error updating job status: {e}")

    async def _broadcast_job_status_change(self, job_id: str, status: str, additional_data: dict = None):
        """Broadcast job status changes."""
        try:
            from .websocket_manager import manager as websocket_manager
            
            broadcast_data = {
                "id": job_id,
                "status": status,
                "action": "status_changed"
            }
            
            if additional_data:
                broadcast_data.update(additional_data)
                
            await websocket_manager.broadcast_job_update(broadcast_data)
            logger.debug(f"Broadcasted status change for job {job_id}: {status}")
            
        except Exception as e:
            logger.error(f"Failed to broadcast status change for job {job_id}: {e}")

    def _load_models_config(self) -> dict:
        """Load models configuration from YAML file."""
        try:
            config_path = Path(os.getenv("CONFIG_DIR", "./config")) / "models.yaml"
            with open(config_path, "r") as f:
                config = yaml.safe_load(f)
                logger.info(f"Loaded models config: {config.get('primary_model')}")
                return config
        except Exception as e:
            logger.error(f"Error loading models config: {e}")
            # Return default configuration
            return {
                "primary_model": "deepseek-coder-v2:16b",
                "worker_models": [
                    {"name": "deepseek-coder-v2:16b", "type": "ollama", "weight": 1.0, "enabled": True}
                ],
                "sentinel_model": {"name": "deepseek-coder-v2:16b", "type": "ollama"}
            }
    
    async def get_progress(self, job_id: str, user_id: int) -> Optional[dict]:
        """Get job progress."""
        try:
            job_data = db_manager.get_job_by_id(job_id, user_id)
            if not job_data:
                logger.warning(f"Job {job_id} not found for user {user_id}")
                return None
            
            return {
                "job_id": job_id,
                "status": job_data["status"],
                "progress": job_data["progress"] or 0,
                "files_scanned": job_data["files_scanned"] or 0,
                "total_files": job_data["files_total"] or 0,
                "current_stage": job_data["current_stage"] or "initializing",
                "active_models": json.loads(job_data["active_models"] or "[]"),
                "eta_seconds": job_data["eta_seconds"],
                "error_message": job_data["error_message"]
            }
            
        except Exception as e:
            logger.error(f"Failed to get progress for job {job_id}: {e}")
            return None
    
    async def get_report(self, job_id: str, user_id: int) -> Optional[dict]:
        """Get analysis report for completed job."""
        try:
            job_data = db_manager.get_job_by_id(job_id, user_id)
            if not job_data:
                logger.warning(f"Job {job_id} not found for user {user_id}")
                return None
                
            if job_data["status"] != "completed":
                logger.warning(f"Job {job_id} is not completed, status: {job_data['status']}")
                return None
            
            # Read report files
            report_dir = self.reports_dir / job_id
            report_json_path = report_dir / "analysis_report.json"
            
            if not report_json_path.exists():
                logger.error(f"Report JSON not found for job {job_id} at {report_json_path}")
                return None
            
            with open(report_json_path, "r") as f:
                report_data = json.load(f)
            
            # Include markdown content if available
            report_md_path = report_dir / "final_report.md"
            if report_md_path.exists():
                with open(report_md_path, "r") as f:
                    report_data["markdown_report"] = f.read()
            
            logger.info(f"Successfully loaded report for job {job_id}")
            return report_data
            
        except Exception as e:
            logger.error(f"Failed to get report for job {job_id}: {e}")
            logger.error(traceback.format_exc())
            return None
    
    async def list_jobs(self, user_id: int, limit: int = 50, offset: int = 0) -> List[dict]:
        """List user jobs."""
        try:
            jobs = db_manager.list_user_jobs(user_id, limit, offset)
            logger.info(f"Listed {len(jobs)} jobs for user {user_id}")
            return jobs
        except Exception as e:
            logger.error(f"Failed to list jobs for user {user_id}: {e}")
            return []
    
    async def cancel_job(self, job_id: str, user_id: int) -> bool:
        """Cancel a running job."""
        try:
            job_data = db_manager.get_job_by_id(job_id, user_id)
            if not job_data:
                logger.warning(f"Job {job_id} not found for user {user_id}")
                return False
                
            if job_data["status"] not in ["queued", "running"]:
                logger.warning(f"Job {job_id} cannot be cancelled, status: {job_data['status']}")
                return False
            
            # Update status to cancelled
            await self._update_job_status(job_id, "cancelled", "cancelled")
            
            # Clean up active job
            if job_id in self.active_jobs:
                del self.active_jobs[job_id]
            
            logger.info(f"Job {job_id} cancelled successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cancel job {job_id}: {e}")
            return False
    
    def get_status(self) -> dict:
        """Get job manager status."""
        return {
            "active_jobs": len(self.active_jobs),
            "max_workers": self.max_workers,
            "reports_dir": str(self.reports_dir),
            "temp_dir": str(self.temp_dir)
        }
    
    async def _synthesize_with_main_llm(self, all_model_reports: dict, job_id: str) -> dict:
        """Use main LLM to synthesize all model reports into depth analysis."""
        try:
            # Load fresh config to ensure we have the latest
            self.model_config = self._load_models_config()
            
            # Get the sentinel/main model from config
            sentinel_model = self.model_config.get("sentinel_model", {})
            model_name = sentinel_model.get("name")
            model_type = sentinel_model.get("type", "ollama")
            
            # If no sentinel model configured, use the primary model
            if not model_name:
                model_name = self.model_config.get("primary_model", "deepseek-coder-v2:16b")
                model_type = "ollama"
                logger.warning(f"No sentinel model configured, using primary model: {model_name}")
            
            logger.info(f"Starting main LLM synthesis with {model_name} (type: {model_type})")
            
            # Prepare synthesis context with error handling
            model_summaries = []
            all_file_summaries = {}
            all_overall_analyses = {}
            
            for model_name_key, report in all_model_reports.items():
                try:
                    # Extract enhanced data if available
                    file_summaries = report.get("file_summaries", [])
                    overall_analysis = report.get("overall_analysis", {})
                    
                    if file_summaries:
                        all_file_summaries[model_name_key] = file_summaries
                    if overall_analysis:
                        all_overall_analyses[model_name_key] = overall_analysis
                    
                    # Create summary with safe access
                    model_summaries.append({
                        "model": model_name_key,
                        "total_findings": report.get("total_findings", len(report.get("findings", []))),
                        "high_risk_files": len([s for s in file_summaries if isinstance(s, dict) and s.get("risk_score", 0) >= 7]),
                        "key_issues": overall_analysis.get("systemic_issues", [])[:5] if isinstance(overall_analysis, dict) else [],
                        "risk_areas": overall_analysis.get("risk_areas", [])[:3] if isinstance(overall_analysis, dict) else []
                    })
                except Exception as e:
                    logger.error(f"Error processing report for model {model_name_key}: {e}")
                    continue
            
            # If no model summaries were created, return early with informative message
            if not model_summaries:
                logger.error("No model summaries could be created from reports")
                return self._create_fallback_synthesis(
                    "No model reports could be processed for synthesis. Individual model analyses may still be available.",
                    all_model_reports
                )
            
            # Create a simplified prompt that's less likely to fail
            prompt = self._create_synthesis_prompt(model_summaries, all_overall_analyses, all_file_summaries)
            
            # Create LLM client for synthesis with better error handling
            try:
                from ..worker.llm_client import LLMClientFactory
                
                synthesis_client = LLMClientFactory.create_client(
                    model_name,
                    model_type,
                    sentinel_model.get("api_key_env"),
                    timeout=600
                )
                
                logger.info("LLM client created successfully for synthesis")
                
            except Exception as e:
                logger.error(f"Failed to create LLM client for synthesis: {e}")
                return self._create_fallback_synthesis(
                    f"Could not initialize synthesis model ({model_name}). Using aggregated analysis from individual models.",
                    all_model_reports
                )
            
            # Get synthesis with retry logic
            max_retries = 2
            for attempt in range(max_retries):
                try:
                    logger.info(f"Attempting synthesis (attempt {attempt + 1}/{max_retries})")
                    response = synthesis_client.generate_sync(prompt, temperature=0.2)
                    
                    # Try to parse the response
                    synthesis_data = self._parse_synthesis_response(response)
                    
                    if synthesis_data:
                        logger.info("Synthesis completed successfully")
                        return {
                            "synthesis_model": model_name,
                            "generated_at": datetime.now().isoformat(),
                            **synthesis_data
                        }
                        
                except Exception as e:
                    logger.error(f"Synthesis attempt {attempt + 1} failed: {e}")
                    if attempt < max_retries - 1:
                        await asyncio.sleep(2)  # Brief delay before retry
                    continue
            
            # If all attempts failed, create informative fallback
            logger.error("All synthesis attempts failed, using fallback")
            return self._create_fallback_synthesis(
                "AI synthesis processing encountered an issue. Individual model analyses are still available below.",
                all_model_reports
            )
            
        except Exception as e:
            logger.error(f"Critical error in main LLM synthesis: {e}", exc_info=True)
            return self._create_fallback_synthesis(
                "Unable to complete AI synthesis. Please review individual model reports below.",
                all_model_reports
            )

    # def _create_synthesis_prompt(self, model_summaries, all_overall_analyses, all_file_summaries):
    #     """Create a simplified, more robust synthesis prompt."""
        
    #     # Create a more concise prompt that's less likely to cause parsing issues
    #     prompt = f"""You are the Chief Security Architect. Synthesize the security findings from multiple AI models into executive insights.

    # ANALYSIS SUMMARY:
    # Total Models: {len(model_summaries)}
    # Total Findings Across All Models: {sum(m['total_findings'] for m in model_summaries)}

    # KEY ISSUES BY MODEL:
    # """
        
    #     for summary in model_summaries[:5]:  # Limit to first 5 models
    #         prompt += f"\n{summary['model']}:"
    #         prompt += f"\n  - Findings: {summary['total_findings']}"
    #         prompt += f"\n  - High-risk files: {summary['high_risk_files']}"
    #         if summary['key_issues']:
    #             prompt += f"\n  - Top issues: {', '.join(summary['key_issues'][:3])}"
        
    #     prompt += """

    # Provide a JSON response with the following structure:
    # {
    #     "executive_insights": "2-3 paragraphs summarizing the key security findings and overall code health",
    #     "critical_consensus_findings": [
    #         {
    #             "issue": "Brief description of the issue",
    #             "severity": "critical",
    #             "models_agreed": ["model1", "model2"],
    #             "confidence": 0.9,
    #             "impact": "Brief impact description"
    #         }
    #     ],
    #     "architectural_risks": ["Risk 1", "Risk 2"],
    #     "security_debt_assessment": "One paragraph assessment of technical/security debt",
    #     "prioritized_action_items": [
    #         {
    #             "action": "Specific action to take",
    #             "priority": 1,
    #             "effort": "low",
    #             "impact": "high",
    #             "category": "security"
    #         }
    #     ],
    #     "confidence_analysis": "Brief assessment of the analysis confidence and coverage"
    # }

    # Keep responses concise and actionable. Focus on the most critical findings."""
        
    #     return prompt

# Replace the _create_synthesis_prompt method with this improved version:

    def _create_synthesis_prompt(self, model_summaries, all_overall_analyses, all_file_summaries):
        """Create an improved synthesis prompt that produces better results."""
        
        prompt = f"""You are the Chief Security Architect analyzing security findings from multiple AI models.
    Create a concise, professional security intelligence report that synthesizes all findings.

    ANALYSIS CONTEXT:
    - {len(model_summaries)} AI models analyzed the codebase
    - Each model produced independent security findings
    - Your task is to synthesize these findings into actionable intelligence

    KEY ISSUES BY MODEL:
    """
        
        for summary in model_summaries[:5]:  # Limit to first 5 models
            prompt += f"\n{summary['model']}:"
            prompt += f"\n  - Findings: {summary['total_findings']}"
            prompt += f"\n  - High-risk files: {summary['high_risk_files']}"
            if summary['key_issues']:
                prompt += f"\n  - Top issues: {', '.join(summary['key_issues'][:3])}"
        
        prompt += """

    IMPORTANT GUIDELINES:
    1. DO NOT mention specific total numbers across all models (like "180 total findings" or "66 critical issues")
    2. Instead, describe findings PER MODEL ("Model A found X issues, Model B found Y issues")
    3. For each issue category, combine similar findings from different models
    4. For each prioritized action, include a brief (1-2 line) solution
    5. Focus on impact-based prioritization

    Provide a JSON response with this EXACT structure:
    {
        "executive_insights": "Summary of key insights focusing on per-model findings rather than aggregate totals",
        "critical_consensus_findings": [
            {
                "issue": "Brief description of the issue",
                "severity": "critical/high/medium/low",
                "models_agreed": ["model1", "model2"],
                "confidence": 0.9,
                "impact": "Brief impact description"
            }
        ],
        "architectural_risks": ["Risk 1", "Risk 2", "Risk 3"],
        "security_debt_assessment": "Assessment of technical/security debt",
        "prioritized_action_items": [
            {
                "action": "Specific action to take",
                "priority": 1,
                "effort": "low/medium/high",
                "impact": "high/medium/low",
                "solution": "1-2 line solution guidance"
            }
        ],
        "risk_matrix": {
            "high_impact_low_effort": ["Action 1", "Action 2"],
            "high_impact_high_effort": ["Action 3", "Action 4"],
            "low_impact_low_effort": ["Action 5"],
            "low_impact_high_effort": ["Action 6"]
        },
        "confidence_analysis": "Assessment of the analysis confidence and model coverage"
    }"""
        
        return prompt

    def _parse_synthesis_response(self, response: str) -> dict:
        """Parse LLM synthesis response with better error handling."""
        try:
            # Try to extract JSON from response
            import re
            
            # First, try to find JSON block in markdown
            json_match = re.search(r'```(?:json)?\s*(.*?)\s*```', response, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
            else:
                # Try to find raw JSON
                json_match = re.search(r'\{.*\}', response, re.DOTALL)
                if json_match:
                    json_str = json_match.group(0)
                else:
                    logger.error("No JSON found in synthesis response")
                    return None
            
            # Parse JSON with error handling
            try:
                data = json.loads(json_str)
                
                # Ensure required fields exist with defaults
                return {
                    "executive_insights": data.get("executive_insights", "Security analysis completed. See findings below."),
                    "critical_consensus_findings": data.get("critical_consensus_findings", []),
                    "unique_insights_by_model": data.get("unique_insights_by_model", {}),
                    "architectural_risks": data.get("architectural_risks", []),
                    "security_debt_assessment": data.get("security_debt_assessment", "Assessment pending."),
                    "prioritized_action_items": data.get("prioritized_action_items", []),
                    "risk_matrix": data.get("risk_matrix", {}),
                    "confidence_analysis": data.get("confidence_analysis", "Analysis completed with available models.")
                }
                
            except json.JSONDecodeError as e:
                logger.error(f"JSON parsing failed: {e}")
                logger.debug(f"Attempted to parse: {json_str[:200]}...")
                return None
                
        except Exception as e:
            logger.error(f"Error parsing synthesis response: {e}")
            return None
############
    # def _create_fallback_synthesis(self, message: str, all_model_reports: dict) -> dict:
    #     """Create an informative fallback synthesis when LLM synthesis fails."""
        
    #     # Aggregate findings from all models
    #     all_findings = []
    #     all_severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    #     all_categories = {}
    #     models_used = []
        
    #     for model_name, report in all_model_reports.items():
    #         models_used.append(model_name)
    #         findings = report.get("findings", [])
            
    #         for finding in findings:
    #             if isinstance(finding, dict):
    #                 severity = finding.get("severity", "medium")
    #                 if severity in all_severities:
    #                     all_severities[severity] += 1
                    
    #                 category = finding.get("category", "unknown")
    #                 all_categories[category] = all_categories.get(category, 0) + 1
        
    #     # Create prioritized actions based on severity counts
    #     prioritized_actions = []
    #     action_priority = 1
        
    #     if all_severities["critical"] > 0:
    #         prioritized_actions.append({
    #             "action": f"Address {all_severities['critical']} critical severity vulnerabilities immediately",
    #             "priority": action_priority,
    #             "effort": "high",
    #             "impact": "high",
    #             "category": "critical_vulnerabilities"
    #         })
    #         action_priority += 1
        
    #     if all_severities["high"] > 0:
    #         prioritized_actions.append({
    #             "action": f"Fix {all_severities['high']} high severity issues within this sprint",
    #             "priority": action_priority,
    #             "effort": "medium",
    #             "impact": "high",
    #             "category": "high_vulnerabilities"
    #         })
    #         action_priority += 1
        
    #     # Get top vulnerability categories
    #     top_categories = sorted(all_categories.items(), key=lambda x: x[1], reverse=True)[:3]
    #     for category, count in top_categories:
    #         prioritized_actions.append({
    #             "action": f"Review and remediate {count} {category.replace('_', ' ')} vulnerabilities",
    #             "priority": action_priority,
    #             "effort": "medium",
    #             "impact": "medium",
    #             "category": category
    #         })
    #         action_priority += 1
        
    #     # Create executive insights based on aggregated data
    #     total_findings = sum(all_severities.values())
    #     risk_level = "CRITICAL" if all_severities["critical"] > 0 else \
    #                 "HIGH" if all_severities["high"] > 5 else \
    #                 "MEDIUM" if total_findings > 10 else "LOW"
        
    #     executive_insights = f"""Security analysis completed using {len(models_used)} AI models. {message}

    # The analysis identified {total_findings} total security findings across your codebase. """

    #     if all_severities["critical"] > 0:
    #         executive_insights += f"URGENT: {all_severities['critical']} critical vulnerabilities require immediate attention. "
        
    #     if all_severities["high"] > 0:
    #         executive_insights += f"Additionally, {all_severities['high']} high-severity issues should be addressed promptly. "
        
    #     executive_insights += f"\n\nThe most common vulnerability categories are: {', '.join([cat[0].replace('_', ' ') for cat in top_categories])}. "
    #     executive_insights += "Detailed findings from each model are available in the sections below."
        
    #     return {
    #         "synthesis_model": "aggregation_fallback",
    #         "executive_insights": executive_insights,
    #         "critical_consensus_findings": [],  # Can't determine consensus without synthesis
    #         "unique_insights_by_model": {},
    #         "architectural_risks": [
    #             f"Unable to perform architectural analysis - {message}",
    #             "Review individual model reports for architectural insights"
    #         ],
    #         "security_debt_assessment": f"Security debt assessment unavailable. Based on findings: {total_findings} issues identified, with {all_severities['critical'] + all_severities['high']} requiring urgent attention.",
    #         "prioritized_action_items": prioritized_actions[:7],  # Limit to top 7
    #         "risk_matrix": {
    #             "high_impact_low_effort": [],
    #             "high_impact_high_effort": [f"Fix {all_severities['critical']} critical issues"],
    #             "low_impact_low_effort": [],
    #             "low_impact_high_effort": []
    #         },
    #         "confidence_analysis": f"This is an aggregated summary based on {len(models_used)} model analyses. {message}",
    #         "generated_at": datetime.now().isoformat()
    #     }

# Replace the _create_fallback_synthesis method with this improved version:

    def _create_fallback_synthesis(self, message: str, all_model_reports: dict) -> dict:
        """Create an informative fallback synthesis with model-specific insights."""
        
        # Track findings by model and category
        model_statistics = {}
        all_severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        all_categories = {}
        models_used = []
        model_specific_insights = {}
        
        # Process each model's findings separately
        for model_name, report in all_model_reports.items():
            models_used.append(model_name)
            findings = report.get("findings", [])
            
            # Per-model statistics
            model_statistics[model_name] = {
                "total": len(findings),
                "severities": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "categories": {},
                "files_affected": set()
            }
            
            # Track top issues by model
            top_issues = {}
            
            for finding in findings:
                if isinstance(finding, dict):
                    # Track severity
                    severity = finding.get("severity", "medium")
                    if severity in all_severities:
                        all_severities[severity] += 1
                        model_statistics[model_name]["severities"][severity] += 1
                    
                    # Track category
                    category = finding.get("category", "unknown")
                    all_categories[category] = all_categories.get(category, 0) + 1
                    model_statistics[model_name]["categories"][category] = model_statistics[model_name]["categories"].get(category, 0) + 1
                    
                    # Track affected files
                    if "file" in finding:
                        model_statistics[model_name]["files_affected"].add(finding["file"])
                    
                    # Group by category for issue consolidation
                    issue_key = (category, severity)
                    if issue_key not in top_issues:
                        top_issues[issue_key] = {
                            "category": category,
                            "severity": severity,
                            "count": 0,
                            "example": finding
                        }
                    top_issues[issue_key]["count"] += 1
            
            # Get top 3 issues for this model
            model_specific_insights[model_name] = sorted(
                top_issues.values(),
                key=lambda x: (
                    {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(x["severity"], 0),
                    x["count"]
                ),
                reverse=True
            )[:3]
            
            # Convert file sets to counts
            model_statistics[model_name]["files_affected"] = len(model_statistics[model_name]["files_affected"])
        
        # Create prioritized actions by consolidating findings
        consolidated_issues = self._consolidate_issues_across_models(model_specific_insights)
        prioritized_actions = []
        
        for i, issue in enumerate(consolidated_issues[:7], 1):  # Limit to top 7
            # Create actionable item with solution
            solution = self._get_solution_for_category(issue["category"])
            
            prioritized_actions.append({
                "action": f"Fix {issue['category'].replace('_', ' ')} vulnerabilities ({issue['count']} instances)",
                "priority": i,
                "effort": issue.get("effort", "medium"),
                "impact": self._get_impact_level(issue["severity"]),
                "solution": solution,
                "category": issue["category"],
                "models": issue["models"]
            })
        
        # Create executive insights based on model-specific data
        total_findings = sum(stats["total"] for stats in model_statistics.values())
        unique_findings = sum(all_severities.values())
        
        # Calculate consensus findings
        consensus_findings = []
        for issue in consolidated_issues:
            if len(issue["models"]) > 1:  # Only include issues found by multiple models
                consensus_findings.append({
                    "issue": issue["category"].replace('_', ' '),
                    "severity": issue["severity"],
                    "models_agreed": issue["models"],
                    "confidence": min(0.9, 0.5 + (0.1 * len(issue["models"]))),
                    "impact": self._get_issue_impact(issue["category"])
                })
        
        # Create model-specific insights
        unique_insights = {}
        for model_name, insights in model_specific_insights.items():
            if insights:
                unique_insights[model_name] = [
                    f"{i['category'].replace('_', ' ')} ({i['severity']}): {i['count']} instances"
                    for i in insights
                ]
        
        # Get top vulnerability categories across all models
        top_categories = sorted(all_categories.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Create risk matrix with actionable items
        risk_matrix = {
            "high_impact_low_effort": [],
            "high_impact_high_effort": [],
            "low_impact_low_effort": [],
            "low_impact_high_effort": []
        }
        
        for action in prioritized_actions[:5]:
            impact = "high" if action["impact"] == "high" else "low"
            effort = action["effort"]
            key = f"{impact}_impact_{effort}_effort"
            if key in risk_matrix:
                risk_matrix[key].append(action["action"])
        
        executive_insights = f"""Security analysis completed using {len(models_used)} AI models.
        
    Each model has provided independent security insights for your codebase:"""

        for model_name, stats in model_statistics.items():
            executive_insights += f"\n\n• {model_name}: Found {stats['total']} potential issues"
            crit_high = stats["severities"]["critical"] + stats["severities"]["high"]
            if crit_high > 0:
                executive_insights += f" including {crit_high} critical/high severity findings"
            top_cats = sorted(stats["categories"].items(), key=lambda x: x[1], reverse=True)[:2]
            if top_cats:
                executive_insights += f". Main concerns: {', '.join([c[0].replace('_', ' ') for c in top_cats])}"
        
        # Add synthesis note without specific total numbers
        if consensus_findings:
            executive_insights += f"\n\nMultiple models agreed on {len(consensus_findings)} key security concerns that should be prioritized."
            
        executive_insights += f"\n\nThe most common vulnerability categories are: {', '.join([cat[0].replace('_', ' ') for cat in top_categories])}."
        
        return {
            "synthesis_model": "enhanced_aggregation",
            "executive_insights": executive_insights,
            "critical_consensus_findings": consensus_findings,
            "unique_insights_by_model": unique_insights,
            "architectural_risks": self._derive_architectural_risks(consolidated_issues),
            "security_debt_assessment": self._create_security_debt_assessment(model_statistics, consolidated_issues),
            "prioritized_action_items": prioritized_actions,
            "risk_matrix": risk_matrix,
            "confidence_analysis": f"This analysis synthesizes findings across {len(models_used)} AI models, focusing on areas of consensus.",
            "generated_at": datetime.now().isoformat()
        }

    def _consolidate_issues_across_models(self, model_specific_insights):
        """Consolidate similar issues across multiple models."""
        consolidated = {}
        
        for model_name, issues in model_specific_insights.items():
            for issue in issues:
                # Create a stable key for this issue type
                issue_key = (issue["category"], issue["severity"])
                
                if issue_key not in consolidated:
                    consolidated[issue_key] = {
                        "category": issue["category"],
                        "severity": issue["severity"],
                        "count": 0,
                        "models": [],
                        "effort": self._estimate_remediation_effort(issue["category"])
                    }
                
                consolidated[issue_key]["count"] += issue["count"]
                consolidated[issue_key]["models"].append(model_name)
        
        # Sort by severity then count
        return sorted(
            consolidated.values(),
            key=lambda x: (
                {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(x["severity"], 0),
                x["count"],
                len(x["models"])  # Prioritize issues found by more models
            ),
            reverse=True
        )

    def _get_solution_for_category(self, category):
        """Get a concise solution for a vulnerability category."""
        solutions = {
            "sql_injection": "Implement parameterized queries and input validation",
            "xss": "Sanitize user input and implement Content Security Policy",
            "command_injection": "Use safe APIs instead of shell commands; validate inputs",
            "path_traversal": "Validate file paths and use safe APIs for file access",
            "hardcoded_secrets": "Move secrets to environment variables or secret management",
            "weak_crypto": "Upgrade to modern encryption algorithms and key management",
            "broken_access_control": "Implement proper role-based access control checks",
            "insecure_design": "Conduct threat modeling and security-focused code reviews",
            "outdated_dependencies": "Implement automated dependency scanning and updates",
            "authentication_bypass": "Add multi-factor authentication and session validation",
            "insecure_deserialization": "Validate and sanitize data before deserialization",
            "xxe": "Disable external entity processing in XML parsers",
            "race_condition": "Implement proper locking mechanisms and atomic operations",
            "insecure_file_upload": "Validate file types, scan content, and limit permissions",
            "csrf": "Implement anti-CSRF tokens and same-site cookies",
            "session_fixation": "Generate new session IDs upon authentication changes",
            "information_disclosure": "Audit and minimize sensitive data exposure in responses"
        }
        
        return solutions.get(category, "Follow secure coding best practices for remediation")

    def _get_impact_level(self, severity):
        """Convert severity to impact level."""
        impact_map = {
            "critical": "high", 
            "high": "high", 
            "medium": "medium", 
            "low": "low"
        }
        return impact_map.get(severity, "medium")

    def _get_issue_impact(self, category):
        """Get the impact description for an issue category."""
        impacts = {
            "sql_injection": "Database compromise, data theft, and system takeover",
            "xss": "Client-side attacks, session hijacking, and credential theft",
            "command_injection": "Remote code execution and system compromise",
            "path_traversal": "Unauthorized file access and information disclosure",
            "hardcoded_secrets": "Credential exposure and unauthorized system access",
            "weak_crypto": "Data confidentiality breaches and regulatory violations",
            "broken_access_control": "Unauthorized access to sensitive functionality or data",
            "insecure_design": "Architectural flaws leading to security breaches",
            "outdated_dependencies": "Known vulnerability exploitation",
            "authentication_bypass": "Unauthorized system access and account takeover",
            "insecure_deserialization": "Remote code execution and data tampering",
            "xxe": "Server-side file disclosure and denial of service",
            "race_condition": "Data integrity violations and privilege escalation",
            "insecure_file_upload": "Malicious file execution and server compromise",
            "csrf": "Unauthorized actions performed on behalf of authenticated users",
            "session_fixation": "Session hijacking and account takeover",
            "information_disclosure": "Sensitive data leakage and privacy violations"
        }
        
        return impacts.get(category, "Security compromise depending on vulnerability context")

    def _estimate_remediation_effort(self, category):
        """Estimate the effort required to fix issues in this category."""
        high_effort = ["insecure_design", "broken_access_control", "weak_crypto", "outdated_dependencies"]
        low_effort = ["hardcoded_secrets", "information_disclosure"]
        
        if category in high_effort:
            return "high"
        elif category in low_effort:
            return "low"
        else:
            return "medium"

    def _derive_architectural_risks(self, consolidated_issues):
        """Derive architectural risks from consolidated issues."""
        risks = []
        
        # Map issue categories to architectural risk areas
        architecture_mapping = {
            "sql_injection": "Data layer security architecture",
            "authentication_bypass": "Authentication system architecture",
            "weak_crypto": "Cryptography implementation architecture",
            "broken_access_control": "Access control architecture",
            "insecure_design": "Overall security architecture",
            "hardcoded_secrets": "Secrets management architecture",
            "outdated_dependencies": "Dependency management process",
            "insecure_deserialization": "Data processing architecture"
        }
        
        # Add specific architectural risks based on issues
        for issue in consolidated_issues[:5]:  # Consider top 5 issues
            category = issue["category"]
            if category in architecture_mapping:
                risks.append(f"{architecture_mapping[category]}: Review needed due to {issue['count']} {category.replace('_', ' ')} findings")
        
        # Add general architectural risk if not enough specific ones
        if len(risks) < 3:
            risks.append("Security reviews should be integrated into development lifecycle")
            
        return risks[:5]  # Limit to 5 architectural risks

    def _create_security_debt_assessment(self, model_statistics, consolidated_issues):
        """Create a security debt assessment based on findings."""
        # Count critical and high issues across all models
        critical_high_count = sum(
            stats["severities"]["critical"] + stats["severities"]["high"]
            for stats in model_statistics.values()
        )
        
        # Count affected files
        affected_files = sum(stats["files_affected"] for stats in model_statistics.values())
        
        # Calculate debt based on issue density and severity
        if critical_high_count > 20:
            debt_level = "significant"
        elif critical_high_count > 10:
            debt_level = "moderate"
        elif critical_high_count > 5:
            debt_level = "manageable"
        else:
            debt_level = "minimal"
        
        # Create debt assessment message
        assessment = f"This codebase has {debt_level} security technical debt. "
        
        # Add specific areas of concern
        top_categories = {}
        for issue in consolidated_issues:
            category = issue["category"]
            if category not in top_categories:
                top_categories[category] = issue["count"]
        
        top_categories = sorted(top_categories.items(), key=lambda x: x[1], reverse=True)[:3]
        if top_categories:
            assessment += f"Main areas requiring attention: {', '.join([cat[0].replace('_', ' ') for cat in top_categories])}. "
        
        # Add remediation recommendation
        if debt_level in ["significant", "moderate"]:
            assessment += "Consider dedicating a sprint to security remediation."
        else:
            assessment += "Address issues alongside feature development."
            
        return assessment