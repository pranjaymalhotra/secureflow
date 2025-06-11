"""
SecureFlow Worker CLI Runner

Command-line interface for running individual worker analysis processes.
"""

import os
import sys
import json
import argparse
import logging
import time
from pathlib import Path
from typing import List, Dict, Any

from .llm_client import LLMClient
from .vulnerability_detector import VulnerabilityDetector
from ..scheduler.file_processor import FileProcessor

logger = logging.getLogger(__name__)

def setup_logging(level: str = "INFO"):
    """Setup logging configuration."""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("worker.log", mode="a")
        ]
    )

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="SecureFlow Worker Process")
    
    parser.add_argument(
        "--model", 
        default="auto",
        help="Model name to use for analysis (use 'auto' to load from config)"
    )
    
    parser.add_argument(
        "--job", 
        required=True,
        help="Job ID"
    )
    
    parser.add_argument(
        "--shard", 
        required=True,
        help="Shard directory path"
    )
    
    parser.add_argument(
        "--type", 
        required=True,
        choices=["ollama", "gemini", "openai"],
        help="LLM type"
    )
    
    parser.add_argument(
        "--api-key-env",
        help="Environment variable name for API key"
    )
    
    parser.add_argument(
        "--timeout",
        type=int,
        default=1800,
        help="Worker timeout in seconds (default: 1800)"
    )
    
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level"
    )
    
    return parser.parse_args()

def load_file_list(shard_dir: Path) -> List[Path]:
    """Load list of files to analyze from shard directory."""
    files_manifest = shard_dir / "files.txt"
    
    if not files_manifest.exists():
        raise FileNotFoundError(f"Files manifest not found: {files_manifest}")
    
    file_paths = []
    with open(files_manifest, "r") as f:
        for line in f:
            file_path = Path(line.strip())
            if file_path.exists():
                file_paths.append(file_path)
            else:
                logger.warning(f"File not found: {file_path}")
    
    return file_paths

def run_worker_analysis(
    model_name: str,
    model_type: str,
    job_id: str,
    file_paths: List[Path],
    output_file: Path,
    api_key_env: str = None,
    timeout: int = 1800
) -> Dict[str, Any]:
    """Run enhanced worker analysis with per-file summaries and overall analysis."""
    
    start_time = time.time()
    
    try:
        # Initialize LLM client
        llm_client = LLMClient(
            model_name=model_name,
            model_type=model_type,
            api_key_env=api_key_env,
            timeout=timeout
        )
        
        # Initialize vulnerability detector
        detector = VulnerabilityDetector(llm_client)
        
        # Initialize file processor
        file_processor = FileProcessor()
        
        # Process each file
        all_findings = []
        file_summaries = []
        processed_files = 0
        
        logger.info(f"Starting enhanced analysis of {len(file_paths)} files with model {model_name}")
        
        for file_path in file_paths:
            try:
                logger.debug(f"Analyzing file: {file_path}")
                
                # Read file content
                content = file_processor.read_file_content(file_path)
                if not content or content.startswith("Error reading file"):
                    logger.warning(f"Skipping unreadable file: {file_path}")
                    continue
                
                # Get file info
                file_info = file_processor.get_file_info(file_path)
                
                # Analyze file for vulnerabilities
                findings = detector.analyze_file(
                    file_path=file_path,
                    content=content,
                    file_info=file_info
                )
                
                # Generate file summary
                file_summary = detector.generate_file_summary(
                    file_path=file_path,
                    content=content,
                    findings=findings
                )
                file_summaries.append(file_summary)
                
                all_findings.extend(findings)
                processed_files += 1
                
                logger.debug(f"Found {len(findings)} issues in {file_path}, risk score: {file_summary.get('risk_score', 0)}")
                
            except Exception as e:
                logger.error(f"Error analyzing file {file_path}: {e}")
                continue
        
        # Generate overall analysis
        logger.info("Generating overall codebase analysis...")
        overall_analysis = detector.generate_overall_analysis(
            all_findings=all_findings,
            file_summaries=file_summaries,
            files_analyzed=file_paths[:processed_files]
        )
        
        processing_time = time.time() - start_time
        
        # Prepare enhanced results
        results = {
            "worker": model_name,
            "job_id": job_id,
            "findings": [finding.model_dump() for finding in all_findings],
            "file_summaries": file_summaries,
            "overall_analysis": overall_analysis,
            "metadata": {
                "files_processed": processed_files,
                "total_files": len(file_paths),
                "processing_time_seconds": processing_time,
                "model_type": model_type,
                "timestamp": time.time(),
                "high_risk_files": len([s for s in file_summaries if s.get('risk_score', 0) >= 7]),
                "total_risk_score": sum(s.get('risk_score', 0) for s in file_summaries)
            }
        }
        
        # Save results to output file
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
        
        logger.info(
            f"Worker {model_name} completed enhanced analysis: "
            f"{processed_files}/{len(file_paths)} files, "
            f"{len(all_findings)} findings, "
            f"{len(file_summaries)} file summaries, "
            f"{processing_time:.2f}s"
        )
        
        return results
        
    except Exception as e:
        logger.error(f"Worker analysis failed: {e}")
        # Save error result
        error_result = {
            "worker": model_name,
            "job_id": job_id,
            "findings": [],
            "file_summaries": [],
            "overall_analysis": {},
            "error": str(e),
            "metadata": {
                "files_processed": 0,
                "total_files": len(file_paths),
                "processing_time_seconds": time.time() - start_time,
                "model_type": model_type,
                "timestamp": time.time(),
                "status": "error"
            }
        }
        
        with open(output_file, "w") as f:
            json.dump(error_result, f, indent=2)
        
        raise

def main():
    """Main worker entry point."""
    args = parse_arguments()
    setup_logging(args.log_level)
    
    import yaml
    
    def load_model_config():
        """Load model configuration from YAML file."""
        config_path = Path(os.getenv("CONFIG_DIR", "./config")) / "models.yaml"
        try:
            with open(config_path, "r") as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Error loading model config: {e}")
            return {"primary_model": "deepseek-coder-v2:16b"}
    # Use the configured model if none specified or if "auto" is specified
    if args.model == "auto" or not args.model:
        model_config = load_model_config()
        args.model = model_config.get("primary_model", "deepseek-coder-v2:16b")
        logger.info(f"Using configured model from models.yaml: {args.model}")
    # END OF ADDITION

    try:
        logger.info(f"Starting worker: {args.model} for job {args.job}")
        
        # Validate inputs
        shard_dir = Path(args.shard)
        if not shard_dir.exists():
            raise FileNotFoundError(f"Shard directory not found: {shard_dir}")
        
        # Load file list
        file_paths = load_file_list(shard_dir)
        if not file_paths:
            logger.warning("No files to analyze")
            return 0
        
        # Prepare output file
        output_file = shard_dir / f"{args.model.replace(':', '_')}.json"
        
        # Validate API key if needed
        if args.api_key_env:
            api_key = os.getenv(args.api_key_env)
            if not api_key:
                raise ValueError(f"API key not found in environment variable: {args.api_key_env}")
        
        # Run analysis
        results = run_worker_analysis(
            model_name=args.model,
            model_type=args.type,
            job_id=args.job,
            file_paths=file_paths,
            output_file=output_file,
            api_key_env=args.api_key_env,
            timeout=args.timeout
        )
        
        logger.info(f"Worker completed successfully: {output_file}")
        return 0
        
    except Exception as e:
        logger.error(f"Worker failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())