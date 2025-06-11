"""
SecureFlow Report Service

CLI service for generating final analysis reports.
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path

from ..sentinel.report_generator import ReportGenerator

logger = logging.getLogger(__name__)

def setup_logging(level: str = "INFO"):
    """Setup logging configuration."""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

def load_sentinel_results(job_dir: Path) -> dict:
    """Load merged results from sentinel analysis."""
    try:
        results_file = job_dir / "sentinel_results.json"
        
        if not results_file.exists():
            raise FileNotFoundError(f"Sentinel results not found: {results_file}")
        
        with open(results_file, "r") as f:
            return json.load(f)
            
    except Exception as e:
        logger.error(f"Error loading sentinel results: {e}")
        raise

def main():
    """Main report service entry point."""
    parser = argparse.ArgumentParser(description="SecureFlow Report Service")
    parser.add_argument("--job-dir", required=True, help="Job directory path")
    parser.add_argument("--job-id", required=True, help="Job ID")
    parser.add_argument("--output-dir", required=True, help="Output directory for reports")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    
    args = parser.parse_args()
    
    setup_logging(args.log_level)
    
    try:
        logger.info(f"Starting report generation for job {args.job_id}")
        
        # Validate inputs
        job_dir = Path(args.job_dir)
        if not job_dir.exists():
            raise FileNotFoundError(f"Job directory not found: {job_dir}")
        
        output_dir = Path(args.output_dir) / args.job_id
        
        # Load sentinel results
        sentinel_results = load_sentinel_results(job_dir)
        
        # Initialize report generator
        generator = ReportGenerator()
        
        # Generate reports
        report_files = generator.generate_report(
            merged_results=sentinel_results,
            job_id=args.job_id,
            output_dir=output_dir
        )
        
        logger.info(f"Report generation completed: {report_files}")
        
        # Print report file paths for the caller
        print(json.dumps(report_files))
        
        return 0
        
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())