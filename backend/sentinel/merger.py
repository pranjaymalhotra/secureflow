"""
SecureFlow Enhanced Sentinel Merger

Professional-grade merging with voting mechanism and comprehensive aggregation.
"""

import os
import sys
import json
import argparse
import logging
import yaml
from pathlib import Path
from typing import List, Dict, Any, Tuple, Set
from collections import defaultdict, Counter
from datetime import datetime
import difflib
import hashlib

from ..gateway.models import VulnerabilityFinding, SeverityLevel, DetailedFinding

logger = logging.getLogger(__name__)

class SentinelMerger:
    """Professional merger with voting mechanism and smart aggregation."""
    
    def __init__(self, models_config_path: Path = None):
        self.models_config = self._load_models_config(models_config_path)
        self.confidence_threshold = self.models_config.get("thresholds", {}).get("confidence_minimum", 0.35)
        self.voting_threshold = 0.5  # Percentage of models that must agree
        self.similarity_threshold = 0.75  # For duplicate detection
        self.max_line_distance = 5  # Maximum line distance for grouping
        self.model_weights = self._get_model_weights()
    
    def _load_models_config(self, config_path: Path = None) -> Dict[str, Any]:
        """Load models configuration."""
        try:
            if not config_path:
                config_path = Path(__file__).parent.parent.parent / "config" / "models.yaml"
            
            with open(config_path, "r") as f:
                return yaml.safe_load(f)
                
        except Exception as e:
            logger.error(f"Failed to load models config: {e}")
            return {"thresholds": {"confidence_minimum": 0.35}}
    
    def _get_model_weights(self) -> Dict[str, float]:
        """Get model weights for voting."""
        weights = {}
        for model in self.models_config.get("worker_models", []):
            weights[model["name"]] = model.get("weight", 1.0)
        return weights
    
    def merge_worker_results(self, worker_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Enhanced merge with voting mechanism and comprehensive aggregation."""
        try:
            logger.info(f"Merging results from {len(worker_results)} workers")
            
            # Phase 1: Collect all findings from all models
            all_findings_by_model = defaultdict(list)
            worker_metadata = {}
            
            for result in worker_results:
                worker_name = result.get("worker", "unknown")
                findings = result.get("findings", [])
                metadata = result.get("metadata", {})
                
                worker_metadata[worker_name] = metadata
                
                # Convert findings to VulnerabilityFinding objects
                for finding_data in findings:
                    try:
                        finding = VulnerabilityFinding(**finding_data)
                        all_findings_by_model[worker_name].append(finding)
                    except Exception as e:
                        logger.error(f"Error parsing finding from {worker_name}: {e}")
                        continue
            
            # Phase 2: Show all individual model findings (even low confidence)
            individual_model_summaries = self._create_individual_model_summaries(all_findings_by_model)
            
            # Phase 3: Apply voting mechanism
            voted_findings = self._apply_voting_mechanism(all_findings_by_model)
            
            # Phase 4: Smart deduplication and clustering
            clustered_findings = self._smart_clustering(voted_findings)
            
            # Phase 5: Calculate final confidence with ensemble
            final_findings = self._calculate_ensemble_confidence(clustered_findings)
            
            # Phase 6: Apply minimal filtering (keep most findings)
            filtered_findings = [f for f in final_findings if f.confidence >= self.confidence_threshold]
            
            # Phase 7: Generate comprehensive metadata
            metadata = self._generate_comprehensive_metadata(
                worker_metadata, 
                all_findings_by_model,
                filtered_findings,
                individual_model_summaries
            )
            
            # Phase 8: Generate compliance mapping
            compliance_mapping = self._generate_compliance_mapping(filtered_findings)
            
            return {
                "findings": [f.model_dump() for f in filtered_findings],
                "metadata": metadata,
                "worker_results": worker_metadata,
                "individual_model_findings": individual_model_summaries,
                "voting_results": {
                    "total_unique_issues": len(voted_findings),
                    "consensus_issues": len([f for f in voted_findings if f.get("votes", 0) >= len(all_findings_by_model) * self.voting_threshold]),
                    "disputed_issues": len([f for f in voted_findings if f.get("votes", 0) < len(all_findings_by_model) * self.voting_threshold])
                },
                "compliance_mapping": compliance_mapping,
                "deduplication_stats": {
                    "total_raw_findings": sum(len(findings) for findings in all_findings_by_model.values()),
                    "after_voting": len(voted_findings),
                    "after_clustering": len(clustered_findings),
                    "final_count": len(filtered_findings)
                }
            }
            
        except Exception as e:
            logger.error(f"Error merging worker results: {e}")
            raise
    
    def _create_individual_model_summaries(self, all_findings_by_model: Dict[str, List[VulnerabilityFinding]]) -> Dict[str, Any]:
        """Create summaries of what each model found."""
        summaries = {}
        
        for model_name, findings in all_findings_by_model.items():
            severity_counts = Counter(f.severity.value for f in findings)
            category_counts = Counter(f.category for f in findings)
            
            # Include all findings, even low confidence
            all_issues = []
            for finding in findings:
                all_issues.append({
                    "file": finding.file,
                    "line": finding.line,
                    "category": finding.category,
                    "severity": finding.severity.value,
                    "confidence": finding.confidence,
                    "summary": finding.explanation[:100] + "..." if len(finding.explanation) > 100 else finding.explanation
                })
            
            summaries[model_name] = {
                "total_findings": len(findings),
                "severity_distribution": dict(severity_counts),
                "top_categories": dict(category_counts.most_common(10)),
                "confidence_stats": {
                    "min": min(f.confidence for f in findings) if findings else 0,
                    "max": max(f.confidence for f in findings) if findings else 0,
                    "avg": sum(f.confidence for f in findings) / len(findings) if findings else 0
                },
                "all_findings": all_issues  # Include all findings
            }
        
        return summaries
    
    def _apply_voting_mechanism(self, all_findings_by_model: Dict[str, List[VulnerabilityFinding]]) -> List[Dict[str, Any]]:
        """Apply voting mechanism to validate findings across models."""
        # Create a hash for each unique issue
        issue_votes = defaultdict(lambda: {
            "votes": 0,
            "weighted_votes": 0,
            "models": [],
            "findings": [],
            "confidence_scores": []
        })
        
        for model_name, findings in all_findings_by_model.items():
            model_weight = self.model_weights.get(model_name, 1.0)
            
            for finding in findings:
                # Create a unique key for the issue
                issue_key = self._create_issue_key(finding)
                
                issue_votes[issue_key]["votes"] += 1
                issue_votes[issue_key]["weighted_votes"] += model_weight
                issue_votes[issue_key]["models"].append(model_name)
                issue_votes[issue_key]["findings"].append(finding)
                issue_votes[issue_key]["confidence_scores"].append(finding.confidence)
        
        # Convert to list with voting information
        voted_findings = []
        for issue_key, vote_data in issue_votes.items():
            # Take the finding with highest confidence as representative
            best_finding = max(vote_data["findings"], key=lambda f: f.confidence)
            
            # Calculate consensus confidence
            avg_confidence = sum(vote_data["confidence_scores"]) / len(vote_data["confidence_scores"])
            vote_percentage = vote_data["votes"] / len(all_findings_by_model)
            
            # Boost confidence based on consensus
            if vote_percentage >= 0.8:  # 80% or more models agree
                consensus_boost = 0.2
            elif vote_percentage >= 0.6:  # 60% or more agree
                consensus_boost = 0.1
            elif vote_percentage >= 0.4:  # 40% or more agree
                consensus_boost = 0.05
            else:
                consensus_boost = 0
            
            final_confidence = min(1.0, avg_confidence + consensus_boost)
            
            voted_finding = {
                "finding": best_finding,
                "votes": vote_data["votes"],
                "weighted_votes": vote_data["weighted_votes"],
                "models_agreed": vote_data["models"],
                "vote_percentage": vote_percentage,
                "consensus_confidence": final_confidence,
                "all_findings": vote_data["findings"]
            }
            
            voted_findings.append(voted_finding)
        
        return voted_findings
    
    def _create_issue_key(self, finding: VulnerabilityFinding) -> str:
        """Create a unique key for an issue to enable voting."""
        # Include file, approximate line (within range), and category
        line_group = (finding.line // self.max_line_distance) * self.max_line_distance
        
        # Create a hash of the key components
        key_components = [
            finding.file,
            str(line_group),
            finding.category,
            finding.severity.value
        ]
        
        # Add a portion of the explanation for better uniqueness
        if finding.explanation:
            # Normalize the explanation
            normalized_explanation = finding.explanation.lower().strip()
            # Take first 50 characters
            key_components.append(normalized_explanation[:50])
        
        key_string = "|".join(key_components)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def _smart_clustering(self, voted_findings: List[Dict[str, Any]]) -> List[DetailedFinding]:
        """Smart clustering of similar findings."""
        clusters = []
        
        for voted_finding in voted_findings:
            finding = voted_finding["finding"]
            placed = False
            
            # Try to add to existing cluster
            for cluster in clusters:
                if self._should_cluster(finding, cluster):
                    cluster["findings"].append(voted_finding)
                    placed = True
                    break
            
            # Create new cluster if not placed
            if not placed:
                clusters.append({
                    "representative": finding,
                    "findings": [voted_finding]
                })
        
        # Convert clusters to DetailedFindings
        detailed_findings = []
        for cluster in clusters:
            merged_finding = self._merge_cluster(cluster)
            if merged_finding:
                detailed_findings.append(merged_finding)
        
        return detailed_findings
    
    def _should_cluster(self, finding: VulnerabilityFinding, cluster: Dict[str, Any]) -> bool:
        """Determine if a finding should be added to a cluster."""
        representative = cluster["representative"]
        
        # Must be same file and category
        if finding.file != representative.file or finding.category != representative.category:
            return False
        
        # Check line proximity
        if abs(finding.line - representative.line) > self.max_line_distance:
            return False
        
        # Check explanation similarity
        similarity = self._calculate_text_similarity(finding.explanation, representative.explanation)
        if similarity < self.similarity_threshold:
            return False
        
        return True
    
    def _calculate_text_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity between two text strings."""
        if not text1 or not text2:
            return 0.0
        
        # Normalize texts
        text1 = text1.lower().strip()
        text2 = text2.lower().strip()
        
        # Use difflib sequence matcher
        matcher = difflib.SequenceMatcher(None, text1, text2)
        return matcher.ratio()
    
    def _merge_cluster(self, cluster: Dict[str, Any]) -> DetailedFinding:
        """Merge a cluster of findings into a single detailed finding."""
        all_voted_findings = cluster["findings"]
        
        # Collect all individual findings
        all_findings = []
        all_models = set()
        for voted in all_voted_findings:
            all_findings.extend(voted["all_findings"])
            all_models.update(voted["models_agreed"])
        
        # Sort by confidence
        all_findings.sort(key=lambda f: f.confidence, reverse=True)
        primary_finding = all_findings[0]
        
        # Calculate final confidence
        max_confidence = max(voted["consensus_confidence"] for voted in all_voted_findings)
        
        # Use the most detailed explanation
        best_explanation = max(all_findings, key=lambda f: len(f.explanation)).explanation
        
        # Combine patches
        patches = [f.patch for f in all_findings if f.patch and f.patch.strip()]
        best_patch = max(patches, key=len) if patches else None
        
        # Determine consensus severity
        severity_votes = Counter(f.severity for f in all_findings)
        consensus_severity = severity_votes.most_common(1)[0][0]
        
        # Calculate representative line
        line_sum = sum(f.line for f in all_findings)
        representative_line = line_sum // len(all_findings)
        
        # Collect unique references
        all_references = []
        for finding in all_findings:
            if finding.references:
                all_references.extend(finding.references)
        unique_references = list(set(filter(None, all_references)))[:5]
        
        merged_finding = DetailedFinding(
            file=primary_finding.file,
            line=representative_line,
            category=primary_finding.category,
            severity=consensus_severity,
            confidence=max_confidence,
            explanation=best_explanation,
            patch=best_patch,
            code_snippet=primary_finding.code_snippet,
            references=unique_references,
            found_by=list(all_models)
        )
        
        return merged_finding
    
    def _calculate_ensemble_confidence(self, findings: List[DetailedFinding]) -> List[DetailedFinding]:
        """Calculate ensemble confidence for findings."""
        for finding in findings:
            # Boost confidence based on number of models that found it
            model_count = len(finding.found_by)
            total_models = len(self.model_weights)
            
            if model_count >= total_models * 0.8:
                confidence_boost = 0.15
            elif model_count >= total_models * 0.6:
                confidence_boost = 0.1
            elif model_count >= total_models * 0.4:
                confidence_boost = 0.05
            else:
                confidence_boost = 0
            
            finding.confidence = min(1.0, finding.confidence + confidence_boost)
        
        return findings
    
    def _generate_comprehensive_metadata(
        self,
        worker_metadata: Dict[str, Any],
        all_findings_by_model: Dict[str, List[VulnerabilityFinding]],
        final_findings: List[DetailedFinding],
        individual_summaries: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate comprehensive metadata."""
        
        # Count findings by severity
        severity_counts = Counter(f.severity.value for f in final_findings)
        
        # Calculate risk score
        risk_score = (
            severity_counts.get("critical", 0) * 10 +
            severity_counts.get("high", 0) * 7 +
            severity_counts.get("medium", 0) * 4 +
            severity_counts.get("low", 0) * 2 +
            severity_counts.get("info", 0) * 1
        )
        
        # Determine risk level
        if risk_score >= 50:
            risk_level = "CRITICAL"
        elif risk_score >= 25:
            risk_level = "HIGH"
        elif risk_score >= 10:
            risk_level = "MEDIUM"
        elif risk_score > 0:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"
        
        # Count unique files with issues
        files_with_issues = set(f.file for f in final_findings)
        
        # Calculate model agreement metrics
        consensus_findings = len([f for f in final_findings if len(f.found_by) >= len(all_findings_by_model) * 0.5])
        
        # Top vulnerability categories
        category_counts = Counter(f.category for f in final_findings)
        
        return {
            "analysis_timestamp": datetime.utcnow().isoformat(),
            "total_findings": len(final_findings),
            "severity_counts": dict(severity_counts),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "files_analyzed": sum(m.get("files_processed", 0) for m in worker_metadata.values()),
            "files_with_issues": len(files_with_issues),
            "models_used": list(all_findings_by_model.keys()),
            "model_performance": individual_summaries,
            "consensus_findings": consensus_findings,
            "top_categories": category_counts.most_common(10),
            "confidence_threshold": self.confidence_threshold,
            "voting_threshold": self.voting_threshold,
            "quality_metrics": {
                "average_confidence": sum(f.confidence for f in final_findings) / len(final_findings) if final_findings else 0,
                "high_confidence_findings": len([f for f in final_findings if f.confidence >= 0.8]),
                "model_agreement_rate": consensus_findings / len(final_findings) if final_findings else 0
            }
        }
    
    def _generate_compliance_mapping(self, findings: List[DetailedFinding]) -> Dict[str, Any]:
        """Map findings to compliance standards."""
        compliance_map = {
            "owasp_top_10": defaultdict(list),
            "cwe_top_25": defaultdict(list),
            "pci_dss": defaultdict(list),
            "gdpr": defaultdict(list),
            "hipaa": defaultdict(list),
            "sox": defaultdict(list)
        }
        
        # OWASP mapping
        owasp_mapping = {
            "broken_access_control": "A01:2021",
            "crypto_failures": "A02:2021",
            "weak_crypto": "A02:2021",
            "injection": "A03:2021",
            "sql_injection": "A03:2021",
            "command_injection": "A03:2021",
            "code_injection": "A03:2021",
            "xss": "A03:2021",
            "insecure_design": "A04:2021",
            "security_misconfiguration": "A05:2021",
            "vulnerable_components": "A06:2021",
            "auth_failures": "A07:2021",
            "hardcoded_secrets": "A07:2021",
            "unsafe_deserialization": "A08:2021",
            "insufficient_logging": "A09:2021",
            "ssrf": "A10:2021"
        }
        
        # CWE mapping (simplified)
        cwe_mapping = {
            "sql_injection": "CWE-89",
            "command_injection": "CWE-78",
            "xss": "CWE-79",
            "path_traversal": "CWE-22",
            "hardcoded_secrets": "CWE-798",
            "weak_crypto": "CWE-327",
            "unsafe_deserialization": "CWE-502"
        }
        
        # Map findings
        for finding in findings:
            # OWASP
            if finding.category in owasp_mapping:
                owasp_cat = owasp_mapping[finding.category]
                compliance_map["owasp_top_10"][owasp_cat].append({
                    "file": finding.file,
                    "line": finding.line,
                    "severity": finding.severity.value
                })
            
            # CWE
            if finding.category in cwe_mapping:
                cwe_id = cwe_mapping[finding.category]
                compliance_map["cwe_top_25"][cwe_id].append({
                    "file": finding.file,
                    "line": finding.line,
                    "severity": finding.severity.value
                })
            
            # PCI DSS (payment card related)
            if finding.category in ["hardcoded_secrets", "weak_crypto", "sql_injection"]:
                compliance_map["pci_dss"]["Requirement 6"].append({
                    "issue": finding.category,
                    "file": finding.file
                })
            
            # GDPR (data protection)
            if finding.category in ["insufficient_logging", "weak_crypto", "information_disclosure"]:
                compliance_map["gdpr"]["Article 32"].append({
                    "issue": finding.category,
                    "file": finding.file
                })
        
        # Convert defaultdicts to regular dicts
        for standard in compliance_map:
            compliance_map[standard] = dict(compliance_map[standard])
        
        # Add compliance summary
        compliance_summary = {
            "owasp_coverage": f"{len(compliance_map['owasp_top_10'])} / 10 categories detected",
            "cwe_issues": len([f for findings in compliance_map["cwe_top_25"].values() for f in findings]),
            "pci_dss_violations": len([f for findings in compliance_map["pci_dss"].values() for f in findings]),
            "gdpr_concerns": len([f for findings in compliance_map["gdpr"].values() for f in findings])
        }
        
        return {
            "mapping": compliance_map,
            "summary": compliance_summary
        }

    def generate_enhanced_compliance_report(self, findings: List[DetailedFinding]) -> Dict[str, Any]:
        """Generate enhanced compliance report with detailed analysis."""
        try:
            from .report_generator import ReportGenerator
            
            # Initialize enhanced report generator
            report_generator = ReportGenerator()
            
            # Generate enhanced consensus findings
            enhanced_consensus = report_generator._generate_enhanced_consensus_findings(findings)
            
            # Generate security insights overview
            security_overview = report_generator._generate_security_insights_overview(enhanced_consensus, findings)
            
            # Map findings to compliance standards (use existing compliance_checker)
            compliance_mapping = self._generate_compliance_mapping(findings)
            
            return {
                "enhanced_consensus_findings": enhanced_consensus,
                "security_overview": security_overview,
                "compliance_mapping": compliance_mapping,
                "enhanced_metadata": {
                    "total_consensus_issues": len(enhanced_consensus),
                    "high_priority_issues": len([f for f in enhanced_consensus if f.get("priority") == "High"]),
                    "compliance_frameworks_affected": len(compliance_mapping),
                    "generated_at": datetime.utcnow().isoformat()
                }
            }
        except Exception as e:
            logger.error(f"Error generating enhanced compliance report: {e}")
            return {"error": str(e)}