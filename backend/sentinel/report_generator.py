"""
SecureFlow Enhanced Report Generator

Generates improved security analysis reports with better organization and actionability.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Set

from jinja2 import Template
from ..gateway.models import DetailedFinding, SeverityLevel


logger = logging.getLogger(__name__)

class ReportGenerator:
    """Enhanced report generator with improved formatting and actionability."""
    
    def __init__(self):
        self.markdown_template = self._get_enhanced_markdown_template()
        self.model_config = self._load_model_config()
        self.severity_colors = {
            "critical": "🔴",
            "high": "🟠", 
            "medium": "🟡",
            "low": "🔵",
            "info": "⚪"
        }
    
    def _load_model_config(self):
        """Load model configuration."""
        try:
            from ..worker.llm_client import load_model_config
            return load_model_config()
        except:
            return {"sentinel_model": {"name": "deepseek-coder-v2:16b"}}

    def generate_report(self, merged_results: Dict[str, Any], job_id: str, output_dir: Path) -> Dict[str, str]:
        """Generate comprehensive professional security reports with enhanced insights."""
        try:
            # Ensure output directory exists
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Parse findings and metadata
            findings = [DetailedFinding(**f) for f in merged_results.get("findings", [])]
            metadata = merged_results.get("metadata", {})
            
            # Generate comprehensive analysis components
            executive_dashboard = self._generate_executive_dashboard(findings, metadata)
            security_intelligence = self._generate_security_intelligence_report(findings, merged_results)
            threat_landscape = self._generate_threat_landscape_analysis(findings)
            compliance_assessment = self._generate_compliance_assessment(findings)
            technical_deep_dive = self._generate_technical_deep_dive(findings, metadata)
            remediation_strategy = self._generate_comprehensive_remediation_strategy(findings)
            
            # Enhanced report context
            report_context = {
                "job_id": job_id,
                "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "executive_dashboard": executive_dashboard,
                "security_intelligence": security_intelligence,
                "threat_landscape": threat_landscape,
                "compliance_assessment": compliance_assessment,
                "technical_deep_dive": technical_deep_dive,
                "remediation_strategy": remediation_strategy,
                "metadata": metadata,
                "total_findings": len(findings),
                "report_quality_score": self._calculate_report_quality_score(findings, metadata)
            }
            
            # Generate multiple report formats
            reports_generated = {}
            
            # 1. Executive Summary Report
            executive_report = self._generate_executive_summary_report(report_context)
            exec_file = output_dir / "executive_summary.md"
            with open(exec_file, "w") as f:
                f.write(executive_report)
            reports_generated["executive_summary"] = str(exec_file)
            
            # 2. Technical Security Report
            technical_report = self._generate_technical_security_report(report_context)
            tech_file = output_dir / "technical_security_report.md"
            with open(tech_file, "w") as f:
                f.write(technical_report)
            reports_generated["technical_report"] = str(tech_file)
            
            # 3. Compliance Report
            compliance_report = self._generate_compliance_report_markdown(report_context)
            comp_file = output_dir / "compliance_assessment.md"
            with open(comp_file, "w") as f:
                f.write(compliance_report)
            reports_generated["compliance_report"] = str(comp_file)
            
            # 4. Remediation Playbook
            remediation_playbook = self._generate_remediation_playbook(report_context)
            rem_file = output_dir / "remediation_playbook.md"
            with open(rem_file, "w") as f:
                f.write(remediation_playbook)
            reports_generated["remediation_playbook"] = str(rem_file)
            
            # 5. Enhanced JSON Report with all intelligence
            comprehensive_json = self._generate_comprehensive_json_report(report_context, findings)
            json_file = output_dir / "comprehensive_security_intelligence.json"
            with open(json_file, "w") as f:
                json.dump(comprehensive_json, f, indent=2, default=str)
            reports_generated["json_intelligence"] = str(json_file)
            
            logger.info(f"Professional security reports generated: {list(reports_generated.keys())}")
            return reports_generated
            
        except Exception as e:
            logger.error(f"Error generating professional reports: {e}", exc_info=True)
            raise

    def _identify_critical_consensus(self, findings: List[DetailedFinding]) -> List[Dict[str, Any]]:
        """Identify findings with strong consensus across multiple models."""
        from collections import defaultdict
        
        # Group findings by category
        by_category = defaultdict(list)
        for finding in findings:
            if len(finding.found_by) >= 2:  # Only include findings detected by multiple models
                by_category[finding.category].append(finding)
        
        consensus_items = []
        for category, category_findings in by_category.items():
            # Get count of models that agreed
            model_counts = set()
            for finding in category_findings:
                for model in finding.found_by:
                    model_counts.add(model)
            
            # Calculate average confidence
            avg_confidence = sum(f.confidence for f in category_findings) / len(category_findings)
            
            # Get highest severity finding as example
            example = max(category_findings, key=lambda f: f.severity.value)
            
            consensus_items.append({
                "category": category,
                "detection_count": len(model_counts),
                "models": list(model_counts),
                "confidence": avg_confidence,
                "highest_severity": max(f.severity.value for f in category_findings),
                "finding_count": len(category_findings),
                "example_location": f"{example.file}:{example.line}",
                "impact": self._get_impact_description(category)
            })
        
        # Sort by detection count, highest severity, and confidence
        consensus_items.sort(key=lambda x: (x["detection_count"], x["highest_severity"], x["confidence"]), reverse=True)
        
        return consensus_items

    def _get_impact_description(self, category: str) -> str:
        """Get impact description for a vulnerability category."""
        impact_descriptions = {
            "sql_injection": "Database compromise, unauthorized data access, and full system takeover",
            "unsafe_deserialization": "Remote code execution leading to complete system compromise",
            "code_injection": "Arbitrary code execution with application privileges",
            "hardcoded_secrets": "Credential exposure and unauthorized access",
            "command_injection": "Operating system command execution and server compromise",
            "weak_crypto": "Data breaches and regulatory compliance violations",
            "race_condition": "Data corruption and security control bypass",
            "information_disclosure": "Sensitive data exposure and privacy violations"
        }
        
        return impact_descriptions.get(category, f"Security compromise from {category.replace('_', ' ')} vulnerability")

    def _generate_enhanced_executive_summary(
        self,
        findings: List[DetailedFinding],
        metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate comprehensive executive summary with actionable insights."""
        
        severity_counts = {
            "critical": len([f for f in findings if f.severity == SeverityLevel.CRITICAL]),
            "high": len([f for f in findings if f.severity == SeverityLevel.HIGH]),
            "medium": len([f for f in findings if f.severity == SeverityLevel.MEDIUM]),
            "low": len([f for f in findings if f.severity == SeverityLevel.LOW]),
            "info": len([f for f in findings if f.severity == SeverityLevel.INFO])
        }
        
        # Calculate weighted risk score
        risk_score = (
            severity_counts["critical"] * 10 +
            severity_counts["high"] * 7 +
            severity_counts["medium"] * 4 +
            severity_counts["low"] * 2 +
            severity_counts["info"] * 1
        )
        
        # Determine risk level and recommendations
        if risk_score >= 50:
            risk_level = "CRITICAL"
            risk_description = "Immediate action required - multiple critical vulnerabilities detected"
            time_to_fix = "24-48 hours"
        elif risk_score >= 25:
            risk_level = "HIGH"
            risk_description = "Significant security risks that require prompt attention"
            time_to_fix = "1-2 weeks"
        elif risk_score >= 10:
            risk_level = "MEDIUM"
            risk_description = "Moderate security issues that should be addressed in next sprint"
            time_to_fix = "2-4 weeks"
        elif risk_score > 0:
            risk_level = "LOW"
            risk_description = "Minor security improvements recommended"
            time_to_fix = "Next release cycle"
        else:
            risk_level = "MINIMAL"
            risk_description = "No significant security issues detected"
            time_to_fix = "N/A"
        
        # Identify priority files
        file_risk_scores = {}
        for finding in findings:
            file_path = finding.file
            severity_weight = {
                SeverityLevel.CRITICAL: 10,
                SeverityLevel.HIGH: 7,
                SeverityLevel.MEDIUM: 4,
                SeverityLevel.LOW: 2,
                SeverityLevel.INFO: 1
            }
            file_risk_scores[file_path] = file_risk_scores.get(file_path, 0) + severity_weight[finding.severity]
        
        priority_files = sorted(file_risk_scores.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Get top vulnerability categories with business impact
        category_analysis = self._analyze_vulnerability_categories(findings)
        
        # Calculate confidence and consensus metrics
        avg_confidence = sum(f.confidence for f in findings) / len(findings) if findings else 0
        consensus_findings = len([f for f in findings if len(f.found_by) >= 2])
        consensus_rate = consensus_findings / len(findings) if findings else 0
        
        return {
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_description": risk_description,
            "time_to_fix": time_to_fix,
            "files_analyzed": metadata.get("files_analyzed", 0),
            "files_with_issues": len(set(f.file for f in findings)),
            "priority_files": priority_files,
            "processing_time": metadata.get("total_processing_time_seconds", 0),
            "models_used": metadata.get("models_used", []),
            "category_analysis": category_analysis,
            "confidence_metrics": {
                "average_confidence": round(avg_confidence, 3),
                "high_confidence_findings": len([f for f in findings if f.confidence >= 0.8]),
                "consensus_findings": consensus_findings,
                "consensus_rate": round(consensus_rate, 3)
            }
        }
    
    def _analyze_vulnerability_categories(self, findings: List[DetailedFinding]) -> List[Dict[str, Any]]:
        """Analyze vulnerability categories with business impact assessment."""
        category_data = {}
        
        # Business impact mapping
        impact_mapping = {
            "sql_injection": {
                "business_impact": "Data breach, financial loss, regulatory compliance issues",
                "exploit_difficulty": "Easy",
                "priority": "Critical"
            },
            "command_injection": {
                "business_impact": "System compromise, data theft, service disruption",
                "exploit_difficulty": "Medium",
                "priority": "Critical"
            },
            "xss": {
                "business_impact": "User account compromise, data theft, reputation damage",
                "exploit_difficulty": "Easy",
                "priority": "High"
            },
            "hardcoded_secrets": {
                "business_impact": "Unauthorized access, data breach, service compromise",
                "exploit_difficulty": "Easy",
                "priority": "Critical"
            },
            "path_traversal": {
                "business_impact": "Unauthorized file access, information disclosure",
                "exploit_difficulty": "Medium",
                "priority": "High"
            },
            "weak_crypto": {
                "business_impact": "Data encryption compromise, regulatory compliance issues",
                "exploit_difficulty": "Hard",
                "priority": "Medium"
            }
        }
        
        for finding in findings:
            category = finding.category
            if category not in category_data:
                category_data[category] = {
                    "count": 0,
                    "max_severity": finding.severity,
                    "files": set(),
                    "avg_confidence": 0,
                    "confidences": []
                }
            
            category_data[category]["count"] += 1
            category_data[category]["files"].add(finding.file)
            category_data[category]["confidences"].append(finding.confidence)
            
            # Update max severity
            severity_order = [SeverityLevel.INFO, SeverityLevel.LOW, SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL]
            if severity_order.index(finding.severity) > severity_order.index(category_data[category]["max_severity"]):
                category_data[category]["max_severity"] = finding.severity
        
        # Convert to list with business impact
        category_list = []
        for category, data in category_data.items():
            data["avg_confidence"] = sum(data["confidences"]) / len(data["confidences"])
            data["file_count"] = len(data["files"])
            data.pop("files")  # Remove set for JSON serialization
            data.pop("confidences")
            
            # Add business impact information
            impact_info = impact_mapping.get(category, {
                "business_impact": "Potential security risk requiring assessment",
                "exploit_difficulty": "Unknown",
                "priority": "Medium"
            })
            
            category_list.append({
                "category": category,
                "display_name": category.replace("_", " ").title(),
                **data,
                **impact_info
            })
        
        # Sort by count and severity
        category_list.sort(key=lambda x: (x["count"], x["max_severity"].value), reverse=True)
        return category_list[:10]  # Top 10 categories
    
    def _generate_findings_analysis(self, findings: List[DetailedFinding]) -> Dict[str, Any]:
        """Generate structured findings analysis."""
        
        # Group findings by severity for detailed analysis
        findings_by_severity = {
            "critical": [f for f in findings if f.severity == SeverityLevel.CRITICAL],
            "high": [f for f in findings if f.severity == SeverityLevel.HIGH],
            "medium": [f for f in findings if f.severity == SeverityLevel.MEDIUM],
            "low": [f for f in findings if f.severity == SeverityLevel.LOW],
            "info": [f for f in findings if f.severity == SeverityLevel.INFO]
        }
        
        # Generate detailed analysis for each severity
        severity_analysis = {}
        for severity, severity_findings in findings_by_severity.items():
            if not severity_findings:
                continue
            
            # Group by category within severity
            category_groups = {}
            for finding in severity_findings:
                category = finding.category
                if category not in category_groups:
                    category_groups[category] = []
                category_groups[category].append(finding)
            
            severity_analysis[severity] = {
                "count": len(severity_findings),
                "categories": category_groups,
                "files_affected": list(set(f.file for f in severity_findings)),
                "avg_confidence": sum(f.confidence for f in severity_findings) / len(severity_findings),
                "consensus_findings": len([f for f in severity_findings if len(f.found_by) >= 2])
            }
        
        return severity_analysis
    
    def _generate_actionable_recommendations(
        self,
        findings: List[DetailedFinding],
        metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate specific, actionable recommendations."""
        
        immediate_actions = []
        short_term_actions = []
        long_term_actions = []
        
        # Immediate actions (Critical & High severity)
        critical_high = [f for f in findings if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]]
        
        if critical_high:
            immediate_actions.extend([
                {
                    "action": "Patch Critical Vulnerabilities",
                    "description": f"Address {len([f for f in critical_high if f.severity == SeverityLevel.CRITICAL])} critical vulnerabilities immediately",
                    "timeline": "24-48 hours",
                    "files": list(set(f.file for f in critical_high if f.severity == SeverityLevel.CRITICAL))[:5]
                },
                {
                    "action": "Security Code Review",
                    "description": "Conduct thorough security review of all affected files",
                    "timeline": "Within 1 week",
                    "files": list(set(f.file for f in critical_high))[:10]
                }
            ])
        
        # Short-term actions
        medium_findings = [f for f in findings if f.severity == SeverityLevel.MEDIUM]
        if medium_findings:
            short_term_actions.append({
                "action": "Address Medium Priority Issues",
                "description": f"Fix {len(medium_findings)} medium severity vulnerabilities",
                "timeline": "2-4 weeks",
                "categories": list(set(f.category for f in medium_findings))
            })
        
        # Long-term actions (always applicable)
        long_term_actions.extend([
            {
                "action": "Implement Automated Security Testing",
                "description": "Integrate SAST/DAST tools into CI/CD pipeline",
                "timeline": "1-2 months",
                "benefit": "Prevent future vulnerabilities"
            },
            {
                "action": "Security Training Program",
                "description": "Conduct secure coding training for development team",
                "timeline": "Ongoing",
                "benefit": "Reduce vulnerability introduction rate"
            },
            {
                "action": "Dependency Management",
                "description": "Implement automated dependency vulnerability scanning",
                "timeline": "1 month",
                "benefit": "Keep third-party components secure"
            }
        ])
        
        # Generate category-specific recommendations
        category_recommendations = self._generate_category_recommendations(findings)
        
        return {
            "immediate_actions": immediate_actions,
            "short_term_actions": short_term_actions,
            "long_term_actions": long_term_actions,
            "category_specific": category_recommendations,
            "compliance_considerations": self._get_compliance_recommendations(findings)
        }
    
    def _generate_category_recommendations(self, findings: List[DetailedFinding]) -> List[Dict[str, Any]]:
        """Generate recommendations specific to vulnerability categories found."""
        category_counts = {}
        for finding in findings:
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1
        
        recommendations = []
        
        if "sql_injection" in category_counts:
            recommendations.append({
                "category": "SQL Injection",
                "finding_count": category_counts["sql_injection"],
                "recommendation": "Implement parameterized queries and input validation",
                "tools": ["SQLAlchemy (Python)", "Prepared Statements", "ORM frameworks"],
                "priority": "Critical"
            })
        
        if "xss" in category_counts:
            recommendations.append({
                "category": "Cross-Site Scripting",
                "finding_count": category_counts["xss"],
                "recommendation": "Implement output encoding and Content Security Policy",
                "tools": ["DOMPurify", "CSP headers", "Template engines with auto-escaping"],
                "priority": "High"
            })
        
        if "hardcoded_secrets" in category_counts:
            recommendations.append({
                "category": "Hardcoded Secrets",
                "finding_count": category_counts["hardcoded_secrets"],
                "recommendation": "Use environment variables and secret management systems",
                "tools": ["HashiCorp Vault", "AWS Secrets Manager", "Azure Key Vault"],
                "priority": "Critical"
            })
        
        return recommendations
    
    def _get_compliance_recommendations(self, findings: List[DetailedFinding]) -> List[str]:
        """Get compliance-related recommendations based on findings."""
        recommendations = []
        
        critical_high_count = len([f for f in findings if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]])
        
        if critical_high_count > 0:
            recommendations.extend([
                "Document all security vulnerabilities for compliance audits",
                "Implement remediation tracking with timeline documentation",
                "Consider penetration testing to validate fixes"
            ])
        
        if any("sql_injection" in f.category for f in findings):
            recommendations.append("Ensure database security aligns with PCI DSS requirements if processing payment data")
        
        if any("xss" in f.category for f in findings):
            recommendations.append("Review web application security controls for OWASP compliance")
        
        return recommendations
    
    def _generate_quality_metrics(self, merged_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate quality metrics for the analysis."""
        metadata = merged_results.get("metadata", {})
        dedup_stats = merged_results.get("deduplication_stats", {})
        
        return {
            "analysis_quality": {
                "models_used": len(metadata.get("models_used", [])),
                "confidence_threshold": metadata.get("confidence_threshold", 0.4),
                "average_confidence": metadata.get("average_confidence", 0),
                "consensus_rate": metadata.get("model_agreement_rate", 0)
            },
            "deduplication_metrics": {
                "original_findings": dedup_stats.get("original_count", 0),
                "deduplicated_findings": dedup_stats.get("deduplicated_count", 0),
                "final_findings": dedup_stats.get("final_count", 0),
                "false_positives_filtered": dedup_stats.get("false_positive_filtered", 0)
            },
            "processing_metrics": {
                "total_time_seconds": metadata.get("total_processing_time_seconds", 0),
                "files_analyzed": metadata.get("files_analyzed", 0),
                "worker_count": metadata.get("worker_count", 0)
            }
        }
    
    def _generate_enhanced_markdown_report(self, context: Dict[str, Any]) -> str:
        """Generate enhanced Markdown report content."""
        template = Template(self.markdown_template)
        return template.render(**context)
    
    def _generate_enhanced_json_report(
        self,
        context: Dict[str, Any],
        findings: List[DetailedFinding]
    ) -> Dict[str, Any]:
        """Generate enhanced JSON report structure."""
        return {
            "report_metadata": {
                "job_id": context["job_id"],
                "generated_at": context["generated_at"],
                "report_version": "2.0",
                "report_type": "enhanced_security_analysis"
            },
            "executive_summary": context["executive_summary"],
            "findings_analysis": context["findings_analysis"],
            "recommendations": context["recommendations"],
            "quality_metrics": context["quality_metrics"],
            "detailed_findings": [f.model_dump() for f in findings],
            "analysis_metadata": context["metadata"]
        }
    
    def _get_enhanced_markdown_template(self) -> str:
        """Get enhanced Markdown report template."""
        return """# 🛡️ SecureFlow Security Analysis Report

**Job ID:** {{ job_id }}  
**Generated:** {{ generated_at }}  
**Analysis Models:** {{ metadata.models_used | join(', ') }}  
**Processing Time:** {{ "%.1f"|format(metadata.total_processing_time_seconds) }} seconds

---

## 📊 Executive Summary

### {{ severity_colors[executive_summary.risk_level.lower()] }} Security Posture: **{{ executive_summary.risk_level }}**

{{ executive_summary.risk_description }}

| Metric | Value | Status |
|--------|-------|--------|
| **Total Findings** | {{ executive_summary.total_findings }} | {% if executive_summary.total_findings == 0 %}✅ Clean{% elif executive_summary.total_findings < 10 %}⚠️ Monitor{% else %}🚨 Action Needed{% endif %} |
| **Risk Score** | {{ executive_summary.risk_score }}/100 | {% if executive_summary.risk_score < 10 %}✅ Low{% elif executive_summary.risk_score < 25 %}⚠️ Medium{% elif executive_summary.risk_score < 50 %}🚨 High{% else %}🔥 Critical{% endif %} |
| **Files Analyzed** | {{ executive_summary.files_analyzed }} | ℹ️ Coverage |
| **Files with Issues** | {{ executive_summary.files_with_issues }} | {% if executive_summary.files_with_issues == 0 %}✅ Clean{% else %}⚠️ Review Needed{% endif %} |
| **Recommended Timeline** | {{ executive_summary.time_to_fix }} | ⏰ Deadline |

### 📈 Findings by Severity

| Severity | Count | Business Impact | Action Required |
|----------|-------|-----------------|-----------------|
| {{ severity_colors.critical }} **Critical** | {{ executive_summary.severity_counts.critical }} | System compromise, data breach | Immediate (24-48h) |
| {{ severity_colors.high }} **High** | {{ executive_summary.severity_counts.high }} | Significant security risk | This week |
| {{ severity_colors.medium }} **Medium** | {{ executive_summary.severity_counts.medium }} | Moderate security improvement | Next sprint |
| {{ severity_colors.low }} **Low** | {{ executive_summary.severity_counts.low }} | Minor security enhancement | Next release |
| {{ severity_colors.info }} **Info** | {{ executive_summary.severity_counts.info }} | Best practice recommendation | Future consideration |

### 🎯 Top Vulnerability Categories

{% for category in executive_summary.category_analysis[:5] %}
#### {{ loop.index }}. {{ category.display_name }}
- **Count:** {{ category.count }} finding(s) across {{ category.file_count }} file(s)
- **Max Severity:** {{ severity_colors[category.max_severity.value] }} {{ category.max_severity.value.title() }}
- **Business Impact:** {{ category.business_impact }}
- **Exploit Difficulty:** {{ category.exploit_difficulty }}
- **Average Confidence:** {{ "%.1f"|format(category.avg_confidence * 100) }}%

{% endfor %}

---

## 🚨 Critical Action Items

{% if executive_summary.severity_counts.critical > 0 or executive_summary.severity_counts.high > 0 %}
### Immediate Actions (Next 24-48 Hours)

{% for action in recommendations.immediate_actions %}
#### {{ loop.index }}. {{ action.action }}
**Timeline:** {{ action.timeline }}  
**Description:** {{ action.description }}

{% if action.files %}
**Affected Files:**
{% for file in action.files %}
- `{{ file }}`
{% endfor %}
{% endif %}

---
{% endfor %}

### Short-term Actions (1-4 Weeks)

{% for action in recommendations.short_term_actions %}
#### {{ action.action }}
**Timeline:** {{ action.timeline }}  
**Description:** {{ action.description }}

{% if action.categories %}
**Categories:** {{ action.categories | join(', ') }}
{% endif %}

{% endfor %}
{% else %}
### ✅ No Critical Issues Found

Great job! No critical or high-severity vulnerabilities were detected. Continue with the long-term security improvements below.
{% endif %}

---

## 📋 Detailed Findings Analysis

{% for severity, findings_data in findings_analysis.items() %}
{% if findings_data %}
### {{ severity_colors[severity] }} {{ severity.title() }} Severity Issues ({{ findings_data.count }})

**Files Affected:** {{ findings_data.files_affected | length }}  
**Average Confidence:** {{ "%.1f"|format(findings_data.avg_confidence * 100) }}%  
**Multi-model Consensus:** {{ findings_data.consensus_findings }} finding(s)

{% for category, category_findings in findings_data.categories.items() %}
#### {{ category.replace('_', ' ').title() }} ({{ category_findings | length }} finding(s))

{% for finding in category_findings[:3] %}
##### {{ loop.index }}. {{ finding.file }}:{{ finding.line }}

**Confidence:** {{ "%.1f"|format(finding.confidence * 100) }}%  
**Found by:** {{ finding.found_by | join(', ') }}

**Description:**  
{{ finding.explanation }}

{% if finding.code_snippet %}
**Code Context:**
```
{{ finding.code_snippet }}
```
{% endif %}

{% if finding.patch %}
**Recommended Fix:**  
{{ finding.patch }}
{% endif %}

{% if finding.references %}
**References:**
{% for ref in finding.references %}
- [{{ ref }}]({{ ref }})
{% endfor %}
{% endif %}

---
{% endfor %}
{% if category_findings | length > 3 %}
*... and {{ category_findings | length - 3 }} more {{ category.replace('_', ' ') }} finding(s)*
{% endif %}

{% endfor %}
{% endif %}
{% endfor %}

---

## 🔧 Remediation Recommendations

### Category-Specific Recommendations

{% for rec in recommendations.category_specific %}
#### {{ rec.category }} ({{ rec.finding_count }} finding(s))
**Priority:** {{ rec.priority }}

**Recommendation:** {{ rec.recommendation }}

**Suggested Tools:**
{% for tool in rec.tools %}
- {{ tool }}
{% endfor %}

---
{% endfor %}

### Long-term Security Strategy

{% for action in recommendations.long_term_actions %}
#### {{ action.action }}
**Timeline:** {{ action.timeline }}  
**Description:** {{ action.description }}  
**Benefit:** {{ action.benefit }}

{% endfor %}

{% if recommendations.compliance_considerations %}
### Compliance Considerations

{% for consideration in recommendations.compliance_considerations %}
- {{ consideration }}
{% endfor %}
{% endif %}

---

## 📊 Analysis Quality Metrics

### Model Performance
- **Models Used:** {{ quality_metrics.analysis_quality.models_used }}
- **Confidence Threshold:** {{ quality_metrics.analysis_quality.confidence_threshold }}
- **Average Confidence:** {{ "%.1f"|format(quality_metrics.analysis_quality.average_confidence * 100) }}%
- **Multi-model Agreement:** {{ "%.1f"|format(quality_metrics.analysis_quality.consensus_rate * 100) }}%

### Deduplication Effectiveness
- **Original Findings:** {{ quality_metrics.deduplication_metrics.original_findings }}
- **After Deduplication:** {{ quality_metrics.deduplication_metrics.deduplicated_findings }}
- **Final High-Quality Findings:** {{ quality_metrics.deduplication_metrics.final_findings }}
- **False Positives Filtered:** {{ quality_metrics.deduplication_metrics.false_positives_filtered }}

### Processing Efficiency
- **Total Processing Time:** {{ "%.1f"|format(quality_metrics.processing_metrics.total_time_seconds) }} seconds
- **Files per Second:** {{ "%.1f"|format(quality_metrics.processing_metrics.files_analyzed / quality_metrics.processing_metrics.total_time_seconds) if quality_metrics.processing_metrics.total_time_seconds > 0 else 0 }}
- **Worker Processes:** {{ quality_metrics.processing_metrics.worker_count }}

---

## 📋 Next Steps Checklist

### Immediate (24-48 hours)
{% for action in recommendations.immediate_actions %}
- [ ] {{ action.action }}
{% endfor %}

### Short-term (1-4 weeks)
{% for action in recommendations.short_term_actions %}
- [ ] {{ action.action }}
{% endfor %}

### Long-term (1-6 months)
{% for action in recommendations.long_term_actions %}
- [ ] {{ action.action }}
{% endfor %}

---

## 📞 Support & Resources

- **OWASP Top 10:** [https://owasp.org/www-project-top-ten/](https://owasp.org/www-project-top-ten/)
- **SANS Secure Coding:** [https://www.sans.org/secure-coding/](https://www.sans.org/secure-coding/)
- **CWE Database:** [https://cwe.mitre.org/](https://cwe.mitre.org/)

---

*This report was generated by SecureFlow v2.0 - Enhanced AI-driven security analysis platform*  
*Report confidence level: {{ "%.1f"|format(quality_metrics.analysis_quality.average_confidence * 100) }}% | Analysis time: {{ "%.1f"|format(quality_metrics.processing_metrics.total_time_seconds) }}s*
"""

    def _generate_executive_summary(
        self,
        findings: List[DetailedFinding],
        metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate enhanced executive summary with business impact focus."""
        
        severity_counts = {
            "critical": len([f for f in findings if f.severity == SeverityLevel.CRITICAL]),
            "high": len([f for f in findings if f.severity == SeverityLevel.HIGH]),
            "medium": len([f for f in findings if f.severity == SeverityLevel.MEDIUM]),
            "low": len([f for f in findings if f.severity == SeverityLevel.LOW]),
            "info": len([f for f in findings if f.severity == SeverityLevel.INFO])
        }
        
        # Enhanced risk scoring based on research
        risk_score = (
            severity_counts["critical"] * 15 +  # Increased weight
            severity_counts["high"] * 10 +      # Increased weight
            severity_counts["medium"] * 5 +
            severity_counts["low"] * 2 +
            severity_counts["info"] * 1
        )
        
        # Enhanced risk level determination
        if risk_score >= 30:  # Lowered threshold for critical
            risk_level = "CRITICAL"
            risk_description = "Immediate security action required - system is at high risk of compromise"
            time_to_fix = "24-48 hours"
            business_impact = "High risk of data breach, system compromise, or regulatory penalties"
        elif risk_score >= 15:  # Lowered threshold
            risk_level = "HIGH"
            risk_description = "Significant security vulnerabilities require prompt remediation"
            time_to_fix = "1 week"
            business_impact = "Moderate risk of security incidents and compliance issues"
        elif risk_score >= 8:
            risk_level = "MEDIUM"
            risk_description = "Security improvements needed to maintain secure posture"
            time_to_fix = "2-4 weeks"
            business_impact = "Low to moderate risk of security issues"
        elif risk_score > 0:
            risk_level = "LOW"
            risk_description = "Minor security enhancements recommended"
            time_to_fix = "Next release cycle"
            business_impact = "Minimal immediate risk"
        else:
            risk_level = "SECURE"
            risk_description = "No significant security issues detected"
            time_to_fix = "N/A"
            business_impact = "Current security posture appears adequate"
        
        # Enhanced file analysis
        files_with_issues = set(f.file for f in findings)
        
        # Critical file identification
        critical_files = []
        for file_path in files_with_issues:
            file_findings = [f for f in findings if f.file == file_path]
            critical_count = len([f for f in file_findings if f.severity == SeverityLevel.CRITICAL])
            high_count = len([f for f in file_findings if f.severity == SeverityLevel.HIGH])
            
            if critical_count > 0 or high_count >= 2:
                critical_files.append({
                    "file": file_path,
                    "critical_issues": critical_count,
                    "high_issues": high_count,
                    "total_issues": len(file_findings)
                })
        
        # Enhanced category analysis with business context
        category_analysis = self._analyze_categories_with_business_impact(findings)
        
        # Confidence and consensus metrics
        if findings:
            avg_confidence = sum(f.confidence for f in findings) / len(findings)
            high_confidence_count = len([f for f in findings if f.confidence >= 0.8])
            consensus_findings = len([f for f in findings if len(f.found_by) >= 2])
        else:
            avg_confidence = 0
            high_confidence_count = 0
            consensus_findings = 0
        
        return {
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_description": risk_description,
            "business_impact": business_impact,
            "time_to_fix": time_to_fix,
            "files_analyzed": metadata.get("files_analyzed", 0),
            "files_with_issues": len(files_with_issues),
            "critical_files": critical_files[:15],  # Top 15 critical files
            "processing_time": metadata.get("total_processing_time_seconds", 0),
            "models_used": metadata.get("models_used", []),
            "category_analysis": category_analysis,
            "confidence_metrics": {
                "average_confidence": round(avg_confidence, 3),
                "high_confidence_findings": high_confidence_count,
                "consensus_findings": consensus_findings,
                "analysis_quality": "High" if avg_confidence > 0.7 else "Medium" if avg_confidence > 0.5 else "Low"
            },
            "immediate_actions_needed": self._get_immediate_actions(findings),
            "compliance_impact": self._assess_compliance_impact(findings)
        }

    def _analyze_categories_with_business_impact(self, findings: List[DetailedFinding]) -> List[Dict[str, Any]]:
        """Enhanced category analysis with business impact assessment."""
        
        category_data = {}
        
        # Enhanced business impact mapping based on research
        business_impact_map = {
            "sql_injection": {
                "business_impact": "Critical - Complete database compromise, data theft, regulatory fines",
                "attack_complexity": "Low - Easily exploitable via web forms",
                "detection_difficulty": "Medium - May go unnoticed for extended periods",
                "remediation_cost": "Low - Parameterized queries are straightforward to implement"
            },
            "command_injection": {
                "business_impact": "Critical - Full system control, data theft, service disruption",
                "attack_complexity": "Medium - Requires system access but highly damaging",
                "detection_difficulty": "High - System-level attacks are harder to detect",
                "remediation_cost": "Medium - Requires input validation and sandboxing"
            },
            "xss": {
                "business_impact": "High - User account takeover, session hijacking, reputation damage",
                "attack_complexity": "Low - Common attack vector via user inputs",
                "detection_difficulty": "Low - Usually detected quickly by users",
                "remediation_cost": "Low - Output encoding and CSP headers"
            },
            "hardcoded_secrets": {
                "business_impact": "Critical - Unauthorized system access, data breaches",
                "attack_complexity": "Low - Secrets easily found in code repositories",
                "detection_difficulty": "Medium - May remain hidden until discovered",
                "remediation_cost": "Medium - Requires secret management system implementation"
            },
            "weak_crypto": {
                "business_impact": "High - Data encryption bypass, regulatory compliance violations",
                "attack_complexity": "High - Requires cryptographic expertise",
                "detection_difficulty": "High - Difficult to detect without specialized tools",
                "remediation_cost": "Medium - Update to modern algorithms"
            }
        }
        
        for finding in findings:
            category = finding.category
            if category not in category_data:
                category_data[category] = {
                    "count": 0,
                    "max_severity": finding.severity,
                    "files": set(),
                    "confidences": [],
                    "avg_confidence": 0
                }
            
            category_data[category]["count"] += 1
            category_data[category]["files"].add(finding.file)
            category_data[category]["confidences"].append(finding.confidence)
            
            # Update max severity
            severity_order = [SeverityLevel.INFO, SeverityLevel.LOW, SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL]
            if severity_order.index(finding.severity) > severity_order.index(category_data[category]["max_severity"]):
                category_data[category]["max_severity"] = finding.severity
        
        # Convert to enhanced analysis list
        category_list = []
        for category, data in category_data.items():
            data["avg_confidence"] = sum(data["confidences"]) / len(data["confidences"])
            data["file_count"] = len(data["files"])
            
            # Add business impact information
            impact_info = business_impact_map.get(category, {
                "business_impact": "Potential security risk requiring assessment",
                "attack_complexity": "Unknown",
                "detection_difficulty": "Unknown",
                "remediation_cost": "Unknown"
            })
            
            category_list.append({
                "category": category,
                "display_name": category.replace("_", " ").title(),
                "count": data["count"],
                "max_severity": data["max_severity"],
                "file_count": data["file_count"],
                "avg_confidence": round(data["avg_confidence"], 3),
                **impact_info
            })
        
        # Sort by severity and count
        category_list.sort(key=lambda x: (
            [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.INFO].index(x["max_severity"]),
            -x["count"]
        ))
        
        return category_list

    def _get_immediate_actions(self, findings: List[DetailedFinding]) -> List[Dict[str, Any]]:
        """Generate specific immediate actions based on findings."""
        
        actions = []
        
        # Critical and high severity findings
        urgent_findings = [f for f in findings if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]]
        
        if urgent_findings:
            # Group by category for specific actions
            category_counts = {}
            for finding in urgent_findings:
                category_counts[finding.category] = category_counts.get(finding.category, 0) + 1
            
            for category, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
                action_map = {
                    "sql_injection": {
                        "action": "Implement Parameterized Queries",
                        "description": f"Replace {count} SQL injection vulnerable queries with parameterized statements",
                        "priority": "CRITICAL",
                        "timeline": "24 hours"
                    },
                    "command_injection": {
                        "action": "Sanitize Command Inputs", 
                        "description": f"Implement input validation for {count} command injection points",
                        "priority": "CRITICAL",
                        "timeline": "48 hours"
                    },
                    "xss": {
                        "action": "Implement Output Encoding",
                        "description": f"Add output encoding for {count} XSS vulnerability points",
                        "priority": "HIGH",
                        "timeline": "72 hours"
                    },
                    "hardcoded_secrets": {
                        "action": "Rotate Exposed Credentials",
                        "description": f"Immediately rotate {count} exposed secrets and implement secret management",
                        "priority": "CRITICAL", 
                        "timeline": "6 hours"
                    }
                }
                
                if category in action_map:
                    actions.append(action_map[category])
        
        # Add general security actions
        if len(findings) > 10:
            actions.append({
                "action": "Implement Security Code Review Process",
                "description": "Establish mandatory security reviews for all code changes",
                "priority": "HIGH",
                "timeline": "2 weeks"
            })
        
        return actions[:5]  # Limit to top 5 actions

    def _assess_compliance_impact(self, findings: List[DetailedFinding]) -> Dict[str, Any]:
        """Assess compliance impact of security findings."""
        
        compliance_risks = []
        
        # Check for specific compliance issues
        critical_count = len([f for f in findings if f.severity == SeverityLevel.CRITICAL])
        high_count = len([f for f in findings if f.severity == SeverityLevel.HIGH])
        
        if critical_count > 0:
            compliance_risks.append("PCI DSS - Critical vulnerabilities may violate payment security requirements")
            compliance_risks.append("SOX - Security deficiencies may impact financial reporting controls")
        
        if high_count > 2:
            compliance_risks.append("ISO 27001 - Multiple high-risk findings indicate insufficient security controls")
        
        # Category-specific compliance risks
        categories = set(f.category for f in findings)
        
        if "sql_injection" in categories:
            compliance_risks.append("GDPR - SQL injection risks expose personal data to unauthorized access")
        
        if "hardcoded_secrets" in categories:
            compliance_risks.append("Various - Exposed credentials violate most security frameworks")
        
        return {
            "risk_level": "High" if critical_count > 0 else "Medium" if high_count > 0 else "Low",
            "compliance_risks": compliance_risks[:5],  # Limit to top 5
            "recommendations": [
                "Document all security findings for audit purposes",
                "Implement remediation tracking with compliance reporting",
                "Consider third-party security assessment for validation"
            ]
        }

    def _enhance_finding_details(self, finding: DetailedFinding) -> Dict[str, Any]:
        """Add rich context to vulnerability findings with visual indicators and impact details."""
        
        severity_icons = {
            SeverityLevel.CRITICAL: "🔥",
            SeverityLevel.HIGH: "⚠️",
            SeverityLevel.MEDIUM: "⚡",
            SeverityLevel.LOW: "ℹ️", 
            SeverityLevel.INFO: "✓"
        }
        
        # Get contextual impact description based on vulnerability type
        impact_descriptions = {
            "sql_injection": "SQL injection could allow attackers to extract sensitive data, modify database records, or gain unauthorized system access. Impact varies from data theft to full system compromise.",
            "unsafe_deserialization": "Arbitrary code execution risk allowing attackers to run malicious code with the privileges of the application, potentially leading to complete system compromise.",
            "code_injection": "Allows execution of attacker-controlled code, which can lead to complete system compromise, data theft, or service disruption.",
            "hardcoded_secrets": "Exposed credentials could provide unauthorized access to protected systems, APIs, or databases. These secrets can be discovered through code reviews or repository access.",
            "command_injection": "Attackers can execute arbitrary system commands with the privileges of the application, potentially leading to system compromise.",
            "weak_crypto": "Weak encryption or hashing algorithms can be broken through computational attacks, potentially exposing sensitive data like passwords or personal information.",
            "race_condition": "Can lead to data corruption, unexpected behavior, or security controls being bypassed during high-concurrency operations.",
            "information_disclosure": "Sensitive data leakage through logs, error messages, or API responses can expose credentials, personal data, or system details useful for targeted attacks."
        }
        
        # Get technique details based on vulnerability type
        technique_details = {
            "sql_injection": {
                "attack_vector": "User-supplied input in SQL queries",
                "common_injections": "OR 1=1, UNION SELECT, stacked queries",
                "detection_methods": "Input validation failures, unexpected query results"
            },
            "unsafe_deserialization": {
                "attack_vector": "Untrusted serialized objects",
                "exploitation": "Crafted serialized objects with malicious gadgets",
                "affected_libraries": "pickle, yaml.unsafe_load, eval(json.loads())"
            },
            "code_injection": {
                "attack_vector": "User input reaching eval(), exec() functions",
                "payloads": "Python statements, imports, multi-statement payloads",
                "context": "Server-side input processing without sanitization"
            }
        }

        # Get real-world examples of similar vulnerabilities
        real_world_examples = {
            "sql_injection": ["Equifax breach (2017)", "Yahoo data breach (2013)"],
            "unsafe_deserialization": ["Jenkins CVE-2017-1000353", "Apache Struts CVE-2017-9805"],
            "code_injection": ["PHP Composer CVE-2021-29472", "SolarWinds supply chain attack"],
            "hardcoded_secrets": ["Uber GitHub secret exposure ($100K bug bounty)", "Samsung SmartThings key leak"]
        }
        
        # Get expanded remediation guidance with code examples
        remediation_examples = {
            "sql_injection": {
                "bad": "query = f\"SELECT * FROM users WHERE username = '{user_input}'\"",
                "good": "query = \"SELECT * FROM users WHERE username = %s\"\ncursor.execute(query, (user_input,))"
            },
            "unsafe_deserialization": {
                "bad": "user_data = pickle.loads(serialized_data)",
                "good": "# Option 1: Use json instead\nuser_data = json.loads(serialized_data)\n# Option 2: If pickle required, use restriction\nimport dill\ndill.detect.trace(False)\ndill.settings['recurse'] = True"
            },
            "code_injection": {
                "bad": "result = eval(user_input)",
                "good": "# Use safer alternatives\nfrom ast import literal_eval\ntry:\n    result = literal_eval(user_input)  # Only evaluates literals\nexcept ValueError:\n    result = 'Invalid input'"
            },
            "hardcoded_secrets": {
                "bad": "API_KEY = \"sk-1234567890abcdef\"",
                "good": "import os\nAPI_KEY = os.environ.get(\"API_KEY\")"
            }
        }
        
        # Enhance finding with rich context
        enhanced_finding = {
            "id": finding.id,
            "file": finding.file,
            "line": finding.line,
            "category": finding.category,
            "display_category": finding.category.replace("_", " ").title(),
            "severity": finding.severity.value,
            "severity_icon": severity_icons.get(finding.severity, "❓"),
            "confidence": finding.confidence,
            "confidence_display": f"{finding.confidence*100:.1f}%",
            "explanation": finding.explanation,
            "code_snippet": finding.code_snippet,
            "file_path_parts": self._parse_file_path(finding.file),
            "found_by": finding.found_by,
            
            # Add enhanced context fields
            "impact_description": impact_descriptions.get(finding.category, "This vulnerability may impact system security and should be reviewed."),
            "technique_details": technique_details.get(finding.category, {}),
            "cwe_mapping": self._get_cwe_mapping(finding.category),
            "real_world_examples": real_world_examples.get(finding.category, []),
            "owasp_category": self._map_to_owasp(finding.category),
            "remediation_examples": remediation_examples.get(finding.category, {}),
            "affected_components": self._identify_affected_components(finding.file),
            "visualization_data": self._generate_visualization_data(finding)
        }
        
        return enhanced_finding

    def _parse_file_path(self, file_path: str) -> Dict[str, str]:
        """Parse a file path into meaningful components for better visualization."""
        try:
            from pathlib import Path
            path = Path(file_path)
            
            return {
                "filename": path.name,
                "extension": path.suffix.lstrip('.'),
                "directory": str(path.parent),
                "is_test": "test" in path.name.lower() or "test" in str(path.parent).lower(),
                "is_vendor": "vendor" in str(path.parent).lower() or "node_modules" in str(path.parent).lower(),
                "depth": len(path.parts)
            }
        except:
            # Fallback if parsing fails
            return {
                "filename": file_path.split('/')[-1] if '/' in file_path else file_path,
                "extension": file_path.split('.')[-1] if '.' in file_path else "",
                "directory": '/'.join(file_path.split('/')[:-1]) if '/' in file_path else "",
                "is_test": "test" in file_path.lower(),
                "is_vendor": "vendor" in file_path.lower() or "node_modules" in file_path.lower(),
                "depth": file_path.count('/') + 1
            }

    def _get_cwe_mapping(self, category: str) -> Dict[str, Any]:
        """Map vulnerability category to CWE IDs."""
        cwe_mapping = {
            "sql_injection": {
                "id": "CWE-89", 
                "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                "url": "https://cwe.mitre.org/data/definitions/89.html"
            },
            "unsafe_deserialization": {
                "id": "CWE-502", 
                "name": "Deserialization of Untrusted Data",
                "url": "https://cwe.mitre.org/data/definitions/502.html"
            },
            "code_injection": {
                "id": "CWE-94", 
                "name": "Improper Control of Generation of Code ('Code Injection')",
                "url": "https://cwe.mitre.org/data/definitions/94.html"
            },
            "hardcoded_secrets": {
                "id": "CWE-798", 
                "name": "Use of Hard-coded Credentials",
                "url": "https://cwe.mitre.org/data/definitions/798.html"
            },
            "command_injection": {
                "id": "CWE-78", 
                "name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
                "url": "https://cwe.mitre.org/data/definitions/78.html"
            },
            "weak_crypto": {
                "id": "CWE-327", 
                "name": "Use of a Broken or Risky Cryptographic Algorithm",
                "url": "https://cwe.mitre.org/data/definitions/327.html"
            },
            "race_condition": {
                "id": "CWE-362", 
                "name": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
                "url": "https://cwe.mitre.org/data/definitions/362.html"
            },
            "information_disclosure": {
                "id": "CWE-200", 
                "name": "Exposure of Sensitive Information to an Unauthorized Actor",
                "url": "https://cwe.mitre.org/data/definitions/200.html"
            }
        }
        
        return cwe_mapping.get(category, {"id": "Unknown", "name": "No mapping available", "url": ""})

    def _map_to_owasp(self, category: str) -> Dict[str, Any]:
        """Map vulnerability category to OWASP Top 10 2021."""
        owasp_mapping = {
            "sql_injection": {
                "id": "A03:2021", 
                "name": "Injection",
                "url": "https://owasp.org/Top10/A03_2021-Injection/"
            },
            "unsafe_deserialization": {
                "id": "A08:2021", 
                "name": "Software and Data Integrity Failures",
                "url": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
            },
            "code_injection": {
                "id": "A03:2021", 
                "name": "Injection",
                "url": "https://owasp.org/Top10/A03_2021-Injection/"
            },
            "hardcoded_secrets": {
                "id": "A07:2021", 
                "name": "Identification and Authentication Failures",
                "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
            },
            "weak_crypto": {
                "id": "A02:2021", 
                "name": "Cryptographic Failures",
                "url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
            },
            "insecure_file_upload": {
                "id": "A01:2021", 
                "name": "Broken Access Control",
                "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
            }
        }
        
        return owasp_mapping.get(category, {"id": "Unknown", "name": "Other Vulnerability", "url": "https://owasp.org/Top10/"})

    def _identify_affected_components(self, file_path: str) -> Dict[str, Any]:
        """Identify affected application components based on file path."""
        components = {
            "auth": ["auth", "login", "authentication", "user", "credential", "password", "session"],
            "payment": ["payment", "stripe", "checkout", "billing", "invoice", "transaction"],
            "admin": ["admin", "dashboard", "management", "control"],
            "api": ["api", "rest", "graphql", "endpoint"],
            "database": ["database", "db", "model", "repository", "entity", "schema"],
            "frontend": ["component", "view", "template", "react", "angular", "vue", "ui", "interface"],
            "utils": ["util", "helper", "common", "shared"],
            "config": ["config", "setting", "environment", "env"]
        }
        
        file_lower = file_path.lower()
        affected = []
        
        for component, keywords in components.items():
            for keyword in keywords:
                if keyword in file_lower:
                    affected.append(component)
                    break
        
        if not affected:
            affected = ["unknown"]
        
        # Format for display
        return {
            "names": affected,
            "display": ", ".join(affected).title(),
            "primary": affected[0].title()
        }

    def _generate_visualization_data(self, finding: DetailedFinding) -> Dict[str, Any]:
        """Generate data for vulnerability visualization."""
        # This would be extended with more complex visualization data
        return {
            "position": {
                "line": finding.line,
                "column": 1  # Assuming we don't have column information
            },
            "severity_color": {
                SeverityLevel.CRITICAL: "#d9534f",
                SeverityLevel.HIGH: "#f0ad4e",
                SeverityLevel.MEDIUM: "#ffd700",
                SeverityLevel.LOW: "#5bc0de",
                SeverityLevel.INFO: "#5cb85c"
            }.get(finding.severity, "#5bc0de"),
            "highlight_lines": range(max(1, finding.line - 2), finding.line + 3)
        }

    def _analyze_vulnerability_chains(self, findings: List[DetailedFinding]) -> List[Dict[str, Any]]:
        """Identify chains of related vulnerabilities that could be exploited together."""
        from collections import defaultdict
        import networkx as nx
        
        # Group findings by file
        findings_by_file = defaultdict(list)
        for finding in findings:
            findings_by_file[finding.file].append(finding)
        
        # Define vulnerability relationships
        vulnerability_chains = []
        
        # Check for chains in the same file
        for file_path, file_findings in findings_by_file.items():
            # Sort by line number to establish potential flow
            file_findings.sort(key=lambda f: f.line)
            
            # Check for classic attack chains
            attack_chains = [
                # Chain 1: Authentication bypass leading to unauthorized access
                {
                    "name": "Authentication Bypass Chain",
                    "patterns": ["auth_failures", "broken_access_control", "insecure_deserialization"],
                    "description": "Authentication bypass followed by access control issues could allow complete unauthorized access",
                    "severity_modifier": 1.2  # Increase severity by 20%
                },
                # Chain 2: Injection leading to RCE
                {
                    "name": "Injection to RCE Chain",
                    "patterns": ["sql_injection", "code_injection", "command_injection", "unsafe_deserialization"],
                    "description": "Injection vulnerabilities that could escalate to remote code execution",
                    "severity_modifier": 1.3
                },
                # Chain 3: Information disclosure leading to account compromise
                {
                    "name": "Information Disclosure Chain",
                    "patterns": ["information_disclosure", "hardcoded_secrets", "weak_crypto"],
                    "description": "Information disclosure that reveals sensitive data like credentials",
                    "severity_modifier": 1.1
                }
            ]
            
            # Check for matches in each chain
            for chain in attack_chains:
                chain_findings = []
                for pattern in chain["patterns"]:
                    for finding in file_findings:
                        if pattern in finding.category and finding not in chain_findings:
                            chain_findings.append(finding)
                            break
                
                # If we found at least 2 elements in the chain, it's a potential issue
                if len(chain_findings) >= 2:
                    # Calculate increased risk based on chain
                    base_severity = max([f.severity.value for f in chain_findings])
                    chain_severity = min(base_severity, "critical")  # Cap at critical
                    
                    vulnerability_chains.append({
                        "name": chain["name"],
                        "description": chain["description"],
                        "findings": chain_findings,
                        "file": file_path,
                        "severity": chain_severity,
                        "combined_risk": "Multiple related vulnerabilities can be chained together to escalate attack impact",
                        "attack_scenario": self._generate_attack_scenario(chain["name"], file_path, chain_findings)
                    })
        
        return vulnerability_chains

    def _generate_attack_scenario(self, chain_name: str, file_path: str, findings: List[DetailedFinding]) -> str:
        """Generate a realistic attack scenario description for a vulnerability chain."""
        scenarios = {
            "Authentication Bypass Chain": f"An attacker could bypass authentication in {file_path} using " + 
                                        f"{findings[0].category.replace('_', ' ')}, then exploit {findings[1].category.replace('_', ' ')} " +
                                        "to gain unauthorized administrative access to the system.",
            
            "Injection to RCE Chain": f"An attacker could inject malicious input via {findings[0].category.replace('_', ' ')} in {file_path}, " +
                                    f"then escalate to {findings[1].category.replace('_', ' ')} to achieve remote code execution on the server.",
            
            "Information Disclosure Chain": f"An attacker could exploit {findings[0].category.replace('_', ' ')} in {file_path} to expose " +
                                        f"sensitive data, then use the {findings[1].category.replace('_', ' ')} vulnerability to gain unauthorized access."
        }
        
        return scenarios.get(chain_name, f"Multiple vulnerabilities in {file_path} could be chained together for increased impact.")

    def _generate_enhanced_recommendations(self, findings: List[DetailedFinding], vulnerability_chains: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate comprehensive recommendations with detailed steps, code examples, and timelines."""
        from collections import defaultdict
        
        # Group findings by category for consolidated recommendations
        findings_by_category = defaultdict(list)
        for finding in findings:
            findings_by_category[finding.category].append(finding)
        
        prioritized_actions = []
        
        # First address vulnerability chains as they pose higher risk
        if vulnerability_chains:
            for i, chain in enumerate(vulnerability_chains):
                chain_categories = set(f.category for f in chain["findings"])
                chain_files = set(f.file for f in chain["findings"])
                
                prioritized_actions.append({
                    "priority": i + 1,
                    "action": f"Fix {chain['name']} vulnerability chain",
                    "severity": "critical",  # Chains are always high priority
                    "effort": "high" if len(chain["findings"]) > 3 else "medium",
                    "impact": "critical",
                    "categories": list(chain_categories),
                    "files": list(chain_files),
                    "description": chain["description"],
                    "steps": [
                        f"1. Address {f.category.replace('_', ' ')} in {f.file} around line {f.line}" 
                        for f in chain["findings"]
                    ],
                    "attack_scenario": chain["attack_scenario"],
                    "timeframe": "Immediate (24-48 hours)",
                    "resources_needed": "Security engineer, Application developer",
                    "testing": "Comprehensive security testing required after fixing to verify chain is broken"
                })
        
        # Function to determine effort level
        def determine_effort(category, count):
            high_effort = ["insecure_design", "broken_access_control", "weak_crypto", "unsafe_deserialization"]
            low_effort = ["hardcoded_secrets", "information_disclosure"]
            
            if category in high_effort or count >= 5:
                return "high"
            elif category in low_effort:
                return "low"
            else:
                return "medium"
        
        # Process critical findings first, grouped by category
        severity_order = ["critical", "high", "medium", "low", "info"]
        offset = len(prioritized_actions)
        
        for severity in severity_order:
            # Get categories with this severity
            categories_with_severity = {}
            for category, category_findings in findings_by_category.items():
                # Check if any finding in this category has the current severity
                severity_findings = [f for f in category_findings if f.severity.value == severity]
                if severity_findings:
                    categories_with_severity[category] = severity_findings
            
            # Sort categories by number of findings
            sorted_categories = sorted(categories_with_severity.items(), key=lambda x: len(x[1]), reverse=True)
            
            for i, (category, category_findings) in enumerate(sorted_categories):
                # Get remediation details
                remediation = self._get_detailed_remediation(category)
                
                affected_files = set(f.file for f in category_findings)
                example_finding = category_findings[0]  # Use first finding as example
                
                prioritized_actions.append({
                    "priority": offset + i + 1,
                    "action": f"Fix {category.replace('_', ' ')} vulnerabilities ({len(category_findings)} instances)",
                    "severity": severity,
                    "effort": determine_effort(category, len(category_findings)),
                    "impact": "high" if severity in ["critical", "high"] else "medium",
                    "category": category,
                    "affected_files": list(affected_files)[:5],  # Limit to 5 files for display
                    "cwe": self._get_cwe_mapping(category),
                    "owasp_category": self._map_to_owasp(category),
                    "description": remediation["description"],
                    "example_location": f"{example_finding.file}:{example_finding.line}",
                    "steps": remediation["steps"],
                    "code_example": {
                        "vulnerable": remediation["vulnerable_code"],
                        "fixed": remediation["fixed_code"],
                        "explanation": remediation["explanation"]
                    },
                    "verification": remediation["verification_steps"],
                    "tools": remediation["tools"],
                    "timeframe": self._get_recommended_timeframe(severity),
                    "additional_resources": remediation["resources"]
                })
            
            offset = len(prioritized_actions)
        
        return {
            "prioritized_actions": prioritized_actions,
            "general_recommendations": self._generate_general_recommendations(findings)
        }

    def _get_detailed_remediation(self, category: str) -> Dict[str, Any]:
        """Get detailed remediation guidance for a vulnerability category."""
        remediation_details = {
            "sql_injection": {
                "description": "SQL injection vulnerabilities allow attackers to manipulate database queries, potentially allowing data theft, modification, or destruction.",
                "steps": [
                    "Replace string concatenation with parameterized queries",
                    "Implement an ORM (Object-Relational Mapping) tool",
                    "Apply input validation and sanitization",
                    "Use the principle of least privilege for database accounts"
                ],
                "vulnerable_code": "query = f\"SELECT * FROM users WHERE username = '{user_input}'\";\nresults = cursor.execute(query);",
                "fixed_code": "query = \"SELECT * FROM users WHERE username = %s\";\nresults = cursor.execute(query, (user_input,));",
                "explanation": "Parameterized queries ensure that user input is treated as data, not executable code, preventing SQL injection attacks.",
                "verification_steps": [
                    "Test with special characters like quotes, semicolons",
                    "Verify that invalid inputs are rejected or sanitized",
                    "Use automated SQL injection testing tools"
                ],
                "tools": ["SQLAlchemy", "Prepared statements", "OWASP ZAP", "SQLMap"],
                "resources": ["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"]
            },
            "unsafe_deserialization": {
                "description": "Unsafe deserialization vulnerabilities can allow attackers to execute arbitrary code by controlling serialized data that is processed by the application.",
                "steps": [
                    "Avoid deserializing data from untrusted sources",
                    "Switch to safer serialization formats like JSON",
                    "If using pickle, implement strict input validation and whitelisting",
                    "Consider using serialization libraries with security features"
                ],
                "vulnerable_code": "import pickle\nuser_data = pickle.loads(serialized_data)",
                "fixed_code": "import json\n# Use JSON instead of pickle\nuser_data = json.loads(serialized_data)\n\n# If pickle is required:\nfrom pickle import loads\nimport hmac\nimport hashlib\n\ndef verify_signature(data, signature, secret_key):\n    return hmac.new(secret_key, data, hashlib.sha256).digest() == signature\n\nif verify_signature(serialized_data, signature, SECRET_KEY):\n    user_data = loads(serialized_data)",
                "explanation": "Pickle is inherently unsafe as it allows arbitrary code execution. JSON is a safer alternative as it only supports data structures. If pickle is required, use cryptographic signatures to verify the integrity of serialized data.",
                "verification_steps": [
                    "Verify that untrusted input cannot be deserialized",
                    "Test with malformed serialized data",
                    "Add integrity checks for serialized data"
                ],
                "tools": ["json", "marshmallow", "cryptography"],
                "resources": ["https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"]
            },
            "code_injection": {
                "description": "Code injection vulnerabilities allow attackers to execute arbitrary code by inserting malicious code into interpreted contexts.",
                "steps": [
                    "Avoid using eval(), exec(), and similar functions",
                    "Use safe alternatives like ast.literal_eval() for parsing expressions",
                    "Implement strong input validation",
                    "Apply the principle of least privilege for execution context"
                ],
                "vulnerable_code": "result = eval(user_expression)",
                "fixed_code": "import ast\n\n# For simple expressions that should only be literals\ntry:\n    result = ast.literal_eval(user_expression)\nexcept (ValueError, SyntaxError):\n    result = 'Invalid expression'",
                "explanation": "eval() evaluates arbitrary Python expressions, which is dangerous with untrusted input. ast.literal_eval() only evaluates literal structures like strings, numbers, lists, and dicts, preventing code execution.",
                "verification_steps": [
                    "Test with inputs containing Python code",
                    "Verify that only expected expressions are evaluated",
                    "Ensure proper error handling for invalid inputs"
                ],
                "tools": ["ast.literal_eval()", "pylint --enable=eval-used"],
                "resources": ["https://nedbatchelder.com/blog/201206/eval_really_is_dangerous.html"]
            },
            "hardcoded_secrets": {
                "description": "Hardcoded secrets in source code can lead to credential exposure and unauthorized access when code is shared or leaked.",
                "steps": [
                    "Move all secrets to environment variables or a secure vault",
                    "Use configuration files outside of source control",
                    "Implement a secrets management solution",
                    "Set up proper key rotation procedures"
                ],
                "vulnerable_code": "API_KEY = \"sk-1234567890abcdef\"\nDATABASE_PASSWORD = \"password123\"",
                "fixed_code": "import os\nfrom dotenv import load_dotenv\n\n# Load environment variables from .env file (not in source control)\nload_dotenv()\n\n# Access secrets from environment\nAPI_KEY = os.environ.get(\"API_KEY\")\nDATABASE_PASSWORD = os.environ.get(\"DATABASE_PASSWORD\")",
                "explanation": "Secrets should never be hardcoded in source files as they can be exposed in version control. Environment variables or dedicated secret management solutions keep credentials separate from code.",
                "verification_steps": [
                    "Verify no secrets in code using tools like detect-secrets",
                    "Test that the application correctly loads secrets from environment",
                    "Run git-secrets scan on repository"
                ],
                "tools": ["python-dotenv", "HashiCorp Vault", "AWS Secrets Manager", "detect-secrets"],
                "resources": ["https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"]
            },
            "command_injection": {
                "description": "Command injection vulnerabilities allow attackers to execute arbitrary system commands by manipulating command parameters.",
                "steps": [
                    "Avoid shell commands when possible - use language APIs instead",
                    "If shell commands are necessary, whitelist allowed commands",
                    "Never concatenate user input into command strings",
                    "Use subprocess with proper argument arrays"
                ],
                "vulnerable_code": "import os\nresult = os.system(f\"ping {user_input}\")",
                "fixed_code": "import subprocess\n\n# Use argument array to prevent command injection\ntry:\n    result = subprocess.run(['ping', user_input], shell=False, check=True,\n                           capture_output=True, text=True, timeout=10)\n    output = result.stdout\nexcept (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:\n    output = f\"Error: {e}\"",
                "explanation": "Passing separate arguments to subprocess.run() prevents command injection because each argument is passed as-is to the command, without shell interpretation.",
                "verification_steps": [
                    "Test with input containing shell metacharacters (;, &&, ||, etc.)",
                    "Verify the application rejects or sanitizes dangerous input",
                    "Use automated command injection testing tools"
                ],
                "tools": ["subprocess module", "OWASP ZAP", "shlex.quote()"],
                "resources": ["https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"]
            }
        }
        
        # Default remediation if specific category not found
        default_remediation = {
            "description": f"Vulnerabilities of type '{category}' may pose security risks to your application.",
            "steps": [
                "Review the code for security issues",
                "Apply security best practices",
                "Implement proper input validation",
                "Consider security testing"
            ],
            "vulnerable_code": "# Vulnerable code example not available",
            "fixed_code": "# Fixed code example not available",
            "explanation": "Apply secure coding practices specific to this vulnerability type.",
            "verification_steps": [
                "Test the fix thoroughly",
                "Consider security review",
                "Implement automated tests"
            ],
            "tools": ["Security linters", "SAST tools", "Code review"],
            "resources": ["https://owasp.org/www-project-top-ten/"]
        }
        
        return remediation_details.get(category, default_remediation)

    def _get_recommended_timeframe(self, severity: str) -> str:
        """Get recommended remediation timeframe based on severity."""
        timeframes = {
            "critical": "Immediate (24-48 hours)",
            "high": "Within 1 week",
            "medium": "Within 2-4 weeks",
            "low": "Next release cycle",
            "info": "When convenient"
        }
        return timeframes.get(severity, "Prioritize based on risk")

    def _generate_general_recommendations(self, findings: List[DetailedFinding]) -> List[Dict[str, Any]]:
        """Generate general security recommendations based on the findings."""
        recommendations = []
        
        # Check if SAST recommendation is needed
        needs_sast = any(f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH] for f in findings)
        if needs_sast:
            recommendations.append({
                "title": "Implement Automated Security Testing",
                "description": "Add Static Application Security Testing (SAST) to your CI/CD pipeline to detect vulnerabilities early.",
                "implementation": [
                    "Set up a tool like Bandit or SonarQube in your CI pipeline",
                    "Configure security rules based on your application's requirements",
                    "Set a quality gate that fails builds with critical security issues",
                    "Review and address security findings regularly"
                ],
                "tools": ["Bandit", "SonarQube", "OWASP Dependency Check", "Safety"],
                "effort": "Medium (3-5 days)",
                "benefit": "Continuous detection of common security issues before they reach production"
            })
        
        # Check if secure coding training is needed
        if len(findings) > 5:
            recommendations.append({
                "title": "Security Training for Developers",
                "description": "Provide secure coding training to prevent introduction of security vulnerabilities.",
                "implementation": [
                    "Schedule regular security awareness sessions",
                    "Create secure coding guidelines specific to your technologies",
                    "Implement pair programming or peer review for security-sensitive code",
                    "Use real examples from your codebase in training"
                ],
                "resources": ["OWASP Secure Coding Practices", "SANS Secure Coding Training"],
                "effort": "Medium (ongoing)",
                "benefit": "Reduced introduction of new security issues through awareness and education"
            })
        
        # Add more general recommendations as needed
        
        return recommendations

    def _generate_model_specific_insights(self, findings: List[DetailedFinding], metadata: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Generate insights specific to each model rather than misleading aggregates."""
        from collections import defaultdict
        
        # Create empty model insights structure for each model
        model_insights = {}
        for model in metadata.get("models_used", []):
            model_insights[model] = {
                "total_findings": 0,
                "severity_counts": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0
                },
                "categories": defaultdict(int),
                "risk_score": 0,
                "files_affected": set(),
                "top_categories": [],
                "severe_examples": []
            }
        
        # Populate with actual findings
        for finding in findings:
            for model in finding.found_by:
                if model in model_insights:
                    # Count total findings
                    model_insights[model]["total_findings"] += 1
                    
                    # Count by severity
                    severity = finding.severity.value
                    model_insights[model]["severity_counts"][severity] += 1
                    
                    # Track affected files
                    model_insights[model]["files_affected"].add(finding.file)
                    
                    # Count categories
                    model_insights[model]["categories"][finding.category] += 1
                    
                    # Add to severe examples if critical or high
                    if severity in ["critical", "high"]:
                        model_insights[model]["severe_examples"].append({
                            "category": finding.category,
                            "severity": severity,
                            "file": finding.file,
                            "line": finding.line,
                            "explanation": finding.explanation[:150] + "..." if len(finding.explanation) > 150 else finding.explanation
                        })
        
        # Calculate risk score and finalize for each model
        for model, data in model_insights.items():
            # Calculate risk score
            data["risk_score"] = (
                data["severity_counts"]["critical"] * 10 +
                data["severity_counts"]["high"] * 7 +
                data["severity_counts"]["medium"] * 4 +
                data["severity_counts"]["low"] * 2 +
                data["severity_counts"]["info"] * 1
            )
            
            # Convert file set to count
            data["files_affected"] = len(data["files_affected"])
            
            # Get top categories
            data["top_categories"] = sorted(
                data["categories"].items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]
            
            # Sort severe examples by severity
            data["severe_examples"].sort(
                key=lambda x: {"critical": 2, "high": 1, "medium": 0}.get(x["severity"], 0),
                reverse=True
            )
            
            # Limit to top 3 examples
            data["severe_examples"] = data["severe_examples"][:3]
        
        return model_insights

    def _generate_enhanced_consensus_findings(self, findings: List[DetailedFinding]) -> List[Dict[str, Any]]:
        """
        Generate comprehensive critical consensus findings with detailed compliance mapping,
        attack scenarios, and business impact analysis.
        """
        from collections import defaultdict
        
        # Group findings by category with minimum 2 model agreement
        consensus_by_category = defaultdict(list)
        for finding in findings:
            if len(finding.found_by) >= 2:
                consensus_by_category[finding.category].append(finding)
        
        enhanced_consensus = []
        
        for category, category_findings in consensus_by_category.items():
            if len(category_findings) < 2:  # Skip if not enough consensus
                continue
                
            # Calculate comprehensive metrics
            models_agreed = set()
            for finding in category_findings:
                models_agreed.update(finding.found_by)
            
            highest_severity = max([f.severity for f in category_findings])
            avg_confidence = sum(f.confidence for f in category_findings) / len(category_findings)
            
            # Get the most critical example
            critical_example = max(category_findings, key=lambda f: (f.severity.value, f.confidence))
            
            # Generate comprehensive compliance mapping
            compliance_details = self._get_comprehensive_compliance_mapping(category)
            
            # Generate detailed threat analysis
            threat_analysis = self._generate_threat_analysis(category, category_findings)
            
            # Generate business impact assessment
            business_impact = self._assess_business_impact(category, len(category_findings))
            
            # Generate attack scenario
            attack_scenario = self._generate_realistic_attack_scenario(category, critical_example)
            
            # Generate detailed remediation roadmap
            remediation_roadmap = self._create_remediation_roadmap(category, category_findings)
            
            # Risk quantification
            risk_metrics = self._calculate_risk_metrics(category, category_findings, len(models_agreed))
            
            enhanced_finding = {
                "category": category,
                "display_name": self._get_professional_category_name(category),
                "severity": highest_severity.value,
                "confidence": round(avg_confidence, 3),
                "confidence_level": self._get_confidence_level(avg_confidence),
                "models_agreed": sorted(list(models_agreed)),
                "consensus_strength": len(models_agreed),
                "findings_count": len(category_findings),
                
                # Threat Intelligence
                "threat_analysis": threat_analysis,
                "attack_scenario": attack_scenario,
                "exploit_difficulty": self._assess_exploit_difficulty(category),
                "attack_prerequisites": self._get_attack_prerequisites(category),
                
                # Business Impact
                "business_impact": business_impact,
                "financial_impact": self._estimate_financial_impact(category),
                "reputation_impact": self._assess_reputation_impact(category),
                "operational_impact": self._assess_operational_impact(category),
                
                # Compliance & Regulatory
                "compliance_mapping": compliance_details,
                "regulatory_risks": self._identify_regulatory_risks(category),
                "audit_implications": self._get_audit_implications(category),
                
                # Technical Details
                "technical_description": self._get_comprehensive_technical_description(category),
                "affected_components": self._analyze_affected_components(category_findings),
                "vulnerability_chain_risk": self._assess_chain_risk(category, findings),
                
                # Remediation
                "remediation_roadmap": remediation_roadmap,
                "immediate_actions": self._get_immediate_actions(category),
                "prevention_strategy": self._get_prevention_strategy(category),
                
                # Risk Metrics
                "risk_metrics": risk_metrics,
                "cvss_estimation": self._estimate_cvss_score(category, highest_severity),
                "priority_score": self._calculate_priority_score(risk_metrics, len(models_agreed)),
                
                # Evidence
                "critical_example": {
                    "file": critical_example.file,
                    "line": critical_example.line,
                    "code_context": critical_example.code_snippet,
                    "explanation": critical_example.explanation
                },
                "affected_files": list(set(f.file for f in category_findings)),
                "line_ranges": [(f.file, f.line) for f in category_findings]
            }
            
            enhanced_consensus.append(enhanced_finding)
        
        # Sort by priority score (descending)
        return sorted(enhanced_consensus, key=lambda x: x["priority_score"], reverse=True)

    def _get_compliance_mapping(self, category: str) -> Dict[str, Any]:
        """
        Map vulnerability categories to compliance frameworks including:
        OWASP Top 10, CWE, NIST, GDPR, PCI DSS, and HIPAA.
        """
        compliance_mappings = {
            "unsafe_deserialization": {
                "owasp": {
                    "id": "A8:2021",
                    "name": "Software and Data Integrity Failures",
                    "url": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
                },
                "cwe": {
                    "id": "CWE-502",
                    "name": "Deserialization of Untrusted Data",
                    "url": "https://cwe.mitre.org/data/definitions/502.html"
                },
                "nist": {
                    "id": "SI-10",
                    "name": "Information Input Validation",
                    "framework": "NIST 800-53"
                },
                "pci_dss": {
                    "requirement": "6.5.1",
                    "description": "Develop applications based on secure coding guidelines"
                }
            },
            "code_injection": {
                "owasp": {
                    "id": "A3:2021",
                    "name": "Injection",
                    "url": "https://owasp.org/Top10/A03_2021-Injection/"
                },
                "cwe": {
                    "id": "CWE-94",
                    "name": "Improper Control of Generation of Code",
                    "url": "https://cwe.mitre.org/data/definitions/94.html"
                },
                "nist": {
                    "id": "SI-10",
                    "name": "Information Input Validation",
                    "framework": "NIST 800-53"
                },
                "pci_dss": {
                    "requirement": "6.5.1",
                    "description": "Develop applications based on secure coding guidelines"
                }
            },
            "hardcoded_secrets": {
                "owasp": {
                    "id": "A7:2021",
                    "name": "Identification and Authentication Failures",
                    "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
                },
                "cwe": {
                    "id": "CWE-798",
                    "name": "Use of Hard-coded Credentials",
                    "url": "https://cwe.mitre.org/data/definitions/798.html"
                },
                "nist": {
                    "id": "IA-5",
                    "name": "Authenticator Management",
                    "framework": "NIST 800-53"
                },
                "pci_dss": {
                    "requirement": "6.5.6",
                    "description": "Verify that all credentials are protected (e.g., not hard-coded)"
                },
                "gdpr": {
                    "article": "32",
                    "description": "Security of processing",
                    "relevance": "Failure to protect access credentials may lead to unauthorized data access"
                }
            },
            "sql_injection": {
                "owasp": {
                    "id": "A3:2021",
                    "name": "Injection",
                    "url": "https://owasp.org/Top10/A03_2021-Injection/"
                },
                "cwe": {
                    "id": "CWE-89",
                    "name": "SQL Injection",
                    "url": "https://cwe.mitre.org/data/definitions/89.html"
                },
                "nist": {
                    "id": "SI-10",
                    "name": "Information Input Validation",
                    "framework": "NIST 800-53"
                },
                "pci_dss": {
                    "requirement": "6.5.1",
                    "description": "Prevent injection flaws, particularly SQL injection"
                },
                "gdpr": {
                    "article": "32",
                    "description": "Security of processing",
                    "relevance": "SQL injection can lead to unauthorized access to personal data"
                }
            },
            "command_injection": {
                "owasp": {
                    "id": "A3:2021",
                    "name": "Injection",
                    "url": "https://owasp.org/Top10/A03_2021-Injection/"
                },
                "cwe": {
                    "id": "CWE-78",
                    "name": "OS Command Injection",
                    "url": "https://cwe.mitre.org/data/definitions/78.html"
                }
            },
            "information_disclosure": {
                "owasp": {
                    "id": "A4:2021",
                    "name": "Insecure Design",
                    "url": "https://owasp.org/Top10/A04_2021-Insecure_Design/"
                },
                "cwe": {
                    "id": "CWE-200",
                    "name": "Exposure of Sensitive Information to an Unauthorized Actor",
                    "url": "https://cwe.mitre.org/data/definitions/200.html"
                }
            }
        }
        
        # Return default minimal compliance info if category not found
        default_compliance = {
            "owasp": {
                "id": "Unknown",
                "name": "See OWASP Top 10",
                "url": "https://owasp.org/Top10/"
            },
            "cwe": {
                "id": "Unknown",
                "name": "See CWE Top 25",
                "url": "https://cwe.mitre.org/top25/"
            }
        }
        
        return compliance_mappings.get(category, default_compliance)

    def _get_detailed_impact(self, category: str) -> Dict[str, Any]:
        """
        Get comprehensive impact details for a vulnerability category,
        including attack vectors and business impacts.
        """
        impact_details = {
            "unsafe_deserialization": {
                "impact": "Untrusted deserialization can lead to remote code execution, allowing attackers to take complete control of affected systems. Exploited vulnerabilities may result in data theft, system compromise, and lateral movement within networks.",
                "attack_vectors": [
                    "Crafting malicious serialized objects that execute arbitrary code when deserialized",
                    "Leveraging gadget chains within application dependencies to trigger code execution",
                    "Injecting malicious serialized data through APIs, file uploads, or network streams"
                ],
                "business_impact": [
                    "Complete system compromise and unauthorized data access",
                    "Potential breach notification requirements under regulations like GDPR",
                    "Loss of customer trust and reputation damage following security breaches",
                    "Service disruptions during incident response and remediation"
                ]
            },
            "code_injection": {
                "impact": "Code injection vulnerabilities allow attackers to execute arbitrary code within the application context, potentially leading to complete system compromise. This can result in unauthorized access to sensitive data, modification of application behavior, and persistence on affected systems.",
                "attack_vectors": [
                    "Injecting malicious code through user inputs that reach eval(), exec() or similar functions",
                    "Exploiting template engines that evaluate user-controlled templates",
                    "Manipulating format strings or interpolation mechanisms to execute code"
                ],
                "business_impact": [
                    "Unauthorized access to business-critical data and systems",
                    "Installation of malware or backdoors for persistent access",
                    "Financial losses from data theft, fraud, or ransomware",
                    "Regulatory penalties and legal liability from data breaches"
                ]
            },
            "hardcoded_secrets": {
                "impact": "Hardcoded credentials and API keys in source code can be easily discovered through code access or repository mining. These exposed secrets provide attackers with legitimate credentials to access protected resources, APIs, or databases with the same privileges as the application.",
                "attack_vectors": [
                    "Mining public or private code repositories for exposed credentials",
                    "Reverse engineering applications to extract embedded secrets",
                    "Using leaked credentials to access restricted systems or APIs",
                    "Chaining credential access with other vulnerabilities for privilege escalation"
                ],
                "business_impact": [
                    "Unauthorized API or service usage resulting in unexpected bills",
                    "Data breaches through legitimate but unauthorized access",
                    "Difficult-to-detect intrusions that appear as legitimate access",
                    "Need for emergency credential rotation across multiple systems"
                ]
            },
            "sql_injection": {
                "impact": "SQL injection allows attackers to manipulate database queries, potentially extracting, modifying, or deleting sensitive data. In severe cases, attackers may gain operating system access through database privileges.",
                "attack_vectors": [
                    "Injecting malicious SQL through user inputs in web forms or API parameters",
                    "Using techniques like UNION queries to extract data from different tables",
                    "Exploiting blind SQL injection through timing or boolean responses",
                    "Leveraging database-specific functions to access files or execute commands"
                ],
                "business_impact": [
                    "Exposure of sensitive customer or business data",
                    "Financial fraud through manipulation of transactional data",
                    "Compliance violations and potential regulatory penalties",
                    "Loss of database integrity requiring restoration from backups"
                ]
            },
            "information_disclosure": {
                "impact": "Information disclosure vulnerabilities expose sensitive data to unauthorized parties, potentially revealing internal system details, personal data, or credentials that facilitate further attacks.",
                "attack_vectors": [
                    "Exploiting verbose error messages that reveal system internals",
                    "Extracting sensitive data from logs, comments, or hidden fields",
                    "Mining backup files, source code, or configuration files accidentally exposed",
                    "Leveraging directory traversal to access unprotected files"
                ],
                "business_impact": [
                    "Privacy violations potentially triggering regulatory action",
                    "Exposure of intellectual property or business secrets",
                    "Reputational damage from publicized data exposures",
                    "Increased vulnerability to targeted attacks using leaked information"
                ]
            }
        }
        
        # Default impact details for unknown categories
        default_impact = {
            "impact": f"The {category.replace('_', ' ')} vulnerability may compromise system security, potentially allowing unauthorized access or data exposure.",
            "attack_vectors": [
                "Exploiting the vulnerability through malicious inputs or actions",
                "Leveraging the issue to gain unauthorized access or privileges"
            ],
            "business_impact": [
                "Potential unauthorized access to sensitive data or systems",
                "Possible service disruption or data integrity issues",
                "Security incident response costs and remediation efforts"
            ]
        }
        
        return impact_details.get(category, default_impact)

    def _get_detailed_description(self, category: str) -> str:
        """
        Get comprehensive, technical descriptions of vulnerability categories
        with explanations of underlying security principles.
        """
        descriptions = {
            "unsafe_deserialization": """
    Unsafe deserialization occurs when an application deserializes untrusted data without sufficient verification. 
    Serialization converts complex data structures into a format that can be stored or transmitted, while deserialization 
    recreates the original object from this data. Languages like Python (pickle), Java, PHP, and .NET support deserialization
    that can execute code during the reconstruction process.

    When attackers control serialized data, they can craft malicious objects that, when deserialized, execute arbitrary code
    within the application context. This vulnerability is particularly dangerous because it often leads to remote code execution
    with the privileges of the application process.

    Common insecure deserialization patterns include:
    - Using pickle.loads() on user-controlled data
    - Deserializing data from untrusted sources without validation
    - Failing to implement integrity checks (cryptographic signatures) on serialized data
    - Using unsafe deserialization features in libraries and frameworks
    """,
            "code_injection": """
    Code injection vulnerabilities occur when an application dynamically evaluates code constructed from user-controlled input.
    This vulnerability class includes various injection types where user input influences code execution contexts.

    The most direct form involves functions like eval(), exec(), or similar constructs that parse and execute code at runtime.
    When user input flows into these functions without proper sanitization, attackers can execute arbitrary code within the
    application's context.

    The vulnerability extends beyond obvious cases to template engines, expression evaluators, and dynamic code loading
    mechanisms. Even if not immediately exploitable for remote code execution, code injection often leads to related
    vulnerabilities like server-side template injection or expression language injection.

    Common code injection patterns include:
    - Directly passing user input to eval() or exec()
    - Using user input in dynamic import statements
    - Evaluating user-controlled templates or expressions
    - Building and executing command strings with user input
    """,
            "hardcoded_secrets": """
    Hardcoded secrets are credentials, API keys, encryption keys, or other sensitive values embedded directly in source code
    rather than retrieved from secure external sources at runtime. This practice creates significant security risks, especially
    in modern development environments where code is shared, versioned, and often publicly accessible.

    When secrets are hardcoded, they cannot be easily rotated without code changes, may be accidentally exposed through
    repository access, and often propagate across development, staging, and production environments. Even if the repository
    is private, the risk increases with each developer, CI/CD system, or deployment tool that accesses the code.

    Modern best practices emphasize separating secrets from code by using environment variables, secure vaults, or dedicated
    secret management services. This approach allows proper access controls, audit logging, and credential rotation without
    code modifications.

    Common hardcoded secrets patterns include:
    - API keys, passwords, or tokens directly assigned in code
    - Connection strings with embedded credentials
    - Encryption keys or signing secrets defined as constants
    - Default credentials that remain unchanged in production
    """,
            "sql_injection": """
    SQL injection occurs when user-supplied data is incorporated into database queries without proper sanitization,
    allowing attackers to manipulate the query structure and execute unintended commands. This vulnerability arises
    from string concatenation or direct interpolation of user inputs into SQL statements.

    When exploited, SQL injection can allow attackers to bypass authentication, access unauthorized data, modify
    database contents, or execute administrative operations. In some database systems, SQL injection can even enable
    file system access or command execution on the host operating system.

    The vulnerability manifests when applications construct SQL queries using string concatenation or formatting
    with user inputs, rather than using parameterized queries or ORMs that properly separate code from data.

    Common SQL injection patterns include:
    - Direct string concatenation of user input into SQL queries
    - String interpolation (f-strings in Python) to build queries
    - Dynamic SQL generation without proper escaping
    - Stored procedures that internally concatenate user inputs
    """,
            "information_disclosure": """
    Information disclosure vulnerabilities expose sensitive data or system details to unauthorized parties. These
    vulnerabilities can reveal internal implementation details, sensitive personal or business data, or system
    information that facilitates other attacks.

    The exposure may occur through verbose error messages, debug information, metadata in files, improper access
    controls, or server misconfigurations. While sometimes considered less severe than other vulnerabilities,
    information disclosure often provides attackers with critical intelligence for targeting more significant attacks.

    Modern applications should implement the principle of least privilege for information access and carefully
    control what data is exposed through interfaces, error messages, and responses.

    Common information disclosure patterns include:
    - Detailed technical error messages exposed to users
    - Sensitive data in logs, comments, or hidden fields
    - Inadequate access controls on API endpoints or files
    - Metadata in documents or images that reveals sensitive information
    - Directory listings or backup files accessible to unauthorized users
    """
        }
        
        # Default description for unknown categories
        default_description = f"""
    The {category.replace('_', ' ')} vulnerability represents a security weakness that could potentially
    be exploited by attackers. This type of vulnerability may allow unauthorized access to data or systems,
    depending on the specific implementation details and context.

    Security best practices recommend reviewing the affected code to identify the specific security weakness
    and implementing appropriate controls to mitigate the risk.
    """
        
        return descriptions.get(category, default_description).strip()


    def _get_remediation_guidance(self, category: str) -> Dict[str, Any]:
        """
        Get detailed remediation guidance with code examples, best practices,
        and implementation steps.
        """
        remediation_guidance = {
            "unsafe_deserialization": {
                "summary": "Replace unsafe deserialization mechanisms with secure alternatives and implement proper input validation",
                "steps": [
                    "Switch to data-only serialization formats like JSON or YAML safe_load",
                    "If pickle is required, implement cryptographic signatures to verify data integrity",
                    "Use allowlists to restrict deserialized classes",
                    "Consider serialization libraries with security features"
                ],
                "code_example": {
                    "vulnerable": "import pickle\nuser_data = pickle.loads(serialized_data)  # Vulnerable to code execution",
                    "secure": """
    # Option 1: Use JSON instead of pickle
    import json
    user_data = json.loads(serialized_data)  # Data-only deserialization

    # Option 2: If pickle is necessary, add signature verification
    import pickle
    import hmac
    import hashlib

    def verify_and_load(data, signature, secret_key):
        computed_hash = hmac.new(secret_key, data, hashlib.sha256).digest()
        if hmac.compare_digest(computed_hash, signature):  # Constant-time comparison
            return pickle.loads(data)
        raise ValueError("Invalid signature - possible tampering detected")
                    """
                },
                "tools": ["bandit", "safety", "OWASP Dependency Check"],
                "additional_resources": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
                    "https://portswigger.net/web-security/deserialization"
                ]
            },
            "code_injection": {
                "summary": "Avoid using dynamic code execution functions with user input and implement proper input validation",
                "steps": [
                    "Remove uses of eval(), exec() and similar functions",
                    "Use ast.literal_eval() for safe evaluation of literals",
                    "Implement input validation and allowlists",
                    "Consider safer alternatives like JSON for data structures"
                ],
                "code_example": {
                    "vulnerable": "result = eval(user_input)  # Vulnerable to code execution",
                    "secure": """
    # Option 1: Use ast.literal_eval() for safe evaluation of literals
    import ast
    try:
        result = ast.literal_eval(user_input)  # Only evaluates literals like strings, numbers, lists, dicts
    except (ValueError, SyntaxError):
        result = None  # Handle invalid input safely

    # Option 2: Use a whitelist approach for specific operations
    allowed_operations = {
        'add': lambda x, y: x + y,
        'subtract': lambda x, y: x - y,
        'multiply': lambda x, y: x * y
    }

    def safe_operation(operation, x, y):
        if operation in allowed_operations:
            return allowed_operations[operation](x, y)
        raise ValueError("Operation not allowed")
                    """
                },
                "tools": ["bandit", "semgrep", "pylint"],
                "additional_resources": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                    "https://portswigger.net/web-security/os-command-injection"
                ]
            },
            "hardcoded_secrets": {
                "summary": "Move all secrets to secure external storage and access them at runtime",
                "steps": [
                    "Remove all hardcoded credentials from source code",
                    "Use environment variables for configuration",
                    "Implement a secrets management solution",
                    "Set up proper key rotation procedures",
                    "Add pre-commit hooks to prevent committing secrets"
                ],
                "code_example": {
                    "vulnerable": """
    # Hardcoded credentials in source code
    API_KEY = "1234567890abcdef"
    DATABASE_PASSWORD = "super_secret_password"
                    """,
                    "secure": """
    # Option 1: Use environment variables
    import os

    API_KEY = os.environ.get("API_KEY")
    DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD")

    # Option 2: Use a dedicated secrets manager
    from aws_secretsmanager_caching import SecretCache
    cache = SecretCache()

    def get_secret(secret_id):
        return cache.get_secret_string(secret_id)

    API_KEY = get_secret("app/api_key")
    DATABASE_PASSWORD = get_secret("app/db_password")
                    """
                },
                "tools": ["detect-secrets", "git-secrets", "trufflehog"],
                "additional_resources": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
                    "https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning"
                ]
            }
        }
        
        # Default remediation for unknown categories
        default_remediation = {
            "summary": f"Review and secure the {category.replace('_', ' ')} vulnerability according to security best practices",
            "steps": [
                "Review affected code for security weaknesses",
                "Apply input validation and output encoding",
                "Follow the principle of least privilege",
                "Implement proper error handling"
            ],
            "code_example": {
                "vulnerable": f"# No specific example available for {category}",
                "secure": f"# No specific example available for {category}"
            },
            "tools": ["Security code scanning tools", "OWASP resources"],
            "additional_resources": [
                "https://owasp.org/www-project-top-ten/",
                "https://cheatsheetseries.owasp.org/"
            ]
        }
        
        return remediation_guidance.get(category, default_remediation)
    
    def _generate_security_insights_overview(self, critical_findings: List[Dict[str, Any]], all_findings: List[DetailedFinding]) -> Dict[str, Any]:
        """
        Generate a comprehensive security overview with insights, patterns,
        and strategic recommendations.
        """
        # Count findings by severity
        severity_counts = {
            "critical": len([f for f in all_findings if f.severity == SeverityLevel.CRITICAL]),
            "high": len([f for f in all_findings if f.severity == SeverityLevel.HIGH]),
            "medium": len([f for f in all_findings if f.severity == SeverityLevel.MEDIUM]),
            "low": len([f for f in all_findings if f.severity == SeverityLevel.LOW]),
            "info": len([f for f in all_findings if f.severity == SeverityLevel.INFO])
        }
        
        # Calculate risk score
        risk_score = (
            severity_counts["critical"] * 10 +
            severity_counts["high"] * 7 +
            severity_counts["medium"] * 4 +
            severity_counts["low"] * 2 +
            severity_counts["info"] * 1
        )
        
        # Determine overall security posture
        if severity_counts["critical"] > 5 or risk_score > 50:
            security_posture = "Critical Risk"
            posture_description = "The application has critical security vulnerabilities that require immediate attention."
        elif severity_counts["critical"] > 0 or severity_counts["high"] > 5:
            security_posture = "High Risk"
            posture_description = "The application has significant security risks that should be addressed promptly."
        elif severity_counts["high"] > 0 or severity_counts["medium"] > 10:
            security_posture = "Moderate Risk"
            posture_description = "The application has security concerns that should be addressed in the next development cycle."
        elif severity_counts["medium"] > 0 or severity_counts["low"] > 0:
            security_posture = "Low Risk"
            posture_description = "The application has minor security concerns that should be reviewed."
        else:
            security_posture = "Minimal Risk"
            posture_description = "No significant security issues were identified."
        
        # Identify potential attack chains
        attack_chains = []
        if any(f["category"] == "hardcoded_secrets" for f in critical_findings) and any(f["category"] in ["code_injection", "command_injection", "unsafe_deserialization"] for f in critical_findings):
            attack_chains.append({
                "name": "Credential Exposure to Code Execution Chain",
                "description": "Exposed credentials could be used to gain initial access, followed by code injection to achieve remote code execution",
                "severity": "Critical",
                "mitigation": "Prioritize fixing both credential storage and code injection issues"
            })
        
        if any(f["category"] == "sql_injection" for f in critical_findings) and any(f["category"] == "information_disclosure" for f in critical_findings):
            attack_chains.append({
                "name": "Data Theft Chain",
                "description": "SQL injection could be used to extract sensitive data, exacerbated by information disclosure vulnerabilities",
                "severity": "Critical",
                "mitigation": "Implement parameterized queries and proper error handling"
            })
        
        # Generate key insights
        insights = []
        if severity_counts["critical"] > 0:
            insights.append(f"Critical vulnerabilities were found that could lead to system compromise")
        
        if any(f["category"] == "hardcoded_secrets" for f in critical_findings):
            insights.append("Credentials are exposed in source code, creating significant security risks")
        
        if any(f["category"] in ["code_injection", "unsafe_deserialization"] for f in critical_findings):
            insights.append("Remote code execution vulnerabilities could allow attackers to compromise the system")
        
        # Add model agreement insight
        if critical_findings:
            max_agreement = max(f["models_count"] for f in critical_findings)
            if max_agreement >= 3:
                insights.append(f"High confidence in findings: {max_agreement} models agreed on critical issues")
        
        # Strategic recommendations
        strategic_recommendations = [
            {
                "title": "Implement Secure Development Lifecycle",
                "description": "Integrate security throughout the development process with code reviews, security testing, and developer training",
                "timeframe": "Long-term",
                "effort": "High",
                "impact": "High"
            }
        ]
        
        if any(f["category"] == "hardcoded_secrets" for f in critical_findings):
            strategic_recommendations.append({
                "title": "Secrets Management Solution",
                "description": "Implement a centralized secrets management system and remove all hardcoded credentials from code",
                "timeframe": "Short-term",
                "effort": "Medium",
                "impact": "High"
            })
        
        if any(f["category"] in ["code_injection", "unsafe_deserialization", "sql_injection"] for f in critical_findings):
            strategic_recommendations.append({
                "title": "Input Validation Framework",
                "description": "Develop a comprehensive input validation framework and apply it consistently across the application",
                "timeframe": "Medium-term",
                "effort": "Medium",
                "impact": "High"
            })
        
        # Compliance impact
        compliance_impacts = []
        if any(f["category"] == "hardcoded_secrets" for f in critical_findings):
            compliance_impacts.append({
                "standard": "PCI DSS",
                "requirement": "3.5 and 8.2",
                "description": "Protect cryptographic keys and ensure proper credential management",
                "risk_level": "High"
            })
        
        if any(f["category"] in ["information_disclosure", "sql_injection"] for f in critical_findings):
            compliance_impacts.append({
                "standard": "GDPR",
                "requirement": "Article 32",
                "description": "Implement appropriate security measures to protect personal data",
                "risk_level": "High"
            })
        
        # Return comprehensive overview
        return {
            "security_posture": security_posture,
            "posture_description": posture_description,
            "risk_score": risk_score,
            "severity_distribution": severity_counts,
            "insights": insights,
            "attack_chains": attack_chains,
            "strategic_recommendations": strategic_recommendations,
            "compliance_impacts": compliance_impacts,
            "critical_findings_count": len(critical_findings),
            "agreement_level": "High" if critical_findings and max(f["models_count"] for f in critical_findings) >= 4 else "Medium",
            "action_priority": "Immediate" if security_posture in ["Critical Risk", "High Risk"] else "Planned"
        }
    
    def _get_comprehensive_compliance_mapping(self, category: str) -> Dict[str, Any]:
        """Generate detailed compliance mapping across all major frameworks."""
        
        comprehensive_mappings = {
            "unsafe_deserialization": {
                "owasp_top_10": {
                    "category": "A08:2021 - Software and Data Integrity Failures",
                    "description": "Applications that do not protect against integrity violations",
                    "risk_factor": "High",
                    "prevalence": "Common",
                    "detectability": "Average",
                    "technical_impact": "Severe",
                    "business_impact": "High",
                    "references": [
                        "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"
                    ]
                },
                "cwe_mapping": {
                    "primary": {
                        "id": "CWE-502",
                        "name": "Deserialization of Untrusted Data",
                        "description": "The application deserializes untrusted data without verification",
                        "likelihood": "High",
                        "impact": "High",
                        "url": "https://cwe.mitre.org/data/definitions/502.html"
                    },
                    "related": [
                        {"id": "CWE-20", "name": "Improper Input Validation"},
                        {"id": "CWE-94", "name": "Improper Control of Generation of Code"}
                    ]
                },
                "nist_controls": {
                    "primary": "SI-10 - Information Input Validation",
                    "secondary": ["SI-3 - Malicious Code Protection", "SC-39 - Process Isolation"],
                    "control_family": "System and Information Integrity",
                    "implementation_guidance": "Validate all inputs and use secure deserialization methods"
                },
                "pci_dss": {
                    "requirements": ["6.5.1", "6.5.8"],
                    "descriptions": [
                        "6.5.1: Injection flaws, particularly SQL injection",
                        "6.5.8: Improper error handling"
                    ],
                    "applicability": "High - affects payment processing systems"
                },
                "gdpr_impact": {
                    "articles": ["Article 32 - Security of processing"],
                    "risk_level": "High",
                    "data_protection_impact": "Could lead to unauthorized access to personal data",
                    "breach_notification": "Required if personal data is compromised"
                },
                "iso_27001": {
                    "controls": ["A.14.2.1", "A.14.2.5"],
                    "annex_a": "A.14 - System acquisition, development and maintenance"
                },
                "industry_specific": {
                    "healthcare_hipaa": {
                        "applicable": True,
                        "safeguards": ["Technical Safeguards - Access Control"],
                        "risk": "PHI exposure through code execution"
                    },
                    "financial_sox": {
                        "applicable": True,
                        "section": "404 - Internal Controls",
                        "risk": "Financial data integrity compromise"
                    }
                }
            },
            "code_injection": {
                "owasp_top_10": {
                    "category": "A03:2021 - Injection",
                    "description": "Application is vulnerable to injection attacks",
                    "risk_factor": "High",
                    "prevalence": "Common",
                    "detectability": "Average",
                    "technical_impact": "Severe",
                    "business_impact": "High",
                    "references": [
                        "https://owasp.org/Top10/A03_2021-Injection/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html"
                    ]
                },
                "cwe_mapping": {
                    "primary": {
                        "id": "CWE-94",
                        "name": "Improper Control of Generation of Code",
                        "description": "Code injection allows execution of arbitrary code",
                        "likelihood": "Medium",
                        "impact": "High",
                        "url": "https://cwe.mitre.org/data/definitions/94.html"
                    },
                    "related": [
                        {"id": "CWE-20", "name": "Improper Input Validation"},
                        {"id": "CWE-95", "name": "Improper Neutralization of Directives"}
                    ]
                },
                "nist_controls": {
                    "primary": "SI-10 - Information Input Validation",
                    "secondary": ["SI-3 - Malicious Code Protection", "AC-6 - Least Privilege"],
                    "control_family": "System and Information Integrity",
                    "implementation_guidance": "Implement input validation and avoid dynamic code execution"
                },
                "pci_dss": {
                    "requirements": ["6.5.1", "6.5.7"],
                    "descriptions": [
                        "6.5.1: Injection flaws",
                        "6.5.7: Cross-site scripting (XSS)"
                    ],
                    "applicability": "Critical - could compromise payment systems"
                },
                "gdpr_impact": {
                    "articles": ["Article 32 - Security of processing", "Article 25 - Data protection by design"],
                    "risk_level": "Critical",
                    "data_protection_impact": "Code execution could access all personal data",
                    "breach_notification": "Mandatory within 72 hours"
                }
            },
            "hardcoded_secrets": {
                "owasp_top_10": {
                    "category": "A07:2021 - Identification and Authentication Failures",
                    "description": "Improper implementation of authentication and session management",
                    "risk_factor": "High",
                    "prevalence": "Common",
                    "detectability": "Easy",
                    "technical_impact": "Severe",
                    "business_impact": "High",
                    "references": [
                        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
                    ]
                },
                "cwe_mapping": {
                    "primary": {
                        "id": "CWE-798",
                        "name": "Use of Hard-coded Credentials",
                        "description": "Software contains hard-coded credentials",
                        "likelihood": "High",
                        "impact": "High",
                        "url": "https://cwe.mitre.org/data/definitions/798.html"
                    },
                    "related": [
                        {"id": "CWE-259", "name": "Use of Hard-coded Password"},
                        {"id": "CWE-321", "name": "Use of Hard-coded Cryptographic Key"}
                    ]
                },
                "pci_dss": {
                    "requirements": ["3.5", "8.2.1", "8.3"],
                    "descriptions": [
                        "3.5: Protect stored cardholder data",
                        "8.2.1: Strong authentication for all system components",
                        "8.3: Secure all authentication mechanisms"
                    ],
                    "applicability": "Critical - violates fundamental PCI DSS requirements"
                },
                "gdpr_impact": {
                    "articles": ["Article 32 - Security of processing", "Article 25 - Data protection by design"],
                    "risk_level": "High",
                    "data_protection_impact": "Exposed credentials could lead to data breaches",
                    "breach_notification": "Required if leads to unauthorized access"
                }
            }
        }
        
        return comprehensive_mappings.get(category, {
            "owasp_top_10": {"category": "Unknown", "description": "No specific mapping available"},
            "cwe_mapping": {"primary": {"id": "Unknown", "name": "No mapping available"}},
            "compliance_notes": "Review against organization-specific compliance requirements"
        })

    def _generate_threat_analysis(self, category: str, findings: List[DetailedFinding]) -> Dict[str, Any]:
        """Generate comprehensive threat analysis including attack vectors and scenarios."""
        
        threat_profiles = {
            "unsafe_deserialization": {
                "threat_actors": [
                    {
                        "type": "Advanced Persistent Threat (APT)",
                        "motivation": "Espionage, data theft",
                        "capability": "High",
                        "likelihood": "Medium"
                    },
                    {
                        "type": "Cybercriminals",
                        "motivation": "Financial gain, ransomware",
                        "capability": "Medium-High",
                        "likelihood": "High"
                    },
                    {
                        "type": "Script Kiddies",
                        "motivation": "Vandalism, proof of concept",
                        "capability": "Low-Medium",
                        "likelihood": "Medium"
                    }
                ],
                "attack_vectors": [
                    {
                        "vector": "Malicious Object Injection",
                        "description": "Crafting serialized objects with malicious payloads that execute upon deserialization",
                        "complexity": "Medium",
                        "detection_difficulty": "High",
                        "payload_examples": ["Reverse shell", "File system access", "Memory corruption"]
                    },
                    {
                        "vector": "Gadget Chain Exploitation",
                        "description": "Using existing classes in the application to chain operations for code execution",
                        "complexity": "High",
                        "detection_difficulty": "Very High",
                        "payload_examples": ["Library function abuse", "Constructor manipulation", "Method chaining"]
                    }
                ],
                "kill_chain_mapping": {
                    "reconnaissance": "Identify deserialization endpoints through fuzzing or code analysis",
                    "weaponization": "Create malicious serialized objects with exploit payloads",
                    "delivery": "Submit crafted objects through API endpoints or file uploads",
                    "exploitation": "Trigger deserialization to execute arbitrary code",
                    "installation": "Deploy backdoors or persistence mechanisms",
                    "command_control": "Establish communication channels for remote access",
                    "actions_objectives": "Data exfiltration, lateral movement, or destructive activities"
                },
                "real_world_examples": [
                    {
                        "incident": "Jenkins CVE-2017-1000353",
                        "year": "2017",
                        "impact": "Remote code execution",
                        "description": "Java deserialization vulnerability in Jenkins allowing unauthenticated RCE"
                    },
                    {
                        "incident": "Apache Struts CVE-2017-9805",
                        "year": "2017", 
                        "impact": "Remote code execution",
                        "description": "REST plugin deserialization vulnerability affecting Equifax breach"
                    }
                ]
            },
            "code_injection": {
                "threat_actors": [
                    {
                        "type": "Web Application Attackers",
                        "motivation": "System compromise, data theft",
                        "capability": "Medium-High",
                        "likelihood": "High"
                    },
                    {
                        "type": "Insider Threats",
                        "motivation": "Privilege escalation, unauthorized access",
                        "capability": "Variable",
                        "likelihood": "Low-Medium"
                    }
                ],
                "attack_vectors": [
                    {
                        "vector": "Direct Function Injection",
                        "description": "Injecting malicious code directly into eval() or exec() functions",
                        "complexity": "Low",
                        "detection_difficulty": "Low-Medium",
                        "payload_examples": ["System commands", "File operations", "Network connections"]
                    },
                    {
                        "vector": "Template Injection",
                        "description": "Exploiting server-side template engines to execute code",
                        "complexity": "Medium",
                        "detection_difficulty": "Medium",
                        "payload_examples": ["Template syntax abuse", "Object method access", "Import statements"]
                    }
                ],
                "kill_chain_mapping": {
                    "reconnaissance": "Identify code execution points through input testing",
                    "weaponization": "Craft payloads that execute within application context",
                    "delivery": "Submit malicious input through user interfaces or APIs",
                    "exploitation": "Trigger code execution through vulnerable functions",
                    "installation": "Execute additional payloads or establish persistence",
                    "command_control": "Use code execution for communication or data transfer",
                    "actions_objectives": "Data access, system control, or service disruption"
                }
            },
            "hardcoded_secrets": {
                "threat_actors": [
                    {
                        "type": "Repository Miners",
                        "motivation": "Credential harvesting, unauthorized access",
                        "capability": "Low-Medium",
                        "likelihood": "High"
                    },
                    {
                        "type": "Supply Chain Attackers",
                        "motivation": "Downstream compromise",
                        "capability": "High", 
                        "likelihood": "Medium"
                    }
                ],
                "attack_vectors": [
                    {
                        "vector": "Source Code Mining",
                        "description": "Automated scanning of code repositories for exposed credentials",
                        "complexity": "Low",
                        "detection_difficulty": "Low",
                        "payload_examples": ["GitHub secret scanning", "Git history analysis", "Dependency scanning"]
                    },
                    {
                        "vector": "Binary Analysis",
                        "description": "Extracting hardcoded secrets from compiled applications",
                        "complexity": "Medium",
                        "detection_difficulty": "Medium",
                        "payload_examples": ["String analysis", "Reverse engineering", "Memory dumping"]
                    }
                ],
                "exposure_timeline": {
                    "immediate": "Secrets exposed as soon as code is committed",
                    "discovery": "Automated tools can find secrets within hours",
                    "exploitation": "Immediate access to protected resources",
                    "persistence": "Secrets remain valid until manually rotated"
                }
            }
        }
        
        default_profile = {
            "threat_actors": [{"type": "General Attackers", "capability": "Variable", "likelihood": "Medium"}],
            "attack_vectors": [{"vector": "Standard Exploitation", "complexity": "Unknown", "detection_difficulty": "Unknown"}],
            "kill_chain_mapping": {},
            "real_world_examples": []
        }
        
        profile = threat_profiles.get(category, default_profile)
        
        # Add context-specific analysis
        profile["findings_context"] = {
            "instances_found": len(findings),
            "affected_files": len(set(f.file for f in findings)),
            "criticality_assessment": "High" if any(f.severity.value == "critical" for f in findings) else "Medium",
            "attack_surface": self._calculate_attack_surface(findings)
        }
        
        return profile

    def _calculate_attack_surface(self, findings: List[DetailedFinding]) -> Dict[str, Any]:
        """Calculate the attack surface based on findings distribution."""
        file_types = set()
        directories = set()
        
        for finding in findings:
            file_path = Path(finding.file)
            file_types.add(file_path.suffix)
            directories.add(str(file_path.parent))
        
        return {
            "file_types_affected": list(file_types),
            "directories_affected": len(directories),
            "exposure_scope": "High" if len(directories) > 3 else "Medium" if len(directories) > 1 else "Low"
        }
    
    def _assess_business_impact(self, category: str, finding_count: int) -> Dict[str, Any]:
        """Assess comprehensive business impact including financial, operational, and reputational risks."""
        
        impact_assessments = {
            "unsafe_deserialization": {
                "financial_impact": {
                    "direct_costs": {
                        "incident_response": "$50,000 - $200,000",
                        "system_recovery": "$25,000 - $100,000", 
                        "forensic_investigation": "$75,000 - $300,000",
                        "legal_fees": "$100,000 - $500,000"
                    },
                    "indirect_costs": {
                        "business_disruption": "$500,000 - $5,000,000",
                        "customer_churn": "$250,000 - $2,000,000",
                        "regulatory_fines": "$100,000 - $50,000,000",
                        "reputation_recovery": "$1,000,000 - $10,000,000"
                    },
                    "total_estimated_impact": "$2,000,000 - $68,000,000"
                },
                "operational_impact": {
                    "service_availability": "Complete service outage during incident response",
                    "recovery_time": "2-4 weeks for full system restoration",
                    "resource_allocation": "Requires dedicated security and development teams",
                    "business_continuity": "Severe disruption to normal operations"
                },
                "reputational_impact": {
                    "customer_trust": "Severe damage - customers may lose confidence in security",
                    "market_perception": "Negative impact on company valuation and partnerships",
                    "media_attention": "High likelihood of negative press coverage",
                    "recovery_timeline": "6-12 months for reputation recovery"
                },
                "regulatory_compliance": {
                    "breach_notification": "Required within 72 hours under GDPR",
                    "audit_requirements": "Mandatory security audits and remediation reporting",
                    "compliance_violations": "Potential violations of PCI DSS, HIPAA, SOX",
                    "ongoing_monitoring": "Enhanced regulatory oversight for 1-2 years"
                }
            },
            "code_injection": {
                "financial_impact": {
                    "direct_costs": {
                        "incident_response": "$40,000 - $150,000",
                        "system_recovery": "$20,000 - $75,000",
                        "security_remediation": "$50,000 - $200,000",
                        "legal_consultation": "$25,000 - $100,000"
                    },
                    "indirect_costs": {
                        "business_disruption": "$300,000 - $3,000,000",
                        "data_breach_costs": "$150,000 - $10,000,000",
                        "regulatory_penalties": "$50,000 - $20,000,000",
                        "competitive_disadvantage": "$500,000 - $5,000,000"
                    },
                    "total_estimated_impact": "$1,135,000 - $38,525,000"
                },
                "operational_impact": {
                    "service_availability": "Potential service degradation or targeted outages",
                    "recovery_time": "1-3 weeks depending on compromise extent",
                    "resource_allocation": "Emergency security response team activation",
                    "business_continuity": "Moderate to severe operational disruption"
                }
            },
            "hardcoded_secrets": {
                "financial_impact": {
                    "direct_costs": {
                        "credential_rotation": "$10,000 - $50,000",
                        "access_review": "$15,000 - $40,000",
                        "security_assessment": "$25,000 - $75,000",
                        "monitoring_enhancement": "$30,000 - $100,000"
                    },
                    "indirect_costs": {
                        "unauthorized_usage": "$50,000 - $500,000",
                        "data_exposure": "$100,000 - $5,000,000",
                        "regulatory_fines": "$25,000 - $10,000,000",
                        "trust_rebuilding": "$200,000 - $2,000,000"
                    },
                    "total_estimated_impact": "$455,000 - $17,765,000"
                },
                "operational_impact": {
                    "service_availability": "Potential API rate limiting or service restrictions",
                    "recovery_time": "1-2 weeks for complete credential rotation",
                    "resource_allocation": "DevOps and security team coordination required",
                    "business_continuity": "Low to moderate operational impact"
                }
            }
        }
        
        # Scale impact based on finding count
        scaling_factors = {
            1: 1.0,
            2-5: 1.3,
            6-10: 1.6,
            11-20: 2.0,
            "20+": 2.5
        }
        
        scale_key = "20+" if finding_count > 20 else next(
            (k for k in scaling_factors.keys() if 
            (isinstance(k, int) and finding_count == k) or
            (isinstance(k, str) and "-" in k and 
            int(k.split("-")[0]) <= finding_count <= int(k.split("-")[1]))), 1
        )
        
        impact_data = impact_assessments.get(category, {
            "financial_impact": {"total_estimated_impact": "$100,000 - $1,000,000"},
            "operational_impact": {"service_availability": "Potential impact", "recovery_time": "Variable"},
            "reputational_impact": {"customer_trust": "Potential damage"}
        })
        
        # Add scaling context
        impact_data["scale_assessment"] = {
            "finding_count": finding_count,
            "impact_multiplier": scaling_factors.get(scale_key, 1.0),
            "severity_rationale": f"Impact scaled by {scaling_factors.get(scale_key, 1.0)}x due to {finding_count} instances found"
        }
        
        return impact_data
    
    def _generate_security_insights_overview(self, critical_findings: List[Dict[str, Any]], all_findings: List[DetailedFinding]) -> Dict[str, Any]:
        """Generate comprehensive security insights with strategic recommendations."""
        
        # Advanced risk scoring
        weighted_risk_score = 0
        for finding in all_findings:
            severity_weights = {
                SeverityLevel.CRITICAL: 15,
                SeverityLevel.HIGH: 10,
                SeverityLevel.MEDIUM: 5,
                SeverityLevel.LOW: 2,
                SeverityLevel.INFO: 1
            }
            # Weight by confidence and model agreement
            confidence_multiplier = finding.confidence
            consensus_multiplier = min(len(finding.found_by) / 6, 1.5)  # Cap at 1.5x
            
            weighted_risk_score += (
                severity_weights[finding.severity] * 
                confidence_multiplier * 
                consensus_multiplier
            )
        
        # Security maturity assessment
        security_maturity = self._assess_security_maturity(all_findings)
        
        # Attack surface analysis
        attack_surface = self._analyze_attack_surface_comprehensive(all_findings)
        
        # Strategic recommendations
        strategic_recommendations = self._generate_strategic_security_recommendations(critical_findings, all_findings)
        
        # Threat landscape assessment
        threat_landscape = self._assess_threat_landscape(critical_findings)
        
        return {
            "overall_security_posture": {
                "risk_score": round(weighted_risk_score, 2),
                "maturity_level": security_maturity["level"],
                "security_grade": self._calculate_security_grade(weighted_risk_score),
                "improvement_areas": security_maturity["improvement_areas"]
            },
            "critical_insights": [
                f"Found {len(critical_findings)} vulnerability categories with multi-model consensus",
                f"Attack surface spans {attack_surface['technologies']} different technologies",
                f"Security maturity level: {security_maturity['level']} - {security_maturity['description']}",
                f"Estimated remediation effort: {self._estimate_total_effort(critical_findings)}"
            ],
            "attack_surface_analysis": attack_surface,
            "threat_landscape": threat_landscape,
            "strategic_recommendations": strategic_recommendations,
            "security_metrics": {
                "vulnerability_density": len(all_findings) / max(1, len(set(f.file for f in all_findings))),
                "critical_vulnerability_ratio": len([f for f in all_findings if f.severity == SeverityLevel.CRITICAL]) / max(1, len(all_findings)),
                "consensus_reliability": len(critical_findings) / max(1, len(all_findings)),
                "remediation_urgency": "Immediate" if weighted_risk_score > 100 else "High" if weighted_risk_score > 50 else "Medium"
            }
        }

    def _assess_security_maturity(self, findings: List[DetailedFinding]) -> Dict[str, Any]:
        """Assess organizational security maturity based on vulnerability patterns."""
        
        critical_count = len([f for f in findings if f.severity == SeverityLevel.CRITICAL])
        high_count = len([f for f in findings if f.severity == SeverityLevel.HIGH])
        
        # Analyze vulnerability categories for maturity indicators
        categories = set(f.category for f in findings)
        
        # Maturity indicators
        has_basic_issues = any(cat in categories for cat in ['hardcoded_secrets', 'weak_crypto'])
        has_injection_issues = any(cat in categories for cat in ['sql_injection', 'code_injection', 'command_injection'])
        has_advanced_issues = any(cat in categories for cat in ['unsafe_deserialization', 'race_condition'])
        
        if critical_count > 10 or has_basic_issues:
            maturity_level = "Initial"
            description = "Basic security practices not consistently implemented"
            improvement_areas = [
                "Implement basic secure coding practices",
                "Establish security awareness training",
                "Deploy automated security scanning tools"
            ]
        elif critical_count > 5 or has_injection_issues:
            maturity_level = "Developing"
            description = "Some security practices in place but significant gaps remain"
            improvement_areas = [
                "Strengthen input validation frameworks",
                "Implement security code review processes",
                "Enhance security testing in CI/CD"
            ]
        elif critical_count > 0 or has_advanced_issues:
            maturity_level = "Defined"
            description = "Security practices established but not fully mature"
            improvement_areas = [
                "Implement advanced threat detection",
                "Enhance security architecture reviews",
                "Develop security champions program"
            ]
        else:
            maturity_level = "Managed"
            description = "Strong security practices with room for optimization"
            improvement_areas = [
                "Implement zero-trust architecture",
                "Enhance threat intelligence integration",
                "Optimize security operations"
            ]
        
        return {
            "level": maturity_level,
            "description": description,
            "improvement_areas": improvement_areas,
            "assessment_basis": f"Based on {len(findings)} findings across {len(categories)} vulnerability categories"
        }

    def _get_professional_category_name(self, category: str) -> str:
        """Convert technical category names to professional security terminology."""
        
        professional_names = {
            "unsafe_deserialization": "Unsafe Object Deserialization",
            "code_injection": "Code Injection Vulnerability",
            "hardcoded_secrets": "Hardcoded Credentials Exposure",
            "sql_injection": "SQL Injection Vulnerability",
            "command_injection": "OS Command Injection",
            "xss": "Cross-Site Scripting (XSS)",
            "path_traversal": "Directory Traversal Vulnerability",
            "weak_crypto": "Cryptographic Weakness",
            "race_condition": "Race Condition Vulnerability",
            "information_disclosure": "Information Disclosure",
            "broken_access_control": "Broken Access Control",
            "auth_failures": "Authentication Bypass",
            "ssrf": "Server-Side Request Forgery (SSRF)",
            "xxe": "XML External Entity (XXE) Injection",
            "insecure_file_upload": "Unrestricted File Upload",
            "security_misconfiguration": "Security Misconfiguration",
            "vulnerable_components": "Vulnerable Dependencies",
            "insufficient_logging": "Inadequate Security Logging"
        }
        
        return professional_names.get(category, category.replace('_', ' ').title())

    def _get_confidence_level(self, confidence: float) -> str:
        """Convert numerical confidence to descriptive level."""
        
        if confidence >= 0.9:
            return "Very High"
        elif confidence >= 0.8:
            return "High"
        elif confidence >= 0.7:
            return "Medium-High"
        elif confidence >= 0.6:
            return "Medium"
        elif confidence >= 0.5:
            return "Medium-Low"
        elif confidence >= 0.4:
            return "Low"
        else:
            return "Very Low"

    def _assess_exploit_difficulty(self, category: str) -> Dict[str, Any]:
        """Assess the difficulty level for exploiting each vulnerability type."""
        
        exploit_assessments = {
            "unsafe_deserialization": {
                "difficulty": "Medium-High",
                "skill_level": "Intermediate to Advanced",
                "tools_required": ["Custom exploit development", "Application-specific gadget chains"],
                "time_to_exploit": "2-8 hours for experienced attacker",
                "success_probability": "High with proper reconnaissance",
                "detection_likelihood": "Low - often appears as normal application traffic",
                "barriers": [
                    "Requires understanding of serialization format",
                    "Need to identify available gadget chains",
                    "May require custom payload development"
                ]
            },
            "code_injection": {
                "difficulty": "Low-Medium",
                "skill_level": "Beginner to Intermediate",
                "tools_required": ["Web proxy tools", "Payload lists", "Basic scripting knowledge"],
                "time_to_exploit": "30 minutes to 2 hours",
                "success_probability": "Very High if input reaches eval/exec",
                "detection_likelihood": "Medium - may trigger application errors",
                "barriers": [
                    "Need to identify injection points",
                    "May require bypassing input filters",
                    "Payload encoding might be necessary"
                ]
            },
            "hardcoded_secrets": {
                "difficulty": "Very Low",
                "skill_level": "Beginner",
                "tools_required": ["Source code access", "String analysis tools", "Git history tools"],
                "time_to_exploit": "5-30 minutes",
                "success_probability": "Very High with code access",
                "detection_likelihood": "Very Low - passive reconnaissance",
                "barriers": [
                    "Requires source code or binary access",
                    "Secrets must still be valid"
                ]
            },
            "sql_injection": {
                "difficulty": "Low-Medium",
                "skill_level": "Beginner to Intermediate",
                "tools_required": ["SQLMap", "Burp Suite", "Manual testing"],
                "time_to_exploit": "30 minutes to 4 hours",
                "success_probability": "High with vulnerable endpoints",
                "detection_likelihood": "Medium-High - generates database errors",
                "barriers": [
                    "May require WAF bypass techniques",
                    "Database-specific syntax knowledge needed",
                    "Blind injection requires more time"
                ]
            },
            "command_injection": {
                "difficulty": "Medium",
                "skill_level": "Intermediate",
                "tools_required": ["Command injection payloads", "Shell encoding tools"],
                "time_to_exploit": "1-4 hours",
                "success_probability": "High with vulnerable functions",
                "detection_likelihood": "High - system commands may be logged",
                "barriers": [
                    "Input sanitization may filter commands",
                    "OS-specific payload requirements",
                    "Network egress restrictions"
                ]
            }
        }
        
        return exploit_assessments.get(category, {
            "difficulty": "Medium",
            "skill_level": "Intermediate",
            "tools_required": ["Standard security tools"],
            "time_to_exploit": "Variable",
            "success_probability": "Medium",
            "detection_likelihood": "Medium",
            "barriers": ["Requires vulnerability-specific analysis"]
        })

    def _get_attack_prerequisites(self, category: str) -> Dict[str, Any]:
        """Define prerequisites and conditions needed for successful exploitation."""
        
        prerequisites = {
            "unsafe_deserialization": {
                "access_requirements": [
                    "Ability to submit serialized data to application",
                    "Network access to vulnerable endpoints",
                    "Understanding of application's object structure"
                ],
                "technical_prerequisites": [
                    "Knowledge of target serialization format (pickle, Java, etc.)",
                    "Access to application dependencies for gadget chain analysis",
                    "Understanding of target platform and environment"
                ],
                "environmental_conditions": [
                    "Application must deserialize user-controlled data",
                    "Vulnerable classes must be available in classpath",
                    "Sufficient privileges for payload execution"
                ],
                "reconnaissance_needed": [
                    "Identify serialization endpoints",
                    "Map application dependencies",
                    "Analyze available object classes"
                ]
            },
            "code_injection": {
                "access_requirements": [
                    "User input reaches eval/exec functions",
                    "Ability to control input parameters",
                    "Network or application access"
                ],
                "technical_prerequisites": [
                    "Basic programming language knowledge",
                    "Understanding of code execution context",
                    "Payload encoding skills if needed"
                ],
                "environmental_conditions": [
                    "Dynamic code execution functions present",
                    "Insufficient input validation",
                    "Appropriate execution context permissions"
                ],
                "reconnaissance_needed": [
                    "Identify code execution endpoints",
                    "Test input validation mechanisms",
                    "Understand execution environment"
                ]
            },
            "hardcoded_secrets": {
                "access_requirements": [
                    "Source code repository access OR",
                    "Binary/package access for reverse engineering",
                    "Git history access (if secrets were committed)"
                ],
                "technical_prerequisites": [
                    "Basic text search capabilities",
                    "Understanding of common secret formats",
                    "Knowledge of where secrets are typically used"
                ],
                "environmental_conditions": [
                    "Secrets must still be valid and active",
                    "Services using secrets must be accessible",
                    "No additional authentication layers"
                ],
                "reconnaissance_needed": [
                    "Identify secret storage patterns",
                    "Map services that use discovered secrets",
                    "Verify secret validity and scope"
                ]
            }
        }
        
        return prerequisites.get(category, {
            "access_requirements": ["Network or application access"],
            "technical_prerequisites": ["Basic security testing knowledge"],
            "environmental_conditions": ["Vulnerable configuration present"],
            "reconnaissance_needed": ["Basic application mapping"]
        })

    def _estimate_financial_impact(self, category: str) -> Dict[str, Any]:
        """Provide detailed financial impact estimates based on industry data."""
        
        # Based on 2024 security incident cost data
        financial_impacts = {
            "unsafe_deserialization": {
                "incident_probability": 0.75,  # 75% chance if exploited
                "cost_ranges": {
                    "small_business": {
                        "min": 100000,
                        "max": 500000,
                        "currency": "USD",
                        "factors": ["Limited data exposure", "Quick containment possible"]
                    },
                    "medium_enterprise": {
                        "min": 500000,
                        "max": 2500000,
                        "currency": "USD", 
                        "factors": ["Moderate data exposure", "Complex recovery"]
                    },
                    "large_enterprise": {
                        "min": 2500000,
                        "max": 15000000,
                        "currency": "USD",
                        "factors": ["Extensive data exposure", "Regulatory penalties", "Brand damage"]
                    }
                },
                "cost_breakdown": {
                    "immediate_response": 0.15,  # 15% of total cost
                    "investigation": 0.20,       # 20%
                    "remediation": 0.25,         # 25%
                    "business_disruption": 0.30, # 30%
                    "legal_regulatory": 0.10     # 10%
                },
                "industry_multipliers": {
                    "healthcare": 1.8,
                    "financial": 2.2,
                    "government": 1.6,
                    "retail": 1.4,
                    "technology": 1.3,
                    "manufacturing": 1.2
                }
            },
            "code_injection": {
                "incident_probability": 0.85,
                "cost_ranges": {
                    "small_business": {"min": 75000, "max": 300000, "currency": "USD"},
                    "medium_enterprise": {"min": 300000, "max": 1500000, "currency": "USD"},
                    "large_enterprise": {"min": 1500000, "max": 8000000, "currency": "USD"}
                },
                "cost_breakdown": {
                    "immediate_response": 0.20,
                    "investigation": 0.15,
                    "remediation": 0.30,
                    "business_disruption": 0.25,
                    "legal_regulatory": 0.10
                }
            },
            "hardcoded_secrets": {
                "incident_probability": 0.60,
                "cost_ranges": {
                    "small_business": {"min": 25000, "max": 150000, "currency": "USD"},
                    "medium_enterprise": {"min": 150000, "max": 750000, "currency": "USD"},
                    "large_enterprise": {"min": 750000, "max": 3000000, "currency": "USD"}
                },
                "cost_breakdown": {
                    "immediate_response": 0.25,
                    "investigation": 0.15,
                    "remediation": 0.35,
                    "business_disruption": 0.15,
                    "legal_regulatory": 0.10
                }
            }
        }
        
        impact_data = financial_impacts.get(category, {
            "incident_probability": 0.5,
            "cost_ranges": {
                "small_business": {"min": 50000, "max": 200000, "currency": "USD"},
                "medium_enterprise": {"min": 200000, "max": 1000000, "currency": "USD"},
                "large_enterprise": {"min": 1000000, "max": 5000000, "currency": "USD"}
            }
        })
        
        # Add contextual factors
        impact_data["influencing_factors"] = {
            "data_sensitivity": "Higher costs for PII, PHI, financial data",
            "regulatory_environment": "GDPR, HIPAA, PCI DSS compliance requirements",
            "business_model": "Customer-facing vs internal systems",
            "geographic_scope": "Multi-jurisdiction incidents increase costs",
            "incident_timing": "Peak business periods amplify impact"
        }
        
        return impact_data

    def _assess_reputation_impact(self, category: str) -> Dict[str, Any]:
        """Assess potential reputational damage and recovery requirements."""
        
        reputation_impacts = {
            "unsafe_deserialization": {
                "severity": "High",
                "public_attention": "High - likely media coverage for data breaches",
                "customer_impact": {
                    "trust_loss": "Severe - customers question technical competence",
                    "churn_probability": "15-30% customer loss possible",
                    "acquisition_impact": "Significant reduction in new customer acquisition"
                },
                "stakeholder_impact": {
                    "investors": "Major concern about technical leadership and security posture",
                    "partners": "May require additional security certifications",
                    "regulators": "Increased scrutiny and potential compliance reviews"
                },
                "recovery_timeline": {
                    "immediate": "Crisis communication within 24 hours",
                    "short_term": "3-6 months for basic trust restoration",
                    "long_term": "12-24 months for full reputation recovery"
                },
                "recovery_requirements": [
                    "Transparent incident communication",
                    "Independent security audit and certification",
                    "Implementation of advanced security measures",
                    "Regular security posture reporting"
                ]
            },
            "code_injection": {
                "severity": "Medium-High",
                "public_attention": "Medium - depends on data accessed",
                "customer_impact": {
                    "trust_loss": "Moderate to severe",
                    "churn_probability": "10-20% customer loss",
                    "acquisition_impact": "Temporary reduction in growth"
                },
                "recovery_timeline": {
                    "short_term": "2-4 months for basic recovery",
                    "long_term": "6-12 months for full recovery"
                }
            },
            "hardcoded_secrets": {
                "severity": "Medium",
                "public_attention": "Low to Medium - often not public unless breached",
                "customer_impact": {
                    "trust_loss": "Moderate - seen as preventable mistake",
                    "churn_probability": "5-15% customer loss",
                    "acquisition_impact": "Minimal if handled properly"
                },
                "recovery_timeline": {
                    "short_term": "1-3 months with proper remediation",
                    "long_term": "3-6 months for full recovery"
                }
            }
        }
        
        return reputation_impacts.get(category, {
            "severity": "Medium",
            "public_attention": "Variable",
            "recovery_timeline": {"short_term": "1-6 months", "long_term": "6-12 months"}
        })

    def _get_audit_implications(self, category: str) -> Dict[str, Any]:
        """Define audit implications and requirements for each vulnerability type."""
        
        audit_implications = {
            "unsafe_deserialization": {
                "compliance_frameworks": {
                    "SOX": {
                        "section": "404 - Internal Controls",
                        "implication": "Material weakness in IT controls",
                        "remediation_required": "Immediate fixes with management certification"
                    },
                    "PCI_DSS": {
                        "requirement": "6.5 - Secure Coding",
                        "implication": "Potential compliance failure",
                        "remediation_required": "Code review and penetration testing"
                    },
                    "ISO27001": {
                        "control": "A.14.2.1 - Secure development policy",
                        "implication": "Control effectiveness questioned",
                        "remediation_required": "Process improvement and additional controls"
                    }
                },
                "audit_requirements": [
                    "Independent security assessment",
                    "Code review by qualified personnel",
                    "Penetration testing of affected systems",
                    "Documentation of remediation efforts"
                ],
                "documentation_needed": [
                    "Vulnerability assessment report",
                    "Remediation plan with timelines",
                    "Testing evidence post-remediation",
                    "Process improvements implemented"
                ],
                "ongoing_monitoring": [
                    "Regular code scanning for similar issues",
                    "Security training completion tracking",
                    "Quarterly security assessments"
                ]
            },
            "code_injection": {
                "compliance_frameworks": {
                    "SOX": {
                        "section": "302 - Corporate Responsibility",
                        "implication": "Potential material weakness",
                        "remediation_required": "CEO/CFO certification of controls"
                    },
                    "GDPR": {
                        "article": "32 - Security of Processing",
                        "implication": "Inadequate technical measures",
                        "remediation_required": "Privacy impact assessment update"
                    }
                },
                "audit_requirements": [
                    "Input validation review",
                    "Dynamic application security testing",
                    "Code quality assessment"
                ]
            },
            "hardcoded_secrets": {
                "compliance_frameworks": {
                    "PCI_DSS": {
                        "requirement": "3.5 - Cryptographic Key Management",
                        "implication": "Key management failure",
                        "remediation_required": "Complete key rotation and process overhaul"
                    },
                    "HIPAA": {
                        "rule": "Security Rule - Access Control",
                        "implication": "Inadequate access controls",
                        "remediation_required": "Risk assessment update"
                    }
                },
                "audit_requirements": [
                    "Credential management review",
                    "Secret scanning implementation",
                    "Access control validation"
                ]
            }
        }
        
        return audit_implications.get(category, {
            "compliance_frameworks": {"General": {"implication": "Potential compliance impact"}},
            "audit_requirements": ["Security review required"],
            "documentation_needed": ["Remediation evidence"]
        })

    def _get_comprehensive_technical_description(self, category: str) -> Dict[str, Any]:
        """Provide detailed technical analysis of vulnerability mechanisms."""
        
        technical_descriptions = {
            "unsafe_deserialization": {
                "mechanism": """
                    Unsafe deserialization occurs when an application deserializes data from untrusted sources 
                    without proper validation. During deserialization, many programming languages can execute 
                    code as part of object reconstruction, including constructor methods, property setters, 
                    and special deserialization hooks (__reduce__ in Python, readObject in Java).
                    
                    Attackers exploit this by crafting malicious serialized objects that, when deserialized,
                    execute arbitrary code. The attack leverages 'gadget chains' - sequences of existing 
                    classes in the application or its dependencies that can be chained together to achieve
                    code execution when their methods are called during deserialization.
                """,
                "technical_details": {
                    "affected_languages": ["Python (pickle)", "Java", "PHP", ".NET", "Ruby", "JavaScript"],
                    "attack_vectors": [
                        "Malicious pickle objects in Python",
                        "Java serialization gadget chains", 
                        "PHP object injection",
                        ".NET BinaryFormatter exploitation"
                    ],
                    "exploitation_techniques": [
                        "Gadget chain construction using existing classes",
                        "Custom serialization hook exploitation",
                        "Type confusion attacks during deserialization",
                        "Memory corruption through object state manipulation"
                    ]
                },
                "code_patterns": {
                    "vulnerable": [
                        "pickle.loads(untrusted_data)",
                        "yaml.load(user_input)",
                        "ObjectInputStream.readObject()",
                        "BinaryFormatter.Deserialize()"
                    ],
                    "secure_alternatives": [
                        "json.loads() for data-only serialization",
                        "yaml.safe_load() with restricted loaders",
                        "Custom serialization with allowlists",
                        "Cryptographic signing of serialized data"
                    ]
                }
            },
            "code_injection": {
                "mechanism": """
                    Code injection vulnerabilities allow attackers to execute arbitrary code by inserting
                    malicious code into contexts where it will be interpreted and executed. This occurs
                    when user input is directly passed to code evaluation functions without proper
                    sanitization or when dynamic code generation incorporates untrusted data.
                    
                    The vulnerability is particularly dangerous because the injected code executes with
                    the same privileges as the application, potentially allowing complete system compromise.
                    Modern applications may be vulnerable through template engines, expression evaluators,
                    or dynamic import mechanisms in addition to obvious eval() functions.
                """,
                "technical_details": {
                    "injection_points": [
                        "eval() and exec() functions",
                        "Template engines (Jinja2, Velocity, etc.)",
                        "Expression language evaluators",
                        "Dynamic import/require statements",
                        "Scripting engine integration"
                    ],
                    "payload_types": [
                        "Direct code execution payloads",
                        "Import-based attacks",
                        "Template syntax abuse",
                        "Expression language injection"
                    ]
                },
                "code_patterns": {
                    "vulnerable": [
                        "eval(user_input)",
                        "exec(f'result = {user_expression}')",
                        "template.render(user_template)",
                        "new Function(user_code)()"
                    ],
                    "secure_alternatives": [
                        "ast.literal_eval() for safe evaluation",
                        "Predefined function mappings",
                        "Sandboxed execution environments",
                        "Input validation with allowlists"
                    ]
                }
            },
            "hardcoded_secrets": {
                "mechanism": """
                    Hardcoded secrets represent credentials, API keys, encryption keys, or other sensitive
                    values embedded directly in source code. This practice creates multiple security risks:
                    the secrets are exposed to anyone with code access, they cannot be easily rotated,
                    and they often propagate across different environments.
                    
                    The vulnerability is particularly problematic in modern development environments where
                    code is version-controlled, shared among team members, and often stored in cloud
                    repositories. Even private repositories can become public accidentally, and the
                    secrets remain in git history even after removal.
                """,
                "technical_details": {
                    "common_locations": [
                        "Configuration files committed to source control",
                        "Environment variable defaults in code",
                        "Test files with real credentials",
                        "Documentation with example configurations",
                        "Build scripts and deployment configurations"
                    ],
                    "exposure_vectors": [
                        "Public repository access",
                        "Git history exposure",
                        "Source code sharing",
                        "Backup and archive exposure",
                        "Binary reverse engineering"
                    ]
                },
                "detection_patterns": [
                    "API key patterns (sk-, pk-, AKIA-, etc.)",
                    "Password assignments with actual values",
                    "Private key headers (-----BEGIN PRIVATE KEY-----)",
                    "Database connection strings with embedded passwords",
                    "JWT secrets and signing keys"
                ]
            }
        }
        
        return technical_descriptions.get(category, {
            "mechanism": f"Technical details for {category} vulnerability type.",
            "technical_details": {"general": "Requires security-specific analysis"},
            "code_patterns": {"vulnerable": ["Various patterns"], "secure_alternatives": ["Security best practices"]}
        })

    def _analyze_affected_components(self, findings: List[DetailedFinding]) -> Dict[str, Any]:
        """Analyze which application components are affected by vulnerabilities."""
        
        component_analysis = {
            "affected_files": [],
            "component_mapping": {},
            "risk_distribution": {},
            "architectural_impact": {}
        }
        
        # Analyze file patterns to identify components
        for finding in findings:
            file_path = finding.file
            
            # Component identification based on file paths and patterns
            component_type = "unknown"
            if any(pattern in file_path.lower() for pattern in ['auth', 'login', 'session']):
                component_type = "authentication"
            elif any(pattern in file_path.lower() for pattern in ['api', 'rest', 'endpoint']):
                component_type = "api_layer"
            elif any(pattern in file_path.lower() for pattern in ['db', 'database', 'model']):
                component_type = "data_layer"
            elif any(pattern in file_path.lower() for pattern in ['ui', 'view', 'template']):
                component_type = "presentation_layer"
            elif any(pattern in file_path.lower() for pattern in ['admin', 'management']):
                component_type = "administration"
            elif any(pattern in file_path.lower() for pattern in ['config', 'setting']):
                component_type = "configuration"
            
            if file_path not in component_analysis["affected_files"]:
                component_analysis["affected_files"].append({
                    "path": file_path,
                    "component_type": component_type,
                    "vulnerability_count": 1,
                    "highest_severity": finding.severity.value,
                    "categories": [finding.category]
                })
            else:
                # Update existing file info
                for file_info in component_analysis["affected_files"]:
                    if file_info["path"] == file_path:
                        file_info["vulnerability_count"] += 1
                        if finding.category not in file_info["categories"]:
                            file_info["categories"].append(finding.category)
                        break
        
        # Group by component type
        component_summary = {}
        for file_info in component_analysis["affected_files"]:
            comp_type = file_info["component_type"]
            if comp_type not in component_summary:
                component_summary[comp_type] = {
                    "file_count": 0,
                    "vulnerability_count": 0,
                    "risk_level": "low"
                }
            component_summary[comp_type]["file_count"] += 1
            component_summary[comp_type]["vulnerability_count"] += file_info["vulnerability_count"]
        
        # Assess risk levels
        for comp_type, summary in component_summary.items():
            if summary["vulnerability_count"] >= 10:
                summary["risk_level"] = "critical"
            elif summary["vulnerability_count"] >= 5:
                summary["risk_level"] = "high"
            elif summary["vulnerability_count"] >= 2:
                summary["risk_level"] = "medium"
            else:
                summary["risk_level"] = "low"
        
        component_analysis["component_mapping"] = component_summary
        component_analysis["risk_distribution"] = {
            "highest_risk_component": max(component_summary.items(), key=lambda x: x[1]["vulnerability_count"])[0] if component_summary else "none",
            "total_components_affected": len(component_summary),
            "critical_components": len([c for c in component_summary.values() if c["risk_level"] == "critical"])
        }
        
        return component_analysis

    def _assess_chain_risk(self, category: str, all_findings: List[DetailedFinding]) -> Dict[str, Any]:
        """Assess the risk of vulnerability chaining and compound attacks."""
        
        # Define vulnerability chains that are commonly exploited together
        dangerous_chains = {
            "rce_escalation": {
                "categories": ["unsafe_deserialization", "code_injection", "command_injection"],
                "description": "Remote code execution chain allowing complete system compromise",
                "risk_multiplier": 2.5
            },
            "data_extraction": {
                "categories": ["sql_injection", "information_disclosure", "path_traversal"],
                "description": "Data theft chain combining database and file system access",
                "risk_multiplier": 2.0
            },
            "auth_bypass": {
                "categories": ["hardcoded_secrets", "auth_failures", "broken_access_control"],
                "description": "Authentication bypass leading to unauthorized access",
                "risk_multiplier": 1.8
            },
            "persistence_chain": {
                "categories": ["code_injection", "insecure_file_upload", "weak_crypto"],
                "description": "Establishing persistent access through multiple vectors",
                "risk_multiplier": 1.6
            }
        }
        
        # Check which chains are present
        finding_categories = set(f.category for f in all_findings)
        present_chains = []
        
        for chain_name, chain_info in dangerous_chains.items():
            matching_categories = [cat for cat in chain_info["categories"] if cat in finding_categories]
            if len(matching_categories) >= 2:  # At least 2 components of the chain
                present_chains.append({
                    "name": chain_name,
                    "description": chain_info["description"],
                    "risk_multiplier": chain_info["risk_multiplier"],
                    "present_categories": matching_categories,
                    "completeness": len(matching_categories) / len(chain_info["categories"]),
                    "chain_risk": "High" if len(matching_categories) >= 3 else "Medium"
                })
        
        # Assess current category's role in chains
        category_chain_participation = []
        for chain_name, chain_info in dangerous_chains.items():
            if category in chain_info["categories"]:
                category_chain_participation.append({
                    "chain": chain_name,
                    "role": "enabler" if category == chain_info["categories"][0] else "escalator",
                    "description": chain_info["description"]
                })
        
        return {
            "chain_risk_level": "High" if len(present_chains) > 1 else "Medium" if present_chains else "Low",
            "present_vulnerability_chains": present_chains,
            "category_participation": category_chain_participation,
            "compound_risk_factors": {
                "multiple_attack_vectors": len(finding_categories) > 5,
                "cross_component_vulnerabilities": len(set(f.file for f in all_findings)) > 3,
                "high_severity_clustering": len([f for f in all_findings if f.severity.value in ["critical", "high"]]) > 5
            },
            "mitigation_priority": "Immediate" if len(present_chains) > 1 else "High" if present_chains else "Standard"
        }

    def _get_prevention_strategy(self, category: str) -> Dict[str, Any]:
        """Define comprehensive prevention strategies for each vulnerability type."""
        
        prevention_strategies = {
            "unsafe_deserialization": {
                "immediate_actions": [
                    "Replace unsafe deserialization with JSON or other data-only formats",
                    "Implement cryptographic signing for required serialized data",
                    "Add input validation and type checking before deserialization",
                    "Use allowlists to restrict deserializable classes"
                ],
                "long_term_strategy": {
                    "architecture": [
                        "Design data exchange using schema-based formats (JSON Schema, Protocol Buffers)",
                        "Implement service-to-service authentication for internal communications",
                        "Use message queues with structured data formats"
                    ],
                    "development_practices": [
                        "Establish secure coding standards prohibiting unsafe deserialization",
                        "Implement automated code scanning for dangerous functions",
                        "Conduct security training on serialization risks"
                    ],
                    "operational_controls": [
                        "Deploy runtime application self-protection (RASP) solutions",
                        "Implement network segmentation to limit blast radius",
                        "Monitor for suspicious deserialization patterns"
                    ]
                },
                "detection_mechanisms": [
                    "Static code analysis for pickle.loads(), yaml.load() patterns",
                    "Runtime monitoring for deserialization operations",
                    "Network traffic analysis for serialized data patterns"
                ]
            },
            "code_injection": {
                "immediate_actions": [
                    "Remove or replace all eval() and exec() functions",
                    "Implement input validation with strict allowlists",
                    "Use ast.literal_eval() for safe evaluation needs",
                    "Apply principle of least privilege for code execution contexts"
                ],
                "long_term_strategy": {
                    "architecture": [
                        "Implement sandboxed execution environments for dynamic content",
                        "Use predefined function mappings instead of dynamic evaluation",
                        "Design APIs that don't require dynamic code generation"
                    ],
                    "development_practices": [
                        "Establish secure coding guidelines prohibiting dynamic evaluation",
                        "Implement peer code review focusing on input handling",
                        "Use static analysis tools to detect dangerous functions"
                    ]
                }
            },
            "hardcoded_secrets": {
                "immediate_actions": [
                    "Rotate all exposed credentials immediately",
                    "Remove hardcoded secrets from source code",
                    "Implement environment variable or vault-based secret management",
                    "Scan git history and clean exposed secrets"
                ],
                "long_term_strategy": {
                    "architecture": [
                        "Deploy centralized secret management solution (HashiCorp Vault, AWS Secrets Manager)",
                        "Implement automated secret rotation",
                        "Use short-lived tokens where possible"
                    ],
                    "development_practices": [
                        "Implement pre-commit hooks to prevent secret commits",
                        "Use secret scanning tools in CI/CD pipeline",
                        "Establish secure development environment practices"
                    ],
                    "operational_controls": [
                        "Regular secret audits and rotation schedules",
                        "Monitor for secret usage and access patterns",
                        "Implement break-glass procedures for emergency access"
                    ]
                }
            }
        }
        
        return prevention_strategies.get(category, {
            "immediate_actions": ["Apply security best practices"],
            "long_term_strategy": {"development_practices": ["Implement secure coding standards"]},
            "detection_mechanisms": ["Deploy security monitoring tools"]
        })

    def _estimate_cvss_score(self, category: str, severity: SeverityLevel) -> Dict[str, Any]:
        """Estimate CVSS 3.1 scores for vulnerability categories."""
        
        cvss_estimates = {
            "unsafe_deserialization": {
                "base_score": 9.8,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "breakdown": {
                    "attack_vector": "Network (AV:N)",
                    "attack_complexity": "Low (AC:L)",
                    "privileges_required": "None (PR:N)",
                    "user_interaction": "None (UI:N)",
                    "scope": "Unchanged (S:U)",
                    "confidentiality": "High (C:H)",
                    "integrity": "High (I:H)",
                    "availability": "High (A:H)"
                },
                "severity_rating": "Critical"
            },
            "code_injection": {
                "base_score": 9.8,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "breakdown": {
                    "attack_vector": "Network (AV:N)",
                    "attack_complexity": "Low (AC:L)",
                    "privileges_required": "None (PR:N)",
                    "user_interaction": "None (UI:N)",
                    "scope": "Unchanged (S:U)",
                    "confidentiality": "High (C:H)",
                    "integrity": "High (I:H)",
                    "availability": "High (A:H)"
                },
                "severity_rating": "Critical"
            },
            "hardcoded_secrets": {
                "base_score": 7.5,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                "breakdown": {
                    "attack_vector": "Network (AV:N)",
                    "attack_complexity": "Low (AC:L)",
                    "privileges_required": "Low (PR:L)",
                    "user_interaction": "None (UI:N)",
                    "scope": "Unchanged (S:U)",
                    "confidentiality": "High (C:H)",
                    "integrity": "None (I:N)",
                    "availability": "None (A:N)"
                },
                "severity_rating": "High"
            },
            "sql_injection": {
                "base_score": 9.8,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "severity_rating": "Critical"
            }
        }
        
        # Adjust score based on actual severity found
        severity_adjustments = {
            SeverityLevel.CRITICAL: 1.0,
            SeverityLevel.HIGH: 0.8,
            SeverityLevel.MEDIUM: 0.6,
            SeverityLevel.LOW: 0.4,
            SeverityLevel.INFO: 0.2
        }
        
        base_data = cvss_estimates.get(category, {
            "base_score": 5.0,
            "vector": "CVSS:3.1/AV:N/AC:M/PR:L/UI:N/S:U/C:L/I:L/A:L",
            "severity_rating": "Medium"
        })
        
        adjusted_score = base_data["base_score"] * severity_adjustments.get(severity, 1.0)
        
        return {
            **base_data,
            "adjusted_score": round(adjusted_score, 1),
            "adjustment_reason": f"Adjusted for {severity.value} severity finding"
        }

    def _calculate_priority_score(self, risk_metrics: Dict[str, Any], model_consensus: int) -> float:
        """Calculate a priority score for vulnerability remediation ordering."""
        
        # Base score components
        severity_weight = {
            "critical": 25,
            "high": 20,
            "medium": 10,
            "low": 5,
            "info": 1
        }
        
        base_score = severity_weight.get(risk_metrics.get("severity", "medium"), 10)
        
        # Confidence multiplier (0.5 to 1.5)
        confidence = risk_metrics.get("confidence", 0.5)
        confidence_multiplier = 0.5 + confidence
        
        # Consensus multiplier (1.0 to 2.0)
        consensus_multiplier = 1.0 + (model_consensus / 6.0)
        
        # Exploit difficulty modifier
        exploit_difficulty = risk_metrics.get("exploit_difficulty", {}).get("difficulty", "Medium")
        difficulty_modifiers = {
            "Very Low": 1.5,
            "Low": 1.3,
            "Low-Medium": 1.2,
            "Medium": 1.0,
            "Medium-High": 0.8,
            "High": 0.6,
            "Very High": 0.4
        }
        difficulty_multiplier = difficulty_modifiers.get(exploit_difficulty, 1.0)
        
        # Calculate final priority score
        priority_score = (
            base_score * 
            confidence_multiplier * 
            consensus_multiplier * 
            difficulty_multiplier
        )
        
        return round(priority_score, 2)

    def _generate_realistic_attack_scenario(self, category: str, example_finding: DetailedFinding) -> Dict[str, Any]:
        """Generate realistic, detailed attack scenarios for each vulnerability type."""
        
        scenarios = {
            "unsafe_deserialization": {
                "scenario_name": "Enterprise Application Compromise via Deserialization",
                "attack_narrative": f"""
                    An attacker discovers the application accepts serialized data through API endpoint at {example_finding.file}:{example_finding.line}.
                    
                    Phase 1 - Reconnaissance:
                    The attacker analyzes the application to identify deserialization endpoints and maps available
                    Java/Python libraries to construct gadget chains.
                    
                    Phase 2 - Weaponization:
                    A malicious serialized object is crafted that leverages available libraries (such as Commons Collections
                    or PyYAML) to execute arbitrary code during deserialization.
                    
                    Phase 3 - Exploitation:
                    The malicious payload is submitted through the vulnerable endpoint, triggering deserialization
                    and executing attacker-controlled code with application privileges.
                    
                    Phase 4 - Post-Exploitation:
                    With code execution achieved, the attacker establishes persistence, conducts privilege escalation,
                    and begins lateral movement to access sensitive data or critical systems.
                """,
                "technical_steps": [
                    "1. Identify serialization format and vulnerable endpoints",
                    "2. Map application dependencies for gadget chain construction", 
                    "3. Develop exploit payload targeting specific vulnerability",
                    "4. Test payload delivery and execution confirmation",
                    "5. Execute reconnaissance and establish persistent access",
                    "6. Conduct data exfiltration or deploy additional malware"
                ],
                "business_impact_timeline": {
                    "0-1 hours": "Initial compromise and reconnaissance",
                    "1-24 hours": "Lateral movement and privilege escalation",
                    "1-7 days": "Data discovery and exfiltration planning", 
                    "1-30 days": "Long-term access maintenance and objectives completion"
                },
                "detection_opportunities": [
                    "Unusual deserialization operations in application logs",
                    "Unexpected network connections from application servers",
                    "File system modifications outside normal application paths",
                    "Process spawning anomalies from application context"
                ]
            },
            "code_injection": {
                "scenario_name": "Web Application Code Execution Attack",
                "attack_narrative": f"""
                    An attacker identifies code injection vulnerability in {example_finding.file} where user input
                    reaches eval() or similar code execution functions.
                    
                    Phase 1 - Discovery:
                    Through fuzzing or code analysis, the attacker identifies input parameters that are processed
                    by dynamic code evaluation functions.
                    
                    Phase 2 - Exploitation:
                    Malicious code is injected through vulnerable parameters, achieving immediate code execution
                    within the application context.
                    
                    Phase 3 - Escalation:
                    The attacker leverages code execution to access file systems, environment variables,
                    and network resources accessible to the application.
                    
                    Phase 4 - Persistence:
                    Web shells or backdoors are installed to maintain access, and sensitive data is identified
                    for extraction.
                """,
                "technical_steps": [
                    "1. Identify input parameters reaching code evaluation",
                    "2. Test injection payloads and bypass input filters",
                    "3. Achieve reliable code execution with custom payloads",
                    "4. Enumerate system resources and privileges",
                    "5. Install persistence mechanisms (web shells)",
                    "6. Access and exfiltrate sensitive application data"
                ]
            },
            "hardcoded_secrets": {
                "scenario_name": "Credential Exposure and Unauthorized Access",
                "attack_narrative": f"""
                    An attacker gains access to source code containing hardcoded credentials at {example_finding.file}:{example_finding.line}.
                    
                    Phase 1 - Discovery:
                    Through repository access, leaked code, or reverse engineering, the attacker discovers
                    hardcoded API keys, database passwords, or service credentials.
                    
                    Phase 2 - Validation:
                    The attacker tests discovered credentials against their associated services to confirm
                    validity and assess access scope.
                    
                    Phase 3 - Exploitation:
                    Valid credentials are used to access protected resources, databases, or APIs with
                    the same privileges as the legitimate application.
                    
                    Phase 4 - Abuse:
                    The attacker uses legitimate access to extract data, modify systems, or use services
                    for malicious purposes while avoiding detection.
                """,
                "technical_steps": [
                    "1. Mine source code or binaries for credential patterns",
                    "2. Extract and catalog discovered secrets",
                    "3. Test credential validity against associated services",
                    "4. Map accessible resources and privilege levels",
                    "5. Execute unauthorized operations using valid credentials",
                    "6. Maintain access while avoiding detection"
                ]
            }
        }
        
        return scenarios.get(category, {
            "scenario_name": f"Generic {category.replace('_', ' ').title()} Attack",
            "attack_narrative": f"An attacker exploits the {category} vulnerability to compromise application security.",
            "technical_steps": ["1. Identify vulnerability", "2. Develop exploit", "3. Execute attack"]
        })

    def _create_remediation_roadmap(self, category: str, findings: List[DetailedFinding]) -> Dict[str, Any]:
        """Create detailed remediation roadmaps with timelines and dependencies."""
        
        remediation_roadmaps = {
            "unsafe_deserialization": {
                "total_effort": "4-8 weeks",
                "complexity": "High",
                "phases": [
                    {
                        "phase": "Emergency Response",
                        "timeline": "Week 1",
                        "effort": "40 hours",
                        "tasks": [
                            "Identify all deserialization endpoints in application",
                            "Implement temporary input validation as emergency mitigation",
                            "Deploy monitoring for suspicious deserialization patterns",
                            "Assess blast radius and potential compromise indicators"
                        ],
                        "deliverables": [
                            "Complete inventory of deserialization usage",
                            "Emergency mitigation deployment",
                            "Risk assessment report"
                        ],
                        "dependencies": []
                    },
                    {
                        "phase": "Architecture Redesign", 
                        "timeline": "Weeks 2-4",
                        "effort": "120 hours",
                        "tasks": [
                            "Design replacement data exchange mechanisms using JSON/Protocol Buffers",
                            "Implement secure serialization with cryptographic signing",
                            "Develop migration plan for existing serialized data",
                            "Create secure coding standards and guidelines"
                        ],
                        "deliverables": [
                            "New secure data exchange architecture",
                            "Migration plan documentation",
                            "Updated coding standards"
                        ],
                        "dependencies": ["Emergency Response completion"]
                    },
                    {
                        "phase": "Implementation",
                        "timeline": "Weeks 3-6", 
                        "effort": "200 hours",
                        "tasks": [
                            "Replace unsafe deserialization with secure alternatives",
                            "Implement comprehensive input validation framework",
                            "Update all affected endpoints and data processing",
                            "Conduct security testing of new implementation"
                        ],
                        "deliverables": [
                            "Secure implementation deployment",
                            "Security test results",
                            "Performance impact assessment"
                        ],
                        "dependencies": ["Architecture design approval"]
                    },
                    {
                        "phase": "Validation & Monitoring",
                        "timeline": "Weeks 7-8",
                        "effort": "60 hours", 
                        "tasks": [
                            "Conduct penetration testing of remediated systems",
                            "Deploy permanent monitoring and alerting",
                            "Implement automated security scanning for future prevention",
                            "Document lessons learned and process improvements"
                        ],
                        "deliverables": [
                            "Penetration test report",
                            "Monitoring system deployment",
                            "Prevention framework documentation"
                        ],
                        "dependencies": ["Implementation completion"]
                    }
                ],
                "resource_requirements": {
                    "security_engineer": "Full-time for 8 weeks",
                    "senior_developer": "Half-time for 6 weeks",
                    "architect": "Quarter-time for 4 weeks",
                    "qa_engineer": "Quarter-time for 2 weeks"
                },
                "success_criteria": [
                    "Zero remaining unsafe deserialization instances",
                    "All data exchange using secure formats",
                    "Automated prevention controls in place",
                    "Security testing confirms remediation effectiveness"
                ]
            },
            "code_injection": {
                "total_effort": "2-4 weeks",
                "complexity": "Medium",
                "phases": [
                    {
                        "phase": "Immediate Fixes",
                        "timeline": "Week 1",
                        "effort": "20 hours",
                        "tasks": [
                            "Replace all eval() and exec() functions with safe alternatives",
                            "Implement input validation for dynamic operations",
                            "Deploy temporary monitoring for code execution patterns"
                        ]
                    },
                    {
                        "phase": "Systematic Remediation",
                        "timeline": "Weeks 2-3",
                        "effort": "60 hours",
                        "tasks": [
                            "Implement comprehensive input validation framework",
                            "Replace dynamic code generation with predefined functions",
                            "Update template engines with safe configuration"
                        ]
                    }
                ]
            },
            "hardcoded_secrets": {
                "total_effort": "1-3 weeks",
                "complexity": "Low-Medium",
                "phases": [
                    {
                        "phase": "Emergency Response",
                        "timeline": "Day 1",
                        "effort": "8 hours",
                        "tasks": [
                            "Inventory all hardcoded secrets found",
                            "Immediately rotate all exposed credentials",
                            "Assess which services may have been compromised"
                        ]
                    },
                    {
                        "phase": "Secret Management Implementation",
                        "timeline": "Week 1-2",
                        "effort": "40 hours",
                        "tasks": [
                            "Deploy centralized secret management solution",
                            "Remove all hardcoded secrets from codebase",
                            "Implement environment variable or vault integration"
                        ]
                    }
                ]
            }
        }
        
        roadmap = remediation_roadmaps.get(category, {
            "total_effort": "2-4 weeks",
            "complexity": "Medium",
            "phases": [
                {
                    "phase": "Analysis and Planning",
                    "timeline": "Week 1",
                    "tasks": ["Analyze vulnerability details", "Plan remediation approach"]
                },
                {
                    "phase": "Implementation",
                    "timeline": "Weeks 2-3", 
                    "tasks": ["Implement security fixes", "Test remediation"]
                }
            ]
        })
        
        # Add finding-specific context
        roadmap["context"] = {
            "findings_count": len(findings),
            "affected_files": len(set(f.file for f in findings)),
            "complexity_factors": [
                f"Multiple instances ({len(findings)}) require systematic approach",
                f"Affects {len(set(f.file for f in findings))} different files",
                "May require coordination across development teams"
            ]
        }
        
        return roadmap
    
    def _identify_regulatory_risks(self, category: str) -> Dict[str, Any]:
        """Identify specific regulatory risks and compliance violations for each vulnerability type."""
        
        regulatory_risk_mappings = {
            "unsafe_deserialization": {
                "gdpr": {
                    "risk_level": "Critical",
                    "applicable_articles": [
                        {
                            "article": "Article 32",
                            "title": "Security of processing",
                            "violation": "Failure to implement appropriate technical measures",
                            "penalty_range": "Up to 4% of annual global turnover or €20 million",
                            "specific_requirements": [
                                "Implement appropriate technical and organisational measures",
                                "Ensure confidentiality, integrity, availability and resilience",
                                "Regular testing and evaluation of security measures"
                            ]
                        },
                        {
                            "article": "Article 25",
                            "title": "Data protection by design and by default",
                            "violation": "Inadequate security by design implementation",
                            "penalty_range": "Up to 4% of annual global turnover or €20 million"
                        }
                    ],
                    "breach_notification": {
                        "required": True,
                        "timeline": "72 hours to supervisory authority, 'without undue delay' to data subjects",
                        "threshold": "High risk to rights and freedoms of natural persons",
                        "documentation_required": [
                            "Nature of personal data breach",
                            "Approximate number of data subjects concerned",
                            "Likely consequences of the breach",
                            "Measures taken or proposed to address the breach"
                        ]
                    },
                    "remediation_requirements": [
                        "Immediate containment and assessment",
                        "Independent security audit",
                        "Implementation of additional safeguards",
                        "Staff training on secure processing"
                    ]
                },
                "hipaa": {
                    "risk_level": "High",
                    "applicable_rules": [
                        {
                            "rule": "Security Rule - Administrative Safeguards",
                            "standard": "164.308(a)(1)",
                            "violation": "Failure to implement security measures to protect ePHI",
                            "penalty_range": "$100 - $50,000 per violation; $1.5M annual maximum"
                        },
                        {
                            "rule": "Security Rule - Technical Safeguards", 
                            "standard": "164.312(a)(1)",
                            "violation": "Inadequate access control measures",
                            "penalty_range": "$100 - $50,000 per violation"
                        }
                    ],
                    "breach_notification": {
                        "required": True,
                        "timeline": "60 days to HHS, individuals, and media (if >500 affected)",
                        "documentation_required": [
                            "Description of what happened",
                            "Types of information involved",
                            "Steps individuals should take",
                            "What the organization is doing to investigate and address"
                        ]
                    }
                },
                "pci_dss": {
                    "risk_level": "Critical",
                    "requirements": [
                        {
                            "requirement": "6.5.1",
                            "description": "Injection flaws, particularly SQL injection",
                            "violation": "Inadequate input validation allowing code injection",
                            "consequences": [
                                "Loss of PCI DSS compliance",
                                "Increased transaction fees",
                                "Mandatory security audits",
                                "Potential card brand fines"
                            ]
                        },
                        {
                            "requirement": "6.5.8", 
                            "description": "Improper error handling",
                            "violation": "Information leakage through error messages"
                        }
                    ],
                    "compliance_impact": {
                        "immediate": "Potential compliance failure",
                        "assessment_required": "Qualified Security Assessor (QSA) review",
                        "remediation_timeline": "Must fix before next assessment",
                        "business_impact": "May affect ability to process card payments"
                    }
                },
                "sox": {
                    "risk_level": "High",
                    "applicable_sections": [
                        {
                            "section": "404",
                            "title": "Management Assessment of Internal Controls",
                            "violation": "Material weakness in IT controls over financial reporting",
                            "impact": "Qualified audit opinion, management certification issues"
                        },
                        {
                            "section": "302",
                            "title": "Corporate Responsibility for Financial Reports", 
                            "violation": "Inadequate disclosure controls and procedures",
                            "impact": "CEO/CFO certification complications"
                        }
                    ],
                    "remediation_requirements": [
                        "Document control deficiency",
                        "Implement compensating controls",
                        "Management testing and validation",
                        "Auditor notification and testing"
                    ]
                },
                "industry_specific": {
                    "financial_services": {
                        "frameworks": ["FFIEC", "NYDFS Cybersecurity Regulation", "PRA/FCA"],
                        "key_requirements": [
                            "Incident reporting within specified timeframes",
                            "Board-level cybersecurity oversight",
                            "Third-party risk management",
                            "Penetration testing requirements"
                        ]
                    },
                    "healthcare": {
                        "frameworks": ["HITECH Act", "State breach notification laws"],
                        "additional_risks": [
                            "State Attorney General notification",
                            "Individual patient notification requirements", 
                            "Medical board reporting obligations"
                        ]
                    }
                }
            },
            "code_injection": {
                "gdpr": {
                    "risk_level": "Critical",
                    "applicable_articles": [
                        {
                            "article": "Article 32",
                            "violation": "Insufficient technical security measures",
                            "penalty_range": "Up to 4% of annual global turnover or €20 million"
                        }
                    ],
                    "breach_notification": {
                        "required": True,
                        "timeline": "72 hours",
                        "threshold": "Code injection likely constitutes high risk breach"
                    }
                },
                "pci_dss": {
                    "risk_level": "Critical",
                    "requirements": [
                        {
                            "requirement": "6.5.1",
                            "description": "Injection flaws including code injection",
                            "violation": "Direct violation of secure coding requirements"
                        }
                    ],
                    "compliance_impact": {
                        "immediate": "Critical finding requiring immediate remediation",
                        "business_impact": "May trigger card brand investigation"
                    }
                },
                "sox": {
                    "risk_level": "Medium-High",
                    "impact": "Potential material weakness if affects financial systems"
                }
            },
            "hardcoded_secrets": {
                "gdpr": {
                    "risk_level": "High",
                    "applicable_articles": [
                        {
                            "article": "Article 32",
                            "violation": "Inadequate protection of access credentials",
                            "penalty_range": "Up to 4% of annual global turnover or €20 million"
                        },
                        {
                            "article": "Article 25",
                            "violation": "Failure to implement data protection by design"
                        }
                    ],
                    "breach_notification": {
                        "required": "If credentials provide access to personal data",
                        "timeline": "72 hours if personal data at risk"
                    }
                },
                "pci_dss": {
                    "risk_level": "Critical",
                    "requirements": [
                        {
                            "requirement": "3.5",
                            "description": "Protect stored authentication data",
                            "violation": "Hardcoded credentials violate key management requirements"
                        },
                        {
                            "requirement": "8.2.1",
                            "description": "Strong authentication for all system components",
                            "violation": "Use of default or easily discovered credentials"
                        }
                    ],
                    "compliance_impact": {
                        "immediate": "Major compliance violation",
                        "remediation_required": "Immediate credential rotation and process overhaul"
                    }
                },
                "hipaa": {
                    "risk_level": "High",
                    "applicable_rules": [
                        {
                            "rule": "Security Rule - Access Control",
                            "standard": "164.312(a)(2)(i)",
                            "violation": "Inappropriate access to ePHI through exposed credentials"
                        }
                    ]
                },
                "sox": {
                    "risk_level": "Medium-High", 
                    "impact": "Control deficiency in access management for financial systems"
                },
                "state_regulations": {
                    "california_ccpa": {
                        "risk": "Potential unauthorized access to consumer personal information",
                        "penalty": "Up to $7,500 per violation",
                        "notification": "Required if personal information accessed"
                    },
                    "new_york_shield": {
                        "risk": "Breach of private information security requirements",
                        "notification": "Required notification to NY Attorney General"
                    }
                }
            },
            "sql_injection": {
                "gdpr": {
                    "risk_level": "Critical",
                    "applicable_articles": [
                        {
                            "article": "Article 32",
                            "violation": "Failure to protect against unauthorized access to personal data",
                            "penalty_range": "Up to 4% of annual global turnover or €20 million"
                        }
                    ],
                    "breach_notification": {
                        "required": True,
                        "timeline": "72 hours - SQL injection typically enables data access",
                        "threshold": "High likelihood of personal data compromise"
                    }
                },
                "pci_dss": {
                    "risk_level": "Critical",
                    "requirements": [
                        {
                            "requirement": "6.5.1", 
                            "description": "Injection flaws, particularly SQL injection",
                            "violation": "Direct violation - SQL injection specifically mentioned"
                        }
                    ],
                    "compliance_impact": {
                        "immediate": "Critical finding requiring immediate attention",
                        "forensics": "May require forensic investigation of database access"
                    }
                }
            },
            "information_disclosure": {
                "gdpr": {
                    "risk_level": "Medium-High",
                    "applicable_articles": [
                        {
                            "article": "Article 5",
                            "title": "Principles relating to processing",
                            "violation": "Failure to ensure confidentiality of personal data"
                        },
                        {
                            "article": "Article 32",
                            "violation": "Inadequate measures to ensure confidentiality"
                        }
                    ]
                },
                "hipaa": {
                    "risk_level": "High",
                    "impact": "Direct violation if PHI is disclosed through information leakage"
                }
            }
        }
        
        # Get regulatory risks for the specific category
        category_risks = regulatory_risk_mappings.get(category, {})
        
        # Add cross-cutting regulatory considerations
        general_considerations = {
            "data_residency": {
                "consideration": "Data location and cross-border transfer implications",
                "frameworks": ["GDPR", "Russian Data Localization", "Chinese Cybersecurity Law"],
                "impact": "May affect legal basis for data processing"
            },
            "incident_response": {
                "consideration": "Regulatory incident response requirements",
                "common_requirements": [
                    "Preservation of evidence",
                    "Coordination with law enforcement",
                    "Regular status updates to regulators",
                    "Post-incident security improvements"
                ]
            },
            "third_party_risk": {
                "consideration": "Vendor and supplier notification requirements",
                "impact": "May need to notify business partners and customers"
            }
        }
        
        # Calculate overall regulatory risk score
        risk_scores = {
            "Critical": 4,
            "High": 3,
            "Medium-High": 2.5,
            "Medium": 2,
            "Low": 1
        }
        
        max_risk_score = 0
        high_risk_frameworks = []
        
        for framework, framework_data in category_risks.items():
            if isinstance(framework_data, dict) and "risk_level" in framework_data:
                score = risk_scores.get(framework_data["risk_level"], 0)
                if score > max_risk_score:
                    max_risk_score = score
                if score >= 3:  # High or Critical
                    high_risk_frameworks.append(framework.upper())
        
        overall_risk = "Critical" if max_risk_score >= 4 else "High" if max_risk_score >= 3 else "Medium" if max_risk_score >= 2 else "Low"
        
        return {
            "overall_regulatory_risk": overall_risk,
            "high_risk_frameworks": high_risk_frameworks,
            "framework_specific_risks": category_risks,
            "general_considerations": general_considerations,
            "immediate_actions_required": [
                action for framework_data in category_risks.values() 
                if isinstance(framework_data, dict) and framework_data.get("risk_level") in ["Critical", "High"]
                for action in framework_data.get("remediation_requirements", [])
            ],
            "notification_requirements": {
                framework: framework_data.get("breach_notification", {})
                for framework, framework_data in category_risks.items()
                if isinstance(framework_data, dict) and framework_data.get("breach_notification")
            },
            "compliance_timeline": {
                "immediate": "Assess breach notification requirements (0-24 hours)",
                "short_term": "Implement emergency controls and document incident (1-7 days)",
                "medium_term": "Complete remediation and regulatory reporting (1-4 weeks)",
                "long_term": "Ongoing compliance monitoring and validation (1-12 months)"
            },
            "legal_considerations": {
                "legal_counsel": "Recommend immediate legal consultation for Critical/High risk",
                "documentation": "Preserve all incident documentation for regulatory inquiries",
                "communication": "Coordinate all external communications through legal/compliance teams"
            }
        }
    
    def _generate_executive_dashboard(self, findings: List[DetailedFinding], metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive executive dashboard with key metrics and insights."""
        
        # Security posture calculation
        risk_matrix = self._calculate_risk_matrix(findings)
        security_metrics = self._calculate_security_metrics(findings, metadata)
        business_impact = self._assess_business_impact_comprehensive(findings)
        
        # Trend analysis
        vulnerability_trends = self._analyze_vulnerability_trends(findings)
        
        # Key performance indicators
        security_kpis = {
            "overall_security_score": self._calculate_security_score(findings),
            "vulnerability_density": len(findings) / max(1, len(set(f.file for f in findings))),
            "critical_risk_exposure": len([f for f in findings if f.severity == SeverityLevel.CRITICAL]),
            "remediation_urgency": self._calculate_remediation_urgency(findings),
            "compliance_readiness": self._assess_compliance_readiness(findings),
            "attack_surface_size": self._calculate_attack_surface_metrics(findings)
        }
        
        # Strategic insights
        strategic_insights = self._generate_strategic_insights(findings, metadata)
        
        # Resource requirements
        resource_forecast = self._forecast_remediation_resources(findings)
        
        return {
            "security_posture": {
                "overall_grade": self._assign_security_grade(security_kpis["overall_security_score"]),
                "risk_level": risk_matrix["overall_risk_level"],
                "security_maturity": self._assess_security_maturity_level(findings),
                "improvement_trajectory": strategic_insights["trajectory"]
            },
            "key_metrics": security_kpis,
            "risk_matrix": risk_matrix,
            "business_impact": business_impact,
            "vulnerability_insights": {
                "patterns": vulnerability_trends["patterns"],
                "hotspots": vulnerability_trends["hotspots"],
                "emerging_threats": vulnerability_trends["emerging_threats"]
            },
            "strategic_recommendations": strategic_insights["recommendations"],
            "resource_forecast": resource_forecast,
            "executive_actions": self._generate_executive_actions(findings, business_impact)
        }

    def _generate_security_intelligence_report(self, findings: List[DetailedFinding], merged_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive security intelligence with AI model insights."""
        
        # Model consensus analysis
        model_consensus = self._analyze_model_consensus(findings, merged_results)
        
        # Advanced threat analysis
        threat_intelligence = {
            "attack_vectors": self._map_attack_vectors(findings),
            "vulnerability_chains": self._identify_vulnerability_chains(findings),
            "threat_actor_mapping": self._map_potential_threat_actors(findings),
            "exploit_timeline": self._estimate_exploit_timelines(findings),
            "defense_gaps": self._identify_defense_gaps(findings)
        }
        
        # Intelligence synthesis
        ai_insights = {
            "pattern_recognition": self._extract_vulnerability_patterns(findings),
            "anomaly_detection": self._detect_security_anomalies(findings),
            "predictive_analysis": self._predict_future_vulnerabilities(findings),
            "correlation_analysis": self._correlate_findings_across_models(merged_results)
        }
        
        # Technical intelligence
        technical_intelligence = {
            "code_quality_assessment": self._assess_code_quality_from_findings(findings),
            "architecture_analysis": self._analyze_architectural_weaknesses(findings),
            "technology_stack_risks": self._assess_technology_stack_risks(findings),
            "security_debt_analysis": self._quantify_security_debt(findings)
        }
        
        return {
            "model_consensus": model_consensus,
            "threat_intelligence": threat_intelligence,
            "ai_insights": ai_insights,
            "technical_intelligence": technical_intelligence,
            "confidence_analysis": self._analyze_finding_confidence(findings),
            "intelligence_summary": self._summarize_security_intelligence(findings, merged_results)
        }

    def _generate_technical_deep_dive(self, findings: List[DetailedFinding], metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed technical analysis for security professionals."""
        
        # Vulnerability categorization with technical depth
        categorized_analysis = {}
        for category in set(f.category for f in findings):
            category_findings = [f for f in findings if f.category == category]
            
            categorized_analysis[category] = {
                "technical_overview": self._get_technical_vulnerability_overview(category),
                "exploit_analysis": self._analyze_exploit_methods(category, category_findings),
                "code_analysis": self._perform_code_analysis(category_findings),
                "impact_assessment": self._assess_technical_impact(category, category_findings),
                "detection_methods": self._document_detection_methods(category),
                "mitigation_techniques": self._detail_mitigation_techniques(category),
                "testing_approaches": self._recommend_testing_approaches(category),
                "monitoring_strategies": self._suggest_monitoring_strategies(category)
            }
        
        # Cross-cutting technical analysis
        technical_themes = {
            "input_validation_analysis": self._analyze_input_validation_patterns(findings),
            "authentication_analysis": self._analyze_authentication_patterns(findings),
            "encryption_analysis": self._analyze_encryption_usage(findings),
            "error_handling_analysis": self._analyze_error_handling_patterns(findings),
            "logging_analysis": self._analyze_logging_patterns(findings)
        }
        
        # Advanced technical insights
        advanced_analysis = {
            "attack_surface_mapping": self._map_detailed_attack_surface(findings),
            "data_flow_analysis": self._analyze_data_flows(findings),
            "privilege_analysis": self._analyze_privilege_requirements(findings),
            "network_security_analysis": self._analyze_network_security_implications(findings),
            "runtime_analysis": self._analyze_runtime_behavior_risks(findings)
        }
        
        return {
            "categorized_analysis": categorized_analysis,
            "technical_themes": technical_themes,
            "advanced_analysis": advanced_analysis,
            "technical_recommendations": self._generate_technical_recommendations(findings),
            "implementation_guides": self._create_implementation_guides(findings)
        }

    def _generate_executive_summary_report(self, context: Dict[str, Any]) -> str:
        """Generate professional executive summary report."""
        
        dashboard = context["executive_dashboard"]
        
        template = f"""# Executive Security Assessment Summary

    **Assessment ID:** {context['job_id']}  
    **Date:** {context['generated_at']}  
    **Security Grade:** {dashboard['security_posture']['overall_grade']}  
    **Risk Level:** {dashboard['security_posture']['risk_level']}

    ---

    ## 🎯 Executive Summary

    **Overall Security Posture:** {dashboard['security_posture']['security_maturity']}

    {dashboard['business_impact']['executive_summary']}

    ### Key Security Metrics

    | Metric | Value | Status | Benchmark |
    |--------|-------|--------|-----------|
    | Security Score | {dashboard['key_metrics']['overall_security_score']}/100 | {self._get_score_status(dashboard['key_metrics']['overall_security_score'])} | Industry: 75+ |
    | Critical Vulnerabilities | {dashboard['key_metrics']['critical_risk_exposure']} | {self._get_critical_status(dashboard['key_metrics']['critical_risk_exposure'])} | Target: 0 |
    | Vulnerability Density | {dashboard['key_metrics']['vulnerability_density']:.1f}/file | {self._get_density_status(dashboard['key_metrics']['vulnerability_density'])} | Target: <0.5 |
    | Compliance Readiness | {dashboard['key_metrics']['compliance_readiness']}% | {self._get_compliance_status(dashboard['key_metrics']['compliance_readiness'])} | Target: 95%+ |

    ### 📊 Risk Assessment Matrix

    **Financial Impact Estimate:** {dashboard['business_impact']['financial_projection']}  
    **Regulatory Risk:** {dashboard['business_impact']['regulatory_risk']}  
    **Operational Impact:** {dashboard['business_impact']['operational_impact']}

    ### 🚀 Strategic Recommendations

    {self._format_strategic_recommendations(dashboard['strategic_recommendations'])}

    ### 📈 Resource Investment Required

    {self._format_resource_forecast(dashboard['resource_forecast'])}

    ### ⚡ Immediate Executive Actions

    {self._format_executive_actions(dashboard['executive_actions'])}

    ---

    ## 📋 Next Steps Checklist

    ### Immediate (24-48 hours)
    {self._format_immediate_actions(dashboard['executive_actions'])}

    ### Short-term (1-4 weeks)  
    {self._format_shortterm_actions(dashboard['strategic_recommendations'])}

    ### Long-term (1-6 months)
    {self._format_longterm_strategy(dashboard['strategic_recommendations'])}

    ---

    *This executive summary is derived from comprehensive AI-driven security analysis. Detailed technical findings and remediation guidance are available in the accompanying technical reports.*

    **Report Quality Score:** {context['report_quality_score']}/100  
    **Analysis Confidence:** {self._calculate_analysis_confidence(context)}%
    """
        
        return template

    def _generate_comprehensive_json_report(self, context: Dict[str, Any], findings: List[DetailedFinding]) -> Dict[str, Any]:
        """Generate comprehensive JSON report with all intelligence data."""
        
        return {
            "report_metadata": {
                "job_id": context["job_id"],
                "generated_at": context["generated_at"],
                "report_version": "2.0",
                "analysis_engine": "SecureFlow AI",
                "report_quality_score": context["report_quality_score"],
                "confidence_level": self._calculate_analysis_confidence(context)
            },
            
            "executive_intelligence": {
                "security_posture": context["executive_dashboard"]["security_posture"],
                "key_metrics": context["executive_dashboard"]["key_metrics"],
                "business_impact": context["executive_dashboard"]["business_impact"],
                "strategic_insights": context["executive_dashboard"]["strategic_recommendations"]
            },
            
            "threat_intelligence": {
                "threat_landscape": context["threat_landscape"],
                "attack_vectors": context["security_intelligence"]["threat_intelligence"]["attack_vectors"],
                "vulnerability_chains": context["security_intelligence"]["threat_intelligence"]["vulnerability_chains"],
                "threat_actor_mapping": context["security_intelligence"]["threat_intelligence"]["threat_actor_mapping"]
            },
            
            "technical_intelligence": {
                "vulnerability_analysis": context["technical_deep_dive"]["categorized_analysis"],
                "code_quality": context["security_intelligence"]["technical_intelligence"]["code_quality_assessment"],
                "architecture_analysis": context["security_intelligence"]["technical_intelligence"]["architecture_analysis"],
                "security_patterns": context["technical_deep_dive"]["technical_themes"]
            },
            
            "compliance_intelligence": {
                "compliance_status": context["compliance_assessment"]["overall_status"],
                "regulatory_risks": context["compliance_assessment"]["regulatory_risks"],
                "framework_mapping": context["compliance_assessment"]["framework_mapping"],
                "audit_readiness": context["compliance_assessment"]["audit_readiness"]
            },
            
            "ai_model_intelligence": {
                "model_consensus": context["security_intelligence"]["model_consensus"],
                "confidence_analysis": context["security_intelligence"]["confidence_analysis"],
                "ai_insights": context["security_intelligence"]["ai_insights"],
                "pattern_recognition": context["security_intelligence"]["ai_insights"]["pattern_recognition"]
            },
            
            "remediation_intelligence": {
                "strategic_roadmap": context["remediation_strategy"]["strategic_roadmap"],
                "tactical_actions": context["remediation_strategy"]["tactical_actions"],
                "resource_requirements": context["remediation_strategy"]["resource_requirements"],
                "implementation_guides": context["technical_deep_dive"]["implementation_guides"]
            },
            
            "detailed_findings": [
                {
                    **finding.model_dump(),
                    "enhanced_analysis": self._enhance_finding_with_intelligence(finding),
                    "business_context": self._add_business_context_to_finding(finding),
                    "remediation_guidance": self._get_detailed_remediation_for_finding(finding)
                }
                for finding in findings
            ],
            
            "appendices": {
                "methodology": self._document_analysis_methodology(context),
                "model_details": self._document_model_performance(context),
                "references": self._compile_security_references(),
                "glossary": self._create_security_glossary()
            }
        }