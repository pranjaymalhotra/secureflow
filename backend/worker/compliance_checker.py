"""
SecureFlow Compliance Checker

Maps vulnerabilities to compliance standards and generates comprehensive compliance reports.
"""

import logging
from typing import List, Dict, Any, Set, Tuple
from pathlib import Path
from collections import defaultdict
from datetime import datetime

from ..gateway.models import DetailedFinding, SeverityLevel

logger = logging.getLogger(__name__)

class ComplianceChecker:
    """Check findings against various compliance standards."""
    
    def __init__(self):
        self.standards = self._load_compliance_standards()
    
    def _load_compliance_standards(self) -> Dict[str, Any]:
        """Load compliance standard mappings."""
        return {
            "owasp_2021": {
                "name": "OWASP Top 10 2021",
                "categories": {
                    "A01:2021": {
                        "name": "Broken Access Control",
                        "vulnerabilities": ["broken_access_control", "path_traversal", "authorization_bypass"],
                        "description": "Access control enforces policy such that users cannot act outside of their intended permissions."
                    },
                    "A02:2021": {
                        "name": "Cryptographic Failures",
                        "vulnerabilities": ["weak_crypto", "hardcoded_secrets", "insufficient_randomness"],
                        "description": "Failures related to cryptography which often leads to sensitive data exposure."
                    },
                    "A03:2021": {
                        "name": "Injection",
                        "vulnerabilities": ["sql_injection", "command_injection", "code_injection", "xss", "xxe"],
                        "description": "Injection flaws occur when untrusted data is sent to an interpreter."
                    },
                    "A04:2021": {
                        "name": "Insecure Design",
                        "vulnerabilities": ["insecure_design", "race_condition", "business_logic"],
                        "description": "Missing or ineffective control design."
                    },
                    "A05:2021": {
                        "name": "Security Misconfiguration",
                        "vulnerabilities": ["security_misconfiguration", "debug_enabled", "default_credentials"],
                        "description": "Security misconfiguration is the most commonly seen issue."
                    },
                    "A06:2021": {
                        "name": "Vulnerable and Outdated Components",
                        "vulnerabilities": ["vulnerable_components", "outdated_dependencies"],
                        "description": "Components with known vulnerabilities."
                    },
                    "A07:2021": {
                        "name": "Identification and Authentication Failures",
                        "vulnerabilities": ["auth_failures", "weak_password_policy", "session_management"],
                        "description": "Authentication and session management flaws."
                    },
                    "A08:2021": {
                        "name": "Software and Data Integrity Failures",
                        "vulnerabilities": ["unsafe_deserialization", "integrity_check"],
                        "description": "Code and infrastructure that does not protect against integrity violations."
                    },
                    "A09:2021": {
                        "name": "Security Logging and Monitoring Failures",
                        "vulnerabilities": ["insufficient_logging", "log_injection"],
                        "description": "Insufficient logging, detection, monitoring and active response."
                    },
                    "A10:2021": {
                        "name": "Server-Side Request Forgery (SSRF)",
                        "vulnerabilities": ["ssrf"],
                        "description": "SSRF flaws occur when a web application fetches a remote resource without validating the URL."
                    }
                }
            },
            "cwe_top_25": {
                "name": "CWE Top 25 Most Dangerous Software Weaknesses",
                "mappings": {
                    "CWE-79": ["xss", "dom_xss"],
                    "CWE-89": ["sql_injection"],
                    "CWE-78": ["command_injection"],
                    "CWE-94": ["code_injection", "eval_usage"],
                    "CWE-22": ["path_traversal"],
                    "CWE-798": ["hardcoded_secrets", "hardcoded_credentials"],
                    "CWE-502": ["unsafe_deserialization"],
                    "CWE-287": ["auth_failures", "broken_authentication"],
                    "CWE-327": ["weak_crypto"],
                    "CWE-611": ["xxe"],
                    "CWE-918": ["ssrf"],
                    "CWE-434": ["insecure_file_upload"],
                    "CWE-862": ["broken_access_control"],
                    "CWE-330": ["weak_random", "insufficient_randomness"]
                }
            },
            "pci_dss_v4": {
                "name": "PCI DSS v4.0",
                "requirements": {
                    "6.2": {
                        "name": "Protect system components from known vulnerabilities",
                        "vulnerabilities": ["vulnerable_components", "outdated_dependencies"],
                        "controls": ["Patch management", "Vulnerability scanning"]
                    },
                    "6.3": {
                        "name": "Develop secure applications",
                        "vulnerabilities": ["sql_injection", "xss", "command_injection", "hardcoded_secrets"],
                        "controls": ["Secure coding", "Code review", "SAST/DAST"]
                    },
                    "8.3": {
                        "name": "Strong cryptography",
                        "vulnerabilities": ["weak_crypto", "weak_password_policy"],
                        "controls": ["Strong encryption", "Key management"]
                    }
                }
            },
            "gdpr": {
                "name": "General Data Protection Regulation",
                "articles": {
                    "32": {
                        "name": "Security of processing",
                        "vulnerabilities": ["weak_crypto", "insufficient_logging", "information_disclosure"],
                        "requirements": ["Encryption", "Access control", "Monitoring"]
                    },
                    "33": {
                        "name": "Notification of breach",
                        "vulnerabilities": ["insufficient_logging"],
                        "requirements": ["Breach detection", "Logging"]
                    }
                }
            },
            "hipaa": {
                "name": "Health Insurance Portability and Accountability Act",
                "safeguards": {
                    "technical": {
                        "name": "Technical Safeguards",
                        "vulnerabilities": ["weak_crypto", "broken_access_control", "insufficient_logging"],
                        "controls": ["Access control", "Encryption", "Audit logs"]
                    },
                    "administrative": {
                        "name": "Administrative Safeguards",
                        "vulnerabilities": ["insufficient_logging", "security_misconfiguration"],
                        "controls": ["Risk assessment", "Security management"]
                    },
                    "physical": {
                        "name": "Physical Safeguards",
                        "vulnerabilities": ["information_disclosure"],
                        "controls": ["Facility access", "Device controls"]
                    }
                }
            },
            "nist_800_53": {
                "name": "NIST Special Publication 800-53",
                "controls": {
                    "AC": {
                        "name": "Access Control",
                        "vulnerabilities": ["broken_access_control", "authorization_bypass"],
                        "requirements": ["Least privilege", "Access enforcement"]
                    },
                    "IA": {
                        "name": "Identification and Authentication",
                        "vulnerabilities": ["auth_failures", "weak_password_policy"],
                        "requirements": ["Identification", "Authentication management"]
                    },
                    "SC": {
                        "name": "System and Communications Protection",
                        "vulnerabilities": ["weak_crypto", "sql_injection", "xss"],
                        "requirements": ["Boundary protection", "Cryptographic protection"]
                    },
                    "SI": {
                        "name": "System and Information Integrity",
                        "vulnerabilities": ["vulnerable_components", "code_injection"],
                        "requirements": ["Flaw remediation", "Malicious code protection"]
                    }
                }
            },
            "soc2": {
                "name": "SOC 2",
                "principles": {
                    "security": {
                        "name": "Security",
                        "vulnerabilities": ["broken_access_control", "weak_crypto", "sql_injection"],
                        "controls": ["Access control", "Encryption", "Vulnerability management"]
                    },
                    "availability": {
                        "name": "Availability",
                        "vulnerabilities": ["insufficient_logging", "security_misconfiguration"],
                        "controls": ["Monitoring", "Incident response"]
                    },
                    "confidentiality": {
                        "name": "Confidentiality",
                        "vulnerabilities": ["information_disclosure", "hardcoded_secrets"],
                        "controls": ["Data classification", "Data protection"]
                    }
                }
            }
        }
    
    def map_findings_to_standards(self, findings: List[DetailedFinding]) -> Dict[str, Any]:
        """Map security findings to compliance standards.
        
        Args:
            findings: List of detailed security findings
            
        Returns:
            Dictionary mapping findings to compliance standards
        """
        logger.info(f"Mapping {len(findings)} findings to compliance standards")
        
        # Initialize compliance mapping
        compliance_mapping = {
            standard_id: {
                "name": standard_info["name"],
                "coverage": {},
                "violations": {},
                "compliant_items": {},
                "statistics": {
                    "total_items": 0,
                    "violated_items": 0,
                    "compliance_percentage": 0
                }
            }
            for standard_id, standard_info in self.standards.items()
        }
        
        # Map findings to each standard
        for finding in findings:
            self._map_finding_to_owasp(finding, compliance_mapping["owasp_2021"])
            self._map_finding_to_cwe(finding, compliance_mapping["cwe_top_25"])
            self._map_finding_to_pci_dss(finding, compliance_mapping["pci_dss_v4"])
            self._map_finding_to_gdpr(finding, compliance_mapping["gdpr"])
            self._map_finding_to_hipaa(finding, compliance_mapping["hipaa"])
            self._map_finding_to_nist(finding, compliance_mapping["nist_800_53"])
            self._map_finding_to_soc2(finding, compliance_mapping["soc2"])
        
        # Calculate compliance statistics for each standard
        for standard_id, standard_data in compliance_mapping.items():
            self._calculate_compliance_statistics(standard_data)
        
        return compliance_mapping
    
    def _map_finding_to_owasp(self, finding: DetailedFinding, standard_data: Dict[str, Any]) -> None:
        """Map a finding to OWASP Top 10 2021."""
        categories = self.standards["owasp_2021"]["categories"]
        for category_id, category_info in categories.items():
            if finding.category in category_info["vulnerabilities"]:
                # Record the violation
                if category_id not in standard_data["violations"]:
                    standard_data["violations"][category_id] = {
                        "name": category_info["name"],
                        "description": category_info["description"],
                        "findings": []
                    }
                
                standard_data["violations"][category_id]["findings"].append({
                    "id": finding.id if hasattr(finding, "id") else None,
                    "file": finding.file,
                    "line": finding.line,
                    "category": finding.category,
                    "severity": finding.severity.value,
                    "explanation": finding.explanation
                })
                
                # Update coverage
                standard_data["coverage"][category_id] = {
                    "name": category_info["name"],
                    "status": "violated",
                    "findings_count": len(standard_data["violations"][category_id]["findings"]),
                    "highest_severity": self._get_highest_severity(standard_data["violations"][category_id]["findings"])
                }
    
    def _map_finding_to_cwe(self, finding: DetailedFinding, standard_data: Dict[str, Any]) -> None:
        """Map a finding to CWE Top 25."""
        mappings = self.standards["cwe_top_25"]["mappings"]
        for cwe_id, categories in mappings.items():
            if finding.category in categories:
                # Record the violation
                if cwe_id not in standard_data["violations"]:
                    standard_data["violations"][cwe_id] = {
                        "name": f"CWE-{cwe_id.split('-')[1]}",
                        "url": f"https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[1]}.html",
                        "findings": []
                    }
                
                standard_data["violations"][cwe_id]["findings"].append({
                    "id": finding.id if hasattr(finding, "id") else None,
                    "file": finding.file,
                    "line": finding.line,
                    "category": finding.category,
                    "severity": finding.severity.value,
                    "explanation": finding.explanation
                })
                
                # Update coverage
                standard_data["coverage"][cwe_id] = {
                    "name": f"CWE-{cwe_id.split('-')[1]}",
                    "status": "violated",
                    "findings_count": len(standard_data["violations"][cwe_id]["findings"]),
                    "highest_severity": self._get_highest_severity(standard_data["violations"][cwe_id]["findings"])
                }
    
    def _map_finding_to_pci_dss(self, finding: DetailedFinding, standard_data: Dict[str, Any]) -> None:
        """Map a finding to PCI DSS v4.0."""
        requirements = self.standards["pci_dss_v4"]["requirements"]
        for req_id, req_info in requirements.items():
            if finding.category in req_info["vulnerabilities"]:
                # Record the violation
                if req_id not in standard_data["violations"]:
                    standard_data["violations"][req_id] = {
                        "name": req_info["name"],
                        "controls": req_info["controls"],
                        "findings": []
                    }
                
                standard_data["violations"][req_id]["findings"].append({
                    "id": finding.id if hasattr(finding, "id") else None,
                    "file": finding.file,
                    "line": finding.line,
                    "category": finding.category,
                    "severity": finding.severity.value,
                    "explanation": finding.explanation
                })
                
                # Update coverage
                standard_data["coverage"][req_id] = {
                    "name": req_info["name"],
                    "status": "violated",
                    "findings_count": len(standard_data["violations"][req_id]["findings"]),
                    "highest_severity": self._get_highest_severity(standard_data["violations"][req_id]["findings"])
                }
    
    def _map_finding_to_gdpr(self, finding: DetailedFinding, standard_data: Dict[str, Any]) -> None:
        """Map a finding to GDPR."""
        articles = self.standards["gdpr"]["articles"]
        for article_id, article_info in articles.items():
            if finding.category in article_info["vulnerabilities"]:
                # Record the violation
                if article_id not in standard_data["violations"]:
                    standard_data["violations"][article_id] = {
                        "name": article_info["name"],
                        "requirements": article_info["requirements"],
                        "findings": []
                    }
                
                standard_data["violations"][article_id]["findings"].append({
                    "id": finding.id if hasattr(finding, "id") else None,
                    "file": finding.file,
                    "line": finding.line,
                    "category": finding.category,
                    "severity": finding.severity.value,
                    "explanation": finding.explanation
                })
                
                # Update coverage
                standard_data["coverage"][article_id] = {
                    "name": article_info["name"],
                    "status": "violated",
                    "findings_count": len(standard_data["violations"][article_id]["findings"]),
                    "highest_severity": self._get_highest_severity(standard_data["violations"][article_id]["findings"])
                }
    
    def _map_finding_to_hipaa(self, finding: DetailedFinding, standard_data: Dict[str, Any]) -> None:
        """Map a finding to HIPAA."""
        safeguards = self.standards["hipaa"]["safeguards"]
        for safeguard_id, safeguard_info in safeguards.items():
            if finding.category in safeguard_info["vulnerabilities"]:
                # Record the violation
                if safeguard_id not in standard_data["violations"]:
                    standard_data["violations"][safeguard_id] = {
                        "name": safeguard_info["name"],
                        "controls": safeguard_info["controls"],
                        "findings": []
                    }
                
                standard_data["violations"][safeguard_id]["findings"].append({
                    "id": finding.id if hasattr(finding, "id") else None,
                    "file": finding.file,
                    "line": finding.line,
                    "category": finding.category,
                    "severity": finding.severity.value,
                    "explanation": finding.explanation
                })
                
                # Update coverage
                standard_data["coverage"][safeguard_id] = {
                    "name": safeguard_info["name"],
                    "status": "violated",
                    "findings_count": len(standard_data["violations"][safeguard_id]["findings"]),
                    "highest_severity": self._get_highest_severity(standard_data["violations"][safeguard_id]["findings"])
                }
    
    def _map_finding_to_nist(self, finding: DetailedFinding, standard_data: Dict[str, Any]) -> None:
        """Map a finding to NIST 800-53."""
        controls = self.standards["nist_800_53"]["controls"]
        for control_id, control_info in controls.items():
            if finding.category in control_info["vulnerabilities"]:
                # Record the violation
                if control_id not in standard_data["violations"]:
                    standard_data["violations"][control_id] = {
                        "name": control_info["name"],
                        "requirements": control_info["requirements"],
                        "findings": []
                    }
                
                standard_data["violations"][control_id]["findings"].append({
                    "id": finding.id if hasattr(finding, "id") else None,
                    "file": finding.file,
                    "line": finding.line,
                    "category": finding.category,
                    "severity": finding.severity.value,
                    "explanation": finding.explanation
                })
                
                # Update coverage
                standard_data["coverage"][control_id] = {
                    "name": control_info["name"],
                    "status": "violated",
                    "findings_count": len(standard_data["violations"][control_id]["findings"]),
                    "highest_severity": self._get_highest_severity(standard_data["violations"][control_id]["findings"])
                }
    
    def _map_finding_to_soc2(self, finding: DetailedFinding, standard_data: Dict[str, Any]) -> None:
        """Map a finding to SOC 2."""
        principles = self.standards["soc2"]["principles"]
        for principle_id, principle_info in principles.items():
            if finding.category in principle_info["vulnerabilities"]:
                # Record the violation
                if principle_id not in standard_data["violations"]:
                    standard_data["violations"][principle_id] = {
                        "name": principle_info["name"],
                        "controls": principle_info["controls"],
                        "findings": []
                    }
                
                standard_data["violations"][principle_id]["findings"].append({
                    "id": finding.id if hasattr(finding, "id") else None,
                    "file": finding.file,
                    "line": finding.line,
                    "category": finding.category,
                    "severity": finding.severity.value,
                    "explanation": finding.explanation
                })
                
                # Update coverage
                standard_data["coverage"][principle_id] = {
                    "name": principle_info["name"],
                    "status": "violated",
                    "findings_count": len(standard_data["violations"][principle_id]["findings"]),
                    "highest_severity": self._get_highest_severity(standard_data["violations"][principle_id]["findings"])
                }
    
    def _get_highest_severity(self, findings: List[Dict[str, Any]]) -> str:
        """Get the highest severity from a list of findings."""
        severity_order = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "info": 0
        }
        
        highest = "info"
        for finding in findings:
            if severity_order.get(finding["severity"], 0) > severity_order.get(highest, 0):
                highest = finding["severity"]
        
        return highest
    
    def _calculate_compliance_statistics(self, standard_data: Dict[str, Any]) -> None:
        """Calculate compliance statistics for a standard."""
        # Count total items in the standard
        if standard_data["name"] == "OWASP Top 10 2021":
            total_items = 10  # OWASP Top 10 has 10 categories
        elif standard_data["name"] == "CWE Top 25 Most Dangerous Software Weaknesses":
            total_items = 25  # CWE Top 25 has 25 weaknesses
        elif standard_data["name"] == "PCI DSS v4.0":
            total_items = len(self.standards["pci_dss_v4"]["requirements"])
        elif standard_data["name"] == "General Data Protection Regulation":
            total_items = len(self.standards["gdpr"]["articles"])
        elif standard_data["name"] == "Health Insurance Portability and Accountability Act":
            total_items = len(self.standards["hipaa"]["safeguards"])
        elif standard_data["name"] == "NIST Special Publication 800-53":
            total_items = len(self.standards["nist_800_53"]["controls"])
        elif standard_data["name"] == "SOC 2":
            total_items = len(self.standards["soc2"]["principles"])
        else:
            total_items = 0
        
        # Count violated items
        violated_items = len(standard_data["violations"])
        
        # Calculate compliance percentage
        compliance_percentage = 0 if total_items == 0 else ((total_items - violated_items) / total_items) * 100
        
        # Update statistics
        standard_data["statistics"] = {
            "total_items": total_items,
            "violated_items": violated_items,
            "compliant_items": total_items - violated_items,
            "compliance_percentage": round(compliance_percentage, 2)
        }
    
    def generate_compliance_report(self, findings: List[DetailedFinding]) -> Dict[str, Any]:
        """Generate a comprehensive compliance report.
        
        Args:
            findings: List of detailed security findings
            
        Returns:
            Dictionary containing compliance report data
        """
        logger.info("Generating comprehensive compliance report")
        
        # Map findings to compliance standards
        compliance_mapping = self.map_findings_to_standards(findings)
        
        # Calculate overall compliance score
        overall_score = self._calculate_overall_compliance_score(compliance_mapping)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(compliance_mapping)
        
        # Create executive summary
        executive_summary = self._generate_executive_summary(compliance_mapping, overall_score)
        
        # Create detailed report
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "overall_compliance_score": overall_score,
            "executive_summary": executive_summary,
            "compliance_by_standard": compliance_mapping,
            "recommendations": recommendations,
            "remediation_priority": self._prioritize_remediation(findings, compliance_mapping)
        }
    
    def _calculate_overall_compliance_score(self, compliance_mapping: Dict[str, Any]) -> float:
        """Calculate overall compliance score based on all standards."""
        # Define weights for different standards (can be adjusted)
        standard_weights = {
            "owasp_2021": 0.25,
            "pci_dss_v4": 0.20,
            "cwe_top_25": 0.15,
            "gdpr": 0.15,
            "hipaa": 0.10,
            "nist_800_53": 0.10,
            "soc2": 0.05
        }
        
        weighted_score = 0
        total_weight = 0
        
        for standard_id, weight in standard_weights.items():
            if standard_id in compliance_mapping:
                score = compliance_mapping[standard_id]["statistics"]["compliance_percentage"]
                weighted_score += score * weight
                total_weight += weight
        
        if total_weight == 0:
            return 0
        
        return round(weighted_score / total_weight, 2)
    
    def _generate_executive_summary(self, compliance_mapping: Dict[str, Any], overall_score: float) -> Dict[str, Any]:
        """Generate an executive summary of compliance status."""
        # Determine compliance status
        if overall_score >= 90:
            status = "Excellent"
            color = "green"
            description = "Your application has excellent compliance coverage. Only minor improvements needed."
        elif overall_score >= 75:
            status = "Good"
            color = "blue"
            description = "Your application has good compliance coverage. Some improvements recommended."
        elif overall_score >= 50:
            status = "Fair"
            color = "yellow"
            description = "Your application has fair compliance coverage. Several improvements required."
        elif overall_score >= 25:
            status = "Poor"
            color = "orange"
            description = "Your application has poor compliance coverage. Significant improvements needed."
        else:
            status = "Critical"
            color = "red"
            description = "Your application has critical compliance issues. Immediate attention required."
        
        # Count total violations
        total_violations = sum(
            len(standard["violations"]) 
            for standard in compliance_mapping.values()
        )
        
        # Get standards compliance status
        standards_status = {}
        for standard_id, standard_data in compliance_mapping.items():
            standards_status[standard_id] = {
                "name": standard_data["name"],
                "compliance_percentage": standard_data["statistics"]["compliance_percentage"],
                "violated_items": standard_data["statistics"]["violated_items"],
                "total_items": standard_data["statistics"]["total_items"]
            }
        
        # Get top violations
        top_violations = self._get_top_violations(compliance_mapping)
        
        return {
            "status": status,
            "color": color,
            "description": description,
            "overall_score": overall_score,
            "total_violations": total_violations,
            "standards_status": standards_status,
            "top_violations": top_violations
        }
    
    def _get_top_violations(self, compliance_mapping: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get top compliance violations across standards."""
        all_violations = []
        
        for standard_id, standard_data in compliance_mapping.items():
            for violation_id, violation_data in standard_data["violations"].items():
                all_violations.append({
                    "standard": standard_data["name"],
                    "standard_id": standard_id,
                    "violation_id": violation_id,
                    "name": violation_data["name"],
                    "findings_count": len(violation_data["findings"]),
                    "highest_severity": self._get_highest_severity(violation_data["findings"])
                })
        
        # Sort by findings count and severity
        severity_order = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "info": 0
        }
        
        all_violations.sort(
            key=lambda v: (
                v["findings_count"],
                severity_order.get(v["highest_severity"], 0)
            ),
            reverse=True
        )
        
        return all_violations[:5]  # Return top 5 violations
    
    def _generate_recommendations(self, compliance_mapping: Dict[str, Any]) -> Dict[str, Any]:
        """Generate recommendations based on compliance violations."""
        recommendations = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        }
        
        # OWASP recommendations
        if "owasp_2021" in compliance_mapping:
            owasp_data = compliance_mapping["owasp_2021"]
            for violation_id, violation_data in owasp_data["violations"].items():
                severity = self._get_highest_severity(violation_data["findings"])
                if violation_id == "A01:2021":
                    recommendations[severity].append({
                        "standard": "OWASP Top 10 2021",
                        "category": violation_data["name"],
                        "recommendation": "Implement proper access control mechanisms. Use role-based access control and enforce least privilege."
                    })
                elif violation_id == "A02:2021":
                    recommendations[severity].append({
                        "standard": "OWASP Top 10 2021",
                        "category": violation_data["name"],
                        "recommendation": "Update cryptographic implementations. Use strong, modern algorithms and proper key management."
                    })
                elif violation_id == "A03:2021":
                    recommendations[severity].append({
                        "standard": "OWASP Top 10 2021",
                        "category": violation_data["name"],
                        "recommendation": "Implement proper input validation and parameterized queries to prevent injection attacks."
                    })
                # Add more OWASP categories here
        
        # PCI DSS recommendations
        if "pci_dss_v4" in compliance_mapping:
            pci_data = compliance_mapping["pci_dss_v4"]
            for violation_id, violation_data in pci_data["violations"].items():
                severity = self._get_highest_severity(violation_data["findings"])
                if violation_id == "6.2":
                    recommendations[severity].append({
                        "standard": "PCI DSS v4.0",
                        "category": violation_data["name"],
                        "recommendation": "Implement a vulnerability management program. Regularly update and patch all system components."
                    })
                elif violation_id == "6.3":
                    recommendations[severity].append({
                        "standard": "PCI DSS v4.0",
                        "category": violation_data["name"],
                        "recommendation": "Implement secure coding practices. Conduct regular code reviews and security testing."
                    })
                # Add more PCI DSS requirements here
        
        # GDPR recommendations
        if "gdpr" in compliance_mapping:
            gdpr_data = compliance_mapping["gdpr"]
            for violation_id, violation_data in gdpr_data["violations"].items():
                severity = self._get_highest_severity(violation_data["findings"])
                if violation_id == "32":
                    recommendations[severity].append({
                        "standard": "GDPR",
                        "category": violation_data["name"],
                        "recommendation": "Implement appropriate technical measures to ensure data security, including encryption and access controls."
                    })
                # Add more GDPR articles here
        
        # Flatten and deduplicate recommendations
        flat_recommendations = []
        seen_recs = set()
        
        for severity in ["critical", "high", "medium", "low"]:
            for rec in recommendations[severity]:
                rec_key = f"{rec['standard']}|{rec['category']}|{rec['recommendation']}"
                if rec_key not in seen_recs:
                    seen_recs.add(rec_key)
                    flat_recommendations.append({
                        **rec,
                        "severity": severity
                    })
        
        return {
            "items": flat_recommendations,
            "counts": {
                "critical": len(recommendations["critical"]),
                "high": len(recommendations["high"]),
                "medium": len(recommendations["medium"]),
                "low": len(recommendations["low"]),
                "total": sum(len(recommendations[s]) for s in ["critical", "high", "medium", "low"])
            }
        }
    
    def _prioritize_remediation(self, findings: List[DetailedFinding], compliance_mapping: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Prioritize remediation actions based on findings and compliance impact."""
        # Group findings by category
        findings_by_category = defaultdict(list)
        for finding in findings:
            findings_by_category[finding.category].append(finding)
        
        # Calculate impact score for each category
        category_impact = {}
        for category, category_findings in findings_by_category.items():
            # Count by severity
            severity_counts = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
            
            for finding in category_findings:
                severity_counts[finding.severity.value] += 1
            
            # Calculate weighted impact score
            impact_score = (
                severity_counts["critical"] * 10 +
                severity_counts["high"] * 5 +
                severity_counts["medium"] * 2 +
                severity_counts["low"] * 1
            )
            
            # Count standards affected
            standards_affected = set()
            for standard_id, standard_data in compliance_mapping.items():
                for violation_id, violation_data in standard_data["violations"].items():
                    violation_categories = self._get_categories_for_violation(standard_id, violation_id)
                    if category in violation_categories:
                        standards_affected.add(standard_id)
            
            # Increase score based on standards impact
            compliance_multiplier = 1.0 + (len(standards_affected) * 0.2)
            final_score = impact_score * compliance_multiplier
            
            category_impact[category] = {
                "category": category,
                "findings_count": len(category_findings),
                "severity_counts": severity_counts,
                "standards_affected": list(standards_affected),
                "impact_score": final_score,
                "remediation_complexity": self._estimate_remediation_complexity(category)
            }
        
        # Sort by impact score
        prioritized_categories = sorted(
            category_impact.values(),
            key=lambda x: x["impact_score"],
            reverse=True
        )
        
        # Add remediation guidance
        for category_data in prioritized_categories:
            category_data["remediation_guidance"] = self._get_remediation_guidance(
                category_data["category"]
            )
        
        return prioritized_categories
    
    def _get_categories_for_violation(self, standard_id: str, violation_id: str) -> List[str]:
        """Get vulnerability categories associated with a violation."""
        standard = self.standards.get(standard_id, {})
        
        if standard_id == "owasp_2021":
            return standard.get("categories", {}).get(violation_id, {}).get("vulnerabilities", [])
        elif standard_id == "cwe_top_25":
            return standard.get("mappings", {}).get(violation_id, [])
        elif standard_id == "pci_dss_v4":
            return standard.get("requirements", {}).get(violation_id, {}).get("vulnerabilities", [])
        elif standard_id == "gdpr":
            return standard.get("articles", {}).get(violation_id, {}).get("vulnerabilities", [])
        elif standard_id == "hipaa":
            return standard.get("safeguards", {}).get(violation_id, {}).get("vulnerabilities", [])
        elif standard_id == "nist_800_53":
            return standard.get("controls", {}).get(violation_id, {}).get("vulnerabilities", [])
        elif standard_id == "soc2":
            return standard.get("principles", {}).get(violation_id, {}).get("vulnerabilities", [])
        
        return []
    
    def _estimate_remediation_complexity(self, category: str) -> str:
        """Estimate the complexity of remediation for a category."""
        # Define complexity levels for common vulnerability categories
        complexity_mapping = {
            "sql_injection": "Medium",
            "xss": "Medium",
            "command_injection": "Medium",
            "path_traversal": "Medium",
            "hardcoded_secrets": "Low",
            "weak_crypto": "Medium",
            "broken_access_control": "High",
            "ssrf": "Medium",
            "unsafe_deserialization": "High",
            "xxe": "Medium",
            "security_misconfiguration": "Low",
            "insufficient_logging": "Low",
            "information_disclosure": "Low",
            "vulnerable_components": "Medium",
            "outdated_dependencies": "Low",
            "code_injection": "High",
            "eval_usage": "Medium"
        }
        
        return complexity_mapping.get(category, "Medium")
    
    def _get_remediation_guidance(self, category: str) -> Dict[str, Any]:
        """Get detailed remediation guidance for a vulnerability category."""
        # Define remediation guidance for common vulnerability categories
        guidance = {
            "sql_injection": {
                "summary": "Use parameterized queries or ORM to prevent SQL injection",
                "details": [
                    "Replace string concatenation in SQL queries with parameterized queries",
                    "Use an ORM (Object-Relational Mapping) framework",
                    "Apply input validation and sanitization",
                    "Implement least privilege database accounts"
                ],
                "code_example": {
                    "bad": "query = \"SELECT * FROM users WHERE username = '\" + username + \"'\";",
                    "good": "query = \"SELECT * FROM users WHERE username = ?\"; stmt.setString(1, username);"
                },
                "resources": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                ]
            },
            "xss": {
                "summary": "Implement proper output encoding and Content Security Policy",
                "details": [
                    "Encode all user-supplied data before rendering in HTML, JavaScript, CSS, or URLs",
                    "Implement Content Security Policy (CSP) headers",
                    "Use frameworks that automatically escape template variables",
                    "Validate input and sanitize output"
                ],
                "code_example": {
                    "bad": "element.innerHTML = userInput;",
                    "good": "element.textContent = userInput; // Or use appropriate encoding function"
                },
                "resources": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                ]
            },
            "hardcoded_secrets": {
                "summary": "Move secrets to environment variables or a secure vault",
                "details": [
                    "Remove hardcoded credentials from source code",
                    "Use environment variables for configuration",
                    "Consider using a secrets management solution",
                    "Implement proper key rotation procedures"
                ],
                "code_example": {
                    "bad": "const apiKey = \"abcd1234efgh5678\";",
                    "good": "const apiKey = process.env.API_KEY;"
                },
                "resources": [
                    "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"
                ]
            },
            "command_injection": {
                "summary": "Avoid shell commands or use allowlists with proper argument handling",
                "details": [
                    "Avoid shell commands when possible - use language APIs",
                    "If shell commands are necessary, use allowlists for permitted commands",
                    "Never concatenate user input into command strings",
                    "Use proper argument arrays to pass parameters"
                ],
                "code_example": {
                    "bad": "os.system('ping ' + user_input)",
                    "good": "subprocess.run(['ping', user_input], shell=False)"
                },
                "resources": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
                ]
            }
            # Add more categories as needed
        }
        
        # Return default guidance if category not found
        if category not in guidance:
            return {
                "summary": f"Fix {category} vulnerabilities",
                "details": [
                    "Review and update code to address this vulnerability type",
                    "Implement security best practices",
                    "Consider security testing tools"
                ],
                "resources": [
                    "https://owasp.org/www-project-top-ten/"
                ]
            }
        
        return guidance[category]
    
    def generate_compliance_report_markdown(self, findings: List[DetailedFinding]) -> str:
        """Generate a markdown report for compliance status.
        
        Args:
            findings: List of detailed security findings
            
        Returns:
            Markdown formatted compliance report
        """
        report_data = self.generate_compliance_report(findings)
        
        # Generate markdown
        md = []
        
        # Title and summary
        md.append("# Security Compliance Report\n")
        md.append(f"**Generated:** {report_data['timestamp']}\n")
        md.append("## Executive Summary\n")
        md.append(f"**Overall Compliance Score:** {report_data['overall_compliance_score']}%\n")
        md.append(f"**Status:** {report_data['executive_summary']['status']}\n")
        md.append(f"{report_data['executive_summary']['description']}\n")
        
        # Compliance by standard
        md.append("## Compliance by Standard\n")
        
        for standard_id, standard_data in report_data['compliance_by_standard'].items():
            md.append(f"### {standard_data['name']}\n")
            md.append(f"**Compliance Score:** {standard_data['statistics']['compliance_percentage']}%\n")
            md.append(f"**Compliant Items:** {standard_data['statistics']['compliant_items']} of {standard_data['statistics']['total_items']}\n")
            
            if standard_data['violations']:
                md.append("\n**Violations:**\n")
                for violation_id, violation_data in standard_data['violations'].items():
                    md.append(f"- **{violation_id} - {violation_data['name']}**: {len(violation_data['findings'])} findings\n")
            else:
                md.append("\n**No violations found.**\n")
        
        # Top remediation priorities
        md.append("## Remediation Priorities\n")
        
        for i, priority in enumerate(report_data['remediation_priority'][:5], 1):
            md.append(f"### {i}. {priority['category'].replace('_', ' ').title()}\n")
            md.append(f"**Impact Score:** {priority['impact_score']:.2f}\n")
            md.append(f"**Findings:** {priority['findings_count']}\n")
            md.append(f"**Complexity:** {priority['remediation_complexity']}\n")
            md.append(f"**Standards Affected:** {', '.join(priority['standards_affected'])}\n")
            md.append(f"**Remediation Guidance:** {priority['remediation_guidance']['summary']}\n")
            
            md.append("**Steps:**\n")
            for step in priority['remediation_guidance']['details']:
                md.append(f"- {step}\n")
            
            if i < len(report_data['remediation_priority']):
                md.append("\n")
        
        # Recommendations
        md.append("## Detailed Recommendations\n")
        
        for severity in ["critical", "high", "medium", "low"]:
            severity_recs = [r for r in report_data['recommendations']['items'] if r['severity'] == severity]
            if severity_recs:
                md.append(f"### {severity.title()} Priority\n")
                for rec in severity_recs:
                    md.append(f"- **{rec['standard']} - {rec['category']}**: {rec['recommendation']}\n")
                md.append("\n")
        
        return "\n".join(md)