"""
Base checker class for AWS CIS Compute Benchmark checks
"""

from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod


class BaseAWSChecker(ABC):
    """Base class for AWS CIS Benchmark checkers"""

    def __init__(self, session=None, region: str = "us-east-1", use_mock: bool = True):
        """
        Initialize base checker.

        Args:
            session: boto3 session (if using real AWS)
            region: AWS region
            use_mock: If True, return mock findings
        """
        self.session = session
        self.region = region
        self.use_mock = use_mock

    @abstractmethod
    def run_checks(self) -> List[Dict[str, Any]]:
        """Run all checks for this category"""
        pass

    def create_finding(
        self,
        check_id: str,
        title: str,
        severity: str,
        status: str,
        resource_id: str,
        description: str,
        recommendation: str,
        compliance_standard: str = "CIS AWS Compute Services Benchmark v1.1.0",
        command: Optional[str] = None,
        evidence: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Create a standardized finding dictionary.

        Args:
            check_id: CIS check ID (e.g., "2.1.2")
            title: Finding title
            severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
            status: PASSED, FAILED, WARNING
            resource_id: AWS resource identifier
            description: Detailed description
            recommendation: Remediation recommendation
            compliance_standard: The compliance standard being checked
            command: AWS CLI command that was executed to check this resource
            evidence: Raw output or data from the command/API call

        Returns:
            Finding dictionary
        """
        finding = {
            "check_id": check_id,
            "title": title,
            "severity": severity,
            "status": status,
            "resource_id": resource_id,
            "description": description,
            "recommendation": recommendation,
            "compliance_standard": compliance_standard,
            "region": self.region,
        }
        
        # Ensure automated checks include a command: infer a sensible AWS CLI placeholder if missing
        if command:
            finding["command"] = command
        else:
            title_lower = (title or "").lower()
            if "(automated)" in title_lower:
                # Try to infer service from resource_id (e.g., "s3://bucket" or "iam:...")
                inferred = None
                rid = resource_id or ""
                if rid.startswith("s3://"):
                    inferred = f"aws s3api get-bucket-policy --bucket {rid.replace('s3://','')}"
                elif rid.startswith("arn:aws:"):
                    parts = rid.split(":")
                    if len(parts) > 2:
                        svc = parts[2]
                        inferred = f"aws {svc} describe-configuration --output json"
                elif ":" in rid:
                    svc = rid.split(":", 1)[0]
                    inferred = f"aws {svc} describe-configuration --output json"
                else:
                    inferred = "aws <service> <describe|get> ... --output json"
                finding["command"] = inferred
        if evidence is not None:
            finding["evidence"] = evidence
            
        return finding

    def add_command_evidence(self, finding: Dict[str, Any], command: str, evidence: Any = None) -> Dict[str, Any]:
        """
        Add command and evidence to an existing finding.
        
        Args:
            finding: Existing finding dictionary
            command: AWS CLI command that was executed
            evidence: Raw output or data from the command/API call
            
        Returns:
            Updated finding dictionary
        """
        finding["command"] = command
        if evidence is not None:
            finding["evidence"] = evidence
        return finding
