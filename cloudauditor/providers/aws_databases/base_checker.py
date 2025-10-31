"""
Base checker class for AWS Database Services CIS Benchmark checks.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional


class BaseDatabaseChecker(ABC):
    """
    Base class for all AWS Database Services CIS Benchmark checkers.

    This provides common functionality for creating findings and mock data.
    """

    def __init__(self, session=None, region: str = "us-east-1", use_mock: bool = True):
        """
        Initialize the checker.

        Args:
            session: Boto3 session for AWS API calls
            region: AWS region to scan
            use_mock: If True, use mock data instead of real API calls
        """
        self.session = session
        self.region = region
        self.use_mock = use_mock

    def create_finding(
        self,
        check_id: str,
        title: str,
        severity: str,
        status: str,
        resource_id: str,
        description: str,
        recommendation: str,
        compliance_standard: str = "CIS AWS Database Services Benchmark v1.0.0",
    ) -> Dict[str, Any]:
        """
        Create a standardized finding dictionary.

        Args:
            check_id: CIS check ID (e.g., "2.1", "3.2")
            title: Short title for the finding
            severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO
            status: PASSED, FAILED, or WARNING
            resource_id: AWS resource identifier
            description: Detailed description of the finding
            recommendation: Remediation steps
            compliance_standard: CIS benchmark name and version

        Returns:
            Dictionary containing the finding information
        """
        return {
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

    @abstractmethod
    def run_checks(self) -> List[Dict[str, Any]]:
        """
        Run all checks for this database service.

        Returns:
            List of findings
        """
        pass

    @abstractmethod
    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """
        Generate mock findings for testing.

        Returns:
            List of mock findings
        """
        pass
