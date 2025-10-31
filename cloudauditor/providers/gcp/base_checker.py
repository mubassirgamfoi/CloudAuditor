from typing import Dict, List, Any, Optional
from google.cloud import logging as cloud_logging
from google.cloud import compute_v1
from google.cloud import storage
from google.cloud import bigquery
from google.cloud import dataproc
from google.oauth2 import service_account
import json
import logging

# Optional imports
try:
    from google.cloud import monitoring_v3
except ImportError:
    monitoring_v3 = None

try:
    from google.cloud import sql
except ImportError:
    sql = None

logger = logging.getLogger(__name__)

class BaseGCPChecker:
    """
    Base class for GCP security checks

    Implements CIS Google Cloud Platform Foundation Benchmark v3.0.0
    covering Identity and Access Management, Logging and Monitoring, 
    Networking, Virtual Machines, Storage, Cloud SQL, BigQuery, and Dataproc
    """

    def __init__(self, project_id: str, credentials_path: Optional[str] = None, use_mock: bool = True):
        """
        Initialize BaseGCPChecker.

        Args:
            project_id: GCP project ID
            credentials_path: Path to service account credentials JSON file
            use_mock: Whether to use mock data instead of real GCP API calls
        """
        self.project_id = project_id
        self.credentials_path = credentials_path
        self.use_mock = use_mock
        self.compliance_standard = "CIS Google Cloud Platform Foundation Benchmark v3.0.0"
        
        if not use_mock and credentials_path:
            try:
                self.credentials = service_account.Credentials.from_service_account_file(credentials_path)
                self.logging_client = cloud_logging.Client(credentials=self.credentials)
                if monitoring_v3:
                    self.monitoring_client = monitoring_v3.MetricServiceClient(credentials=self.credentials)
                else:
                    self.monitoring_client = None
                self.compute_client = compute_v1.ComputeClient(credentials=self.credentials)
                self.storage_client = storage.Client(credentials=self.credentials)
                if sql:
                    self.sql_client = sql.Client(credentials=self.credentials)
                else:
                    self.sql_client = None
                self.bigquery_client = bigquery.Client(credentials=self.credentials)
                self.dataproc_client = dataproc.Client(credentials=self.credentials)
            except Exception as e:
                logger.error(f"Failed to initialize GCP clients: {e}")
                self.use_mock = True

    def create_finding(
        self,
        check_id: str,
        title: str,
        severity: str,
        status: str,
        resource_id: str,
        description: str,
        recommendation: str,
        compliance_standard: str = None,
        region: str = None,
        command: Optional[str] = None,
        evidence: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Create a standardized finding.

        Args:
            check_id: Unique identifier for the check
            title: Human-readable title
            severity: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
            status: Check status (PASSED, FAILED, WARNING, INFO)
            resource_id: Resource identifier
            description: Detailed description
            recommendation: Remediation recommendation
            compliance_standard: Compliance standard name
            region: GCP region
            command: gcloud CLI command that was executed to check this resource
            evidence: Raw output or data from the command/API call

        Returns:
            Dictionary containing the finding
        """
        finding = {
            "check_id": check_id,
            "title": title,
            "severity": severity,
            "status": status,
            "resource_id": resource_id,
            "description": description,
            "recommendation": recommendation,
            "compliance_standard": compliance_standard or self.compliance_standard,
            "region": region or "global",
            "provider": "gcp",
            "project_id": self.project_id
        }
        
        if command:
            finding["command"] = command
        else:
            # If marked Automated in title, attach a generic gcloud placeholder
            title_lower = (title or "").lower()
            if "(automated)" in title_lower:
                rid = resource_id or ""
                inferred = "gcloud <service> <describe|get> ... --format=json"
                if rid.startswith("projects/"):
                    inferred = f"gcloud projects get-iam-policy {self.project_id} --format=json"
                finding["command"] = inferred
        if evidence is not None:
            finding["evidence"] = evidence
            
        return finding

    def add_command_evidence(self, finding: Dict[str, Any], command: str, evidence: Any = None) -> Dict[str, Any]:
        """
        Add command and evidence to an existing finding.
        
        Args:
            finding: Existing finding dictionary
            command: gcloud CLI command that was executed
            evidence: Raw output or data from the command/API call
            
        Returns:
            Updated finding dictionary
        """
        finding["command"] = command
        if evidence is not None:
            finding["evidence"] = evidence
        return finding

    def run_checks(self) -> List[Dict[str, Any]]:
        """
        Run all security checks for this service.

        Returns:
            List of check results
        """
        if self.use_mock:
            return self._get_mock_findings()
        
        # Override in subclasses
        return []

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """
        Get mock findings for testing.

        Returns:
            List of mock findings
        """
        return []
