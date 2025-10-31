import logging
from typing import Dict, List, Any, Optional
from .gcp import (
    IAMChecker,
    LoggingChecker,
    NetworkingChecker,
    VMChecker,
    StorageChecker,
    CloudSQLChecker,
    BigQueryChecker,
    DataprocChecker
)

logger = logging.getLogger(__name__)

class GCPScanner:
    """
    Scanner for GCP environments to check CIS benchmark compliance.

    This scanner implements:
    - CIS Google Cloud Platform Foundation Benchmark v3.0.0
    """

    def __init__(
        self,
        profile: Optional[str] = None,
        region: Optional[str] = None,
        use_mock: bool = True,
        enable_cis_foundations: bool = True,
    ):
        """
        Initialize GCP Scanner.

        Args:
            profile: GCP project ID (for compatibility with CLI)
            region: GCP region (for compatibility with CLI)
            use_mock: Whether to use mock data instead of real GCP API calls
            enable_cis_foundations: Whether to run CIS Foundations checks
        """
        self.project_id = profile or "mock-project"
        self.credentials_path = None  # Will be set from environment or config
        self.use_mock = use_mock
        self.enable_cis_foundations = enable_cis_foundations

        logger.debug(f"Initialized GCP scanner: project_id={self.project_id}, region={region}, mock={use_mock}, foundations={enable_cis_foundations}")

    def scan(self) -> Dict[str, Any]:
        """
        Perform a comprehensive security scan of the GCP environment.

        This method runs CIS Foundations checks.

        Returns:
            Dictionary containing scan results
        """
        findings = []
        compliance_standards = []

        logger.info(f"Starting GCP security scan for project: {self.project_id}")

        if self.enable_cis_foundations:
            findings.extend(self._scan_cis_foundations())
            compliance_standards.append("CIS Google Cloud Platform Foundation Benchmark v3.0.0")

        # Calculate summary statistics
        total_findings = len(findings)
        failed_findings = len([f for f in findings if f.get("status") == "FAILED"])
        warning_findings = len([f for f in findings if f.get("status") == "WARNING"])
        passed_findings = len([f for f in findings if f.get("status") == "PASSED"])

        logger.info(f"GCP security scan completed: {total_findings} findings")

        return {
            "provider": "gcp",
            "project_id": self.project_id,
            "compliance_standards": compliance_standards,
            "findings": findings,
            "summary": {
                "total_findings": total_findings,
                "failed": failed_findings,
                "warning": warning_findings,
                "passed": passed_findings,
            }
        }

    def _scan_cis_foundations(self) -> List[Dict[str, Any]]:
        """
        Run CIS Google Cloud Platform Foundation Benchmark checks.

        Returns:
            List of findings from all CIS Foundations checkers
        """
        findings = []

        try:
            logger.info("Running CIS Google Cloud Platform Foundation Benchmark checks...")

            # Initialize all Foundations checkers
            iam_checker = IAMChecker(self.project_id, self.credentials_path, self.use_mock)
            logging_checker = LoggingChecker(self.project_id, self.credentials_path, self.use_mock)
            networking_checker = NetworkingChecker(self.project_id, self.credentials_path, self.use_mock)
            vm_checker = VMChecker(self.project_id, self.credentials_path, self.use_mock)
            storage_checker = StorageChecker(self.project_id, self.credentials_path, self.use_mock)
            cloudsql_checker = CloudSQLChecker(self.project_id, self.credentials_path, self.use_mock)
            bigquery_checker = BigQueryChecker(self.project_id, self.credentials_path, self.use_mock)
            dataproc_checker = DataprocChecker(self.project_id, self.credentials_path, self.use_mock)

            # Run all checks
            logger.debug("Running IAM checks...")
            findings.extend(iam_checker.run_checks())

            logger.debug("Running Logging and Monitoring checks...")
            findings.extend(logging_checker.run_checks())

            logger.debug("Running Networking checks...")
            findings.extend(networking_checker.run_checks())

            logger.debug("Running Virtual Machines checks...")
            findings.extend(vm_checker.run_checks())

            logger.debug("Running Storage checks...")
            findings.extend(storage_checker.run_checks())

            logger.debug("Running Cloud SQL checks...")
            findings.extend(cloudsql_checker.run_checks())

            logger.debug("Running BigQuery checks...")
            findings.extend(bigquery_checker.run_checks())

            logger.debug("Running Dataproc checks...")
            findings.extend(dataproc_checker.run_checks())

            logger.info(f"CIS Google Cloud Platform Foundation Benchmark checks completed: {len(findings)} findings")

        except Exception as e:
            logger.error(f"Error running CIS Google Cloud Platform Foundation Benchmark checks: {e}")
            findings.append({
                "check_id": "GCP.ERROR",
                "title": "Error Running CIS GCP Foundation Checks",
                "severity": "HIGH",
                "status": "WARNING",
                "resource_id": "gcp:cis-foundations",
                "description": f"Failed to run CIS Google Cloud Platform Foundation Benchmark checks: {str(e)}",
                "recommendation": "Verify GCP credentials and permissions for Foundation services",
                "compliance_standard": "CIS Google Cloud Platform Foundation Benchmark v3.0.0",
                "region": "global",
            })

        return findings