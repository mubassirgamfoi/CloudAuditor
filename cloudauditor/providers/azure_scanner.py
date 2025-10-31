from typing import Dict, List, Any, Optional
from cloudauditor.providers.azure.analytics_checks import AnalyticsChecker
from cloudauditor.providers.azure.compute_checks import ComputeChecker
from cloudauditor.providers.azure.identity_checks import IdentityChecker
from cloudauditor.providers.azure.logging_checks import LoggingChecker
from cloudauditor.providers.azure.networking_checks import NetworkingChecker
from cloudauditor.providers.azure.security_checks import SecurityChecker
from cloudauditor.providers.azure.storage_checks import StorageChecker
from cloudauditor.providers.azure.database_checks import DatabaseChecker

class AzureScanner:
    """
    Azure security scanner implementing CIS Microsoft Azure Foundations Benchmark v5.0.0
    """

    def __init__(self, subscription_id: str, tenant_id: str, use_mock: bool = True, 
                 credentials_path: Optional[str] = None, cli_command: str = ""):
        self.subscription_id = subscription_id
        self.tenant_id = tenant_id
        self.use_mock = use_mock
        self.credentials_path = credentials_path
        self.cli_command = cli_command
        
        # Initialize checkers
        self.checkers = {
            "analytics": AnalyticsChecker(subscription_id, tenant_id, use_mock, credentials_path, cli_command),
            "compute": ComputeChecker(subscription_id, tenant_id, use_mock, credentials_path, cli_command),
            "identity": IdentityChecker(subscription_id, tenant_id, use_mock, credentials_path, cli_command),
            "logging": LoggingChecker(subscription_id, tenant_id, use_mock, credentials_path, cli_command),
            "networking": NetworkingChecker(subscription_id, tenant_id, use_mock, credentials_path, cli_command),
            "security": SecurityChecker(subscription_id, tenant_id, use_mock, credentials_path, cli_command),
            "storage": StorageChecker(subscription_id, tenant_id, use_mock, credentials_path, cli_command),
            "database": DatabaseChecker(subscription_id, tenant_id, use_mock, credentials_path, cli_command),
        }

    def scan(self) -> Dict[str, Any]:
        """
        Run all Azure security checks
        """
        all_findings = []
        
        for service_name, checker in self.checkers.items():
            try:
                findings = checker.run_checks()
                all_findings.extend(findings)
            except Exception as e:
                print(f"Error running {service_name} checks: {e}")
                continue

        # Calculate summary
        total_checks = len(all_findings)
        passed_checks = len([f for f in all_findings if f["status"] == "PASSED"])
        failed_checks = len([f for f in all_findings if f["status"] == "FAILED"])
        warning_checks = len([f for f in all_findings if f["status"] == "WARNING"])

        return {
            "provider": "Azure",
            "subscription_id": self.subscription_id,
            "tenant_id": self.tenant_id,
            "cli_command": self.cli_command,
            "timestamp": all_findings[0]["timestamp"] if all_findings else None,
            "compliance_standards": [
                "CIS Microsoft Azure Foundations Benchmark v5.0.0",
                "CIS Microsoft Azure Compute Services Benchmark v2.0.0",
                "CIS Microsoft Azure Storage Services Benchmark v1.0.0",
                "CIS Microsoft Azure Database Services Benchmark v1.0.0",
            ],
            "summary": {
                "total": total_checks,
                "passed": passed_checks,
                "failed": failed_checks,
                "warnings": warning_checks
            },
            "findings": all_findings
        }
