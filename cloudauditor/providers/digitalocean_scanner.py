from typing import Dict, List, Any, Optional
from cloudauditor.providers.digitalocean.base_checker import BaseDOChecker
from cloudauditor.providers.digitalocean.checks_account_access import AccountAccessChecker
from cloudauditor.providers.digitalocean.checks_api import APIChecker
from cloudauditor.providers.digitalocean.checks_least_privilege import LeastPrivilegeChecker
from cloudauditor.providers.digitalocean.checks_security_history import SecurityHistoryChecker
from cloudauditor.providers.digitalocean.checks_droplet import DropletChecker
from cloudauditor.providers.digitalocean.checks_kubernetes import KubernetesChecker
from cloudauditor.providers.digitalocean.checks_logging_monitoring import LoggingMonitoringChecker
from cloudauditor.providers.digitalocean.checks_spaces import SpacesChecker
from cloudauditor.providers.digitalocean.checks_volumes import VolumesChecker


class DigitalOceanScanner:
    """
    DigitalOcean security scanner implementing CIS DigitalOcean Foundations Benchmark v1.0.0
    """

    def __init__(self, account: Optional[str] = None, use_mock: bool = True, cli_command: str = ""):
        self.account = account or "mock-account"
        self.use_mock = use_mock
        self.cli_command = cli_command

        # Initialize checkers
        self.checkers: Dict[str, BaseDOChecker] = {
            "account_access": AccountAccessChecker(self.account, use_mock, cli_command),
            "api": APIChecker(self.account, use_mock, cli_command),
            "least_privilege": LeastPrivilegeChecker(self.account, use_mock, cli_command),
            "security_history": SecurityHistoryChecker(self.account, use_mock, cli_command),
            # Services benchmark checkers
            "droplet": DropletChecker(self.account, use_mock, cli_command),
            "kubernetes": KubernetesChecker(self.account, use_mock, cli_command),
            "logging_monitoring": LoggingMonitoringChecker(self.account, use_mock, cli_command),
            "spaces": SpacesChecker(self.account, use_mock, cli_command),
            "volumes": VolumesChecker(self.account, use_mock, cli_command),
        }

    def scan(self) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        for name, checker in self.checkers.items():
            try:
                findings.extend(checker.run_checks())
            except Exception as e:
                print(f"Error running {name} checks: {e}")
                continue

        total_checks = len(findings)
        passed_checks = len([f for f in findings if f["status"] == "PASSED"])
        failed_checks = len([f for f in findings if f["status"] == "FAILED"])
        warning_checks = len([f for f in findings if f["status"] == "WARNING"])

        return {
            "provider": "DigitalOcean",
            "account": self.account,
            "cli_command": self.cli_command,
            "timestamp": findings[0]["timestamp"] if findings else None,
            "compliance_standards": [
                "CIS DigitalOcean Foundations Benchmark v1.0.0",
                "CIS DigitalOcean Services Benchmark v1.0.0",
            ],
            "summary": {
                "total": total_checks,
                "passed": passed_checks,
                "failed": failed_checks,
                "warnings": warning_checks,
            },
            "findings": findings,
        }


