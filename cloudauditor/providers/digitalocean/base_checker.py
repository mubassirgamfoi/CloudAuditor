from typing import Dict, List, Any
from datetime import datetime


class BaseDOChecker:
    """
    Base class for DigitalOcean security checkers.
    Implements CIS DigitalOcean Foundations Benchmark v1.0.0
    """

    def __init__(self, account: str, use_mock: bool = True, cli_command: str = ""):
        self.account = account
        self.use_mock = use_mock
        self.cli_command = cli_command
        self.compliance_standard = "CIS DigitalOcean Foundations Benchmark v1.0.0"

    def create_finding(
        self,
        check_id: str,
        title: str,
        severity: str,
        status: str,
        resource_id: str,
        description: str,
        recommendation: str,
        command: str = "",
        evidence: Dict[str, Any] | None = None,
        compliance_standard: str | None = None,
    ) -> Dict[str, Any]:
        finding = {
            "check_id": check_id,
            "title": title,
            "severity": severity,
            "status": status,
            "resource_id": resource_id,
            "region": "global",
            "description": description,
            "recommendation": recommendation,
            "compliance_standard": compliance_standard or self.compliance_standard,
            "timestamp": datetime.utcnow().isoformat(),
            "command_executed": command,
            "evidence": evidence or {},
        }
        if (not command) and ("(automated)" in (title or "").lower()):
            finding["command_executed"] = "doctl <resource> <get|list> --output json"
        return finding

    def run_checks(self) -> List[Dict[str, Any]]:
        raise NotImplementedError


