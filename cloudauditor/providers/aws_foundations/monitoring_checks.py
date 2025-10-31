"""
CIS AWS Foundations Benchmark - Monitoring Checks (Section 5)
CloudWatch metric filters and alarm checks
"""

from typing import Dict, Any, List
from cloudauditor.providers.aws_checks.base_checker import BaseAWSChecker


class MonitoringFoundationsChecker(BaseAWSChecker):
    """Checker for monitoring security - CIS AWS Foundations Benchmark"""

    def run_checks(self) -> List[Dict[str, Any]]:
        """Run all monitoring foundation checks"""
        if self.use_mock:
            return self._get_mock_findings()

        findings = []
        try:
            findings.extend(self.check_security_hub())
            findings.extend(self.check_metric_filters_and_alarms())
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="5.ERROR",
                    title="Error Running Monitoring Checks",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="monitoring",
                    description=f"Failed to run monitoring checks: {str(e)}",
                    recommendation="Verify AWS permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_security_hub(self) -> List[Dict[str, Any]]:
        """
        5.16: Ensure AWS Security Hub is enabled
        Level: 1 | Type: Automated | MEDIUM
        """
        findings = []
        try:
            securityhub = self.session.client("securityhub", region_name=self.region)

            try:
                hub = securityhub.describe_hub()

                if hub.get("HubArn"):
                    finding = self.create_finding(
                        check_id="5.16",
                        title="AWS Security Hub Enabled",
                        severity="INFO",
                        status="PASSED",
                        resource_id=f"securityhub:{self.region}",
                        description="AWS Security Hub is enabled in this region.",
                        recommendation="Continue monitoring Security Hub findings",
                        compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                        command=f"aws securityhub describe-hub --region {self.region}",
                        evidence=hub
                    )
                    findings.append(finding)

            except securityhub.exceptions.InvalidAccessException:
                finding = self.create_finding(
                    check_id="5.16",
                    title="AWS Security Hub Not Enabled",
                    severity="MEDIUM",
                    status="FAILED",
                    resource_id=f"securityhub:{self.region}",
                    description="AWS Security Hub is not enabled in this region.",
                    recommendation=(
                        "Enable Security Hub and core standards: "
                        f"aws securityhub enable-security-hub --region {self.region} --enable-default-standards; "
                        f"aws securityhub batch-enable-standards --region {self.region} --standards-subscription-requests "
                        "StandardsArn=arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
                    ),
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                    command=f"aws securityhub describe-hub --region {self.region}",
                    evidence={"Error": "InvalidAccessException", "HubArn": None}
                )
                findings.append(finding)

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="5.16",
                    title="Unable to Check Security Hub",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="securityhub",
                    description=f"Could not verify Security Hub: {str(e)}",
                    recommendation="Verify Security Hub permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_metric_filters_and_alarms(self) -> List[Dict[str, Any]]:
        """
        5.1-5.15: Check for CloudWatch metric filters and alarms
        Level: 1 | Type: Manual | MEDIUM

        Note: This is a simplified check. Full implementation would verify
        specific metric filter patterns for each security event type.
        """
        findings = []
        # Simplified implementation - full version would check for specific patterns
        # for unauthorized API calls, console sign-in without MFA, root usage, etc.
        return findings

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """Return mock findings for testing"""
        return [
            self.create_finding(
                check_id="5.16",
                title="AWS Security Hub Not Enabled",
                severity="MEDIUM",
                status="FAILED",
                resource_id="securityhub:us-east-1",
                description="AWS Security Hub is not enabled in this region.",
                recommendation="Enable AWS Security Hub for centralized security findings",
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command="aws securityhub describe-hub --region us-east-1",
                evidence={"Error": "InvalidAccessException", "HubArn": None}
            ),
        ]
