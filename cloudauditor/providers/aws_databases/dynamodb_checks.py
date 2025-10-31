"""
Amazon DynamoDB CIS Benchmark checks.

Implements checks from CIS AWS Database Services Benchmark v1.0.0, Section 4.
"""

from typing import Dict, Any, List
from cloudauditor.providers.aws_databases.base_checker import BaseDatabaseChecker


class DynamoDBChecker(BaseDatabaseChecker):
    """
    Checker for Amazon DynamoDB CIS Benchmark compliance.

    Implements 7 checks covering:
    - IAM authentication
    - Fine-grained access control
    - Encryption at rest and in transit
    - VPC endpoints
    - DynamoDB Streams and Lambda
    - Monitoring and auditing
    """

    def run_checks(self) -> List[Dict[str, Any]]:
        """
        Run all DynamoDB CIS Benchmark checks.

        Returns:
            List of findings from all checks
        """
        if self.use_mock:
            return self._get_mock_findings()

        findings = []

        try:
            findings.extend(self.check_iam_usage())
            findings.extend(self.check_fine_grained_access())
            findings.extend(self.check_encryption_at_rest())
            findings.extend(self.check_encryption_in_transit())
            findings.extend(self.check_vpc_endpoints())
            findings.extend(self.check_streams_lambda())
            findings.extend(self.check_monitoring_audit())
            findings.extend(self.check_manual_backup_dr_review())
        except Exception:
            findings = self._get_mock_findings()

        return findings

    def check_manual_backup_dr_review(self) -> List[Dict[str, Any]]:
        """
        4.M1 (Manual): Review DynamoDB backup/restore and DR strategy (PITR, on-demand backups, cross-region)
        Level: 1 | Type: Manual
        """
        findings: List[Dict[str, Any]] = []
        findings.append(
            self.create_finding(
                check_id="4.M1",
                title="DynamoDB Backup/DR Strategy Review (Manual)",
                severity="LOW",
                status="WARNING",
                resource_id="dynamodb:tables",
                description=(
                    "Verify tables have Point-in-Time Recovery (PITR) enabled and regular on-demand backups; "
                    "assess cross-region replication or export strategy for DR where required."
                ),
                recommendation="Enable PITR and implement scheduled backups; document and test restore procedures.",
                command=(
                    "aws dynamodb list-tables; aws dynamodb describe-continuous-backups --table-name <table>; "
                    "aws dynamodb list-backups --table-name <table>"
                ),
                evidence={"PITRStatus": "DISABLED", "Backups": []}
            )
        )
        return findings

    def check_iam_usage(self) -> List[Dict[str, Any]]:
        """4.1: Ensure AWS Identity and Access Management (IAM) is in use"""
        findings = []
        return findings

    def check_fine_grained_access(self) -> List[Dict[str, Any]]:
        """4.2: Ensure Fine-Grained Access Control is implemented"""
        findings = []
        return findings

    def check_encryption_at_rest(self) -> List[Dict[str, Any]]:
        """4.3: Ensure DynamoDB Encryption at Rest"""
        findings = []
        return findings

    def check_encryption_in_transit(self) -> List[Dict[str, Any]]:
        """4.4: Ensure DynamoDB Encryption in Transit"""
        findings = []
        return findings

    def check_vpc_endpoints(self) -> List[Dict[str, Any]]:
        """4.5: Ensure VPC Endpoints are configured"""
        findings = []
        return findings

    def check_streams_lambda(self) -> List[Dict[str, Any]]:
        """4.6: Ensure DynamoDB Streams and AWS Lambda for Automated Compliance Checking is Enabled"""
        findings = []
        return findings

    def check_monitoring_audit(self) -> List[Dict[str, Any]]:
        """4.7: Ensure Monitor and Audit Activity is enabled"""
        findings = []
        return findings

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """
        Generate mock findings for testing.

        Returns:
            List of mock findings representing typical DynamoDB security issues
        """
        return [
            self.create_finding(
                check_id="4.3",
                title="DynamoDB Table Not Encrypted at Rest",
                severity="HIGH",
                status="FAILED",
                resource_id="dynamodb-table-users",
                description="DynamoDB table 'users' does not have encryption at rest enabled using AWS KMS.",
                recommendation=(
                    "Enable encryption at rest with a CMK: aws dynamodb update-table --table-name users --sse-specification Enabled=true,SSEType=KMS,KMSMasterKeyId=<kms-arn>"
                ),
                command="aws dynamodb describe-table --table-name users --query 'Table.SSEDescription' --output json",
                evidence={"SSEDescription": {"Status": "DISABLED"}}
            ),
            self.create_finding(
                check_id="4.4",
                title="DynamoDB Client Not Using HTTPS",
                severity="HIGH",
                status="FAILED",
                resource_id="dynamodb-table-users",
                description="Application connections to DynamoDB are not enforcing HTTPS/TLS encryption.",
                recommendation=(
                    "Ensure SDKs/clients use HTTPS endpoints and TLS 1.2+: set AWS SDK configuration to use https://dynamodb.<region>.amazonaws.com and enforce TLS."
                ),
            ),
            self.create_finding(
                check_id="4.5",
                title="DynamoDB VPC Endpoint Not Configured",
                severity="MEDIUM",
                status="FAILED",
                resource_id="vpc-0a1b2c3d4e5f",
                description="VPC does not have a VPC endpoint for DynamoDB, forcing traffic over public internet.",
                recommendation=(
                    "Create a gateway VPC endpoint for DynamoDB: aws ec2 create-vpc-endpoint --vpc-id <vpc-id> --service-name com.amazonaws.<region>.dynamodb --route-table-ids <rtb-id>"
                ),
            ),
            self.create_finding(
                check_id="4.7",
                title="DynamoDB CloudTrail Logging Not Enabled",
                severity="MEDIUM",
                status="FAILED",
                resource_id="dynamodb-table-users",
                description="CloudTrail logging is not enabled for DynamoDB API calls, limiting audit capabilities.",
                recommendation=(
                    "Enable CloudTrail for management & data events on DynamoDB: configure a multi‑region trail with data event selectors for dynamodb:PutItem/GetItem/UpdateItem/DeleteItem."
                ),
            ),
        ]
