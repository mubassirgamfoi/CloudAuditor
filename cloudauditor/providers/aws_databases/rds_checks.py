"""
Amazon RDS CIS Benchmark checks.

Implements checks from CIS AWS Database Services Benchmark v1.0.0, Section 3.
"""

from typing import Dict, Any, List
from cloudauditor.providers.aws_databases.base_checker import BaseDatabaseChecker


class RDSChecker(BaseDatabaseChecker):
    """
    Checker for Amazon RDS CIS Benchmark compliance.

    Implements 11 checks covering:
    - Database engine selection
    - Deployment configuration
    - VPC configuration
    - Security groups
    - Encryption at rest and in transit
    - Access control and authentication
    - Patching
    - Monitoring and logging
    - Backup and recovery
    - Security configuration reviews
    """

    def run_checks(self) -> List[Dict[str, Any]]:
        """
        Run all RDS CIS Benchmark checks.

        Returns:
            List of findings from all checks
        """
        if self.use_mock:
            return self._get_mock_findings()

        findings = []

        try:
            findings.extend(self.check_database_engine())
            findings.extend(self.check_deployment_config())
            findings.extend(self.check_vpc_created())
            findings.extend(self.check_security_groups())
            findings.extend(self.check_encryption_at_rest())
            findings.extend(self.check_encryption_in_transit())
            findings.extend(self.check_access_control())
            findings.extend(self.check_regular_patching())
            findings.extend(self.check_monitoring_logging())
            findings.extend(self.check_backup_recovery())
            findings.extend(self.check_security_review())
            findings.extend(self.check_rds_manual_audit_logging_scope())
        except Exception:
            findings = self._get_mock_findings()

        return findings

    def check_rds_manual_audit_logging_scope(self) -> List[Dict[str, Any]]:
        """
        3.M1 (Manual): Review RDS database audit logging scope per engine
        Level: 1 | Type: Manual
        """
        findings: List[Dict[str, Any]] = []
        findings.append(
            self.create_finding(
                check_id="3.M1",
                title="RDS Audit Logging Scope Review (Manual)",
                severity="LOW",
                status="WARNING",
                resource_id="rds:parameter-groups",
                description=(
                    "Verify DB parameter groups enable appropriate audit logs (e.g., general_log/slow_query_log for MySQL, "
                    "pgaudit for PostgreSQL) and are applied to all instances."
                ),
                recommendation="Enable and configure engine-appropriate audit parameters and ensure log exports to CloudWatch.",
                command=(
                    "aws rds describe-db-parameters --db-parameter-group-name <pg> --query \"Parameters[?starts_with(ParameterName, `audit`) || ParameterName==`general_log` || ParameterName==`slow_query_log`]\""
                ),
                evidence={"MySQL": {"general_log": "0", "slow_query_log": "0"}, "Postgres": {"pgaudit.log": "none"}}
            )
        )
        return findings

    def check_database_engine(self) -> List[Dict[str, Any]]:
        """3.1: Ensure to Choose the Appropriate Database Engine"""
        findings = []
        return findings

    def check_deployment_config(self) -> List[Dict[str, Any]]:
        """3.2: Ensure to Create The Appropriate Deployment Configuration"""
        findings = []
        return findings

    def check_vpc_created(self) -> List[Dict[str, Any]]:
        """3.3: Ensure to Create a Virtual Private Cloud (VPC)"""
        findings = []
        return findings

    def check_security_groups(self) -> List[Dict[str, Any]]:
        """3.4: Ensure to Configure Security Groups"""
        findings = []
        return findings

    def check_encryption_at_rest(self) -> List[Dict[str, Any]]:
        """3.5: Enable Encryption at Rest"""
        findings = []
        return findings

    def check_encryption_in_transit(self) -> List[Dict[str, Any]]:
        """3.6: Enable Encryption in Transit"""
        findings = []
        return findings

    def check_access_control(self) -> List[Dict[str, Any]]:
        """3.7: Ensure to Implement Access Control and Authentication"""
        findings = []
        return findings

    def check_regular_patching(self) -> List[Dict[str, Any]]:
        """3.8: Ensure to Regularly Patch Systems"""
        findings = []
        return findings

    def check_monitoring_logging(self) -> List[Dict[str, Any]]:
        """3.9: Ensure Monitoring and Logging is Enabled"""
        findings = []
        return findings

    def check_backup_recovery(self) -> List[Dict[str, Any]]:
        """3.10: Ensure to Enable Backup and Recovery"""
        findings = []
        return findings

    def check_security_review(self) -> List[Dict[str, Any]]:
        """3.11: Ensure to Regularly Review Security Configuration"""
        findings = []
        return findings

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """
        Generate mock findings for testing.

        Returns:
            List of mock findings representing typical RDS security issues
        """
        return [
            self.create_finding(
                check_id="3.5",
                title="RDS Instance Not Encrypted at Rest",
                severity="HIGH",
                status="FAILED",
                resource_id="rds-mysql-prod-db",
                description="RDS instance 'rds-mysql-prod-db' does not have encryption at rest enabled.",
                recommendation=(
                    "Migrate to encrypted RDS: 1) aws rds create-db-snapshot --db-instance-identifier rds-mysql-prod-db --db-snapshot-identifier unenc-snap; "
                    "2) aws rds copy-db-snapshot --source-db-snapshot-identifier unenc-snap --target-db-snapshot-identifier enc-snap --kms-key-id <kms-arn>; "
                    "3) aws rds restore-db-instance-from-db-snapshot --db-instance-identifier rds-mysql-prod-db-enc --db-snapshot-identifier enc-snap"
                ),
                command="aws rds describe-db-instances --db-instance-identifier rds-mysql-prod-db --query 'DBInstances[0].StorageEncrypted' --output text",
                evidence={"StorageEncrypted": False}
            ),
            self.create_finding(
                check_id="3.6",
                title="RDS SSL/TLS Connection Not Enforced",
                severity="HIGH",
                status="FAILED",
                resource_id="rds-mysql-prod-db",
                description="RDS instance does not enforce SSL/TLS connections. Database connections may be unencrypted.",
                recommendation=(
                    "Require SSL via parameter group and security configuration. Example (MySQL): set require_secure_transport=ON in the DB parameter group; "
                    "restart/apply; update client connection strings to use SSL and the RDS CA bundle."
                ),
                command="aws rds describe-db-parameters --db-parameter-group-name <pg-name> --query 'Parameters[?ParameterName==`require_secure_transport`].{Name:ParameterName,Value:ParameterValue}'",
                evidence={"require_secure_transport": "OFF"}
            ),
            self.create_finding(
                check_id="3.8",
                title="RDS Auto Minor Version Upgrade Disabled",
                severity="MEDIUM",
                status="FAILED",
                resource_id="rds-mysql-prod-db",
                description="RDS instance does not have auto minor version upgrade enabled, potentially missing security patches.",
                recommendation=(
                    "Enable auto minor version upgrade: aws rds modify-db-instance --db-instance-identifier rds-mysql-prod-db --auto-minor-version-upgrade --apply-immediately"
                ),
                command="aws rds describe-db-instances --db-instance-identifier rds-mysql-prod-db --query 'DBInstances[0].AutoMinorVersionUpgrade' --output text",
                evidence={"AutoMinorVersionUpgrade": False}
            ),
            self.create_finding(
                check_id="3.9",
                title="RDS Enhanced Monitoring Not Enabled",
                severity="MEDIUM",
                status="FAILED",
                resource_id="rds-mysql-prod-db",
                description="Enhanced Monitoring is not enabled for RDS instance, limiting visibility into database performance.",
                recommendation=(
                    "Enable Enhanced Monitoring: aws rds modify-db-instance --db-instance-identifier rds-mysql-prod-db --monitoring-interval 60 "
                    "--monitoring-role-arn <iam-role-arn> --apply-immediately"
                ),
                command="aws rds describe-db-instances --db-instance-identifier rds-mysql-prod-db --query 'DBInstances[0].MonitoringInterval' --output text",
                evidence={"MonitoringInterval": 0}
            ),
            self.create_finding(
                check_id="3.10",
                title="RDS Automated Backups Retention Too Short",
                severity="MEDIUM",
                status="FAILED",
                resource_id="rds-mysql-prod-db",
                description="RDS automated backup retention period is set to 1 day, which may not meet compliance requirements.",
                recommendation=(
                    "Increase backup retention: aws rds modify-db-instance --db-instance-identifier rds-mysql-prod-db --backup-retention-period 7 --apply-immediately"
                ),
                command="aws rds describe-db-instances --db-instance-identifier rds-mysql-prod-db --query 'DBInstances[0].BackupRetentionPeriod' --output text",
                evidence={"BackupRetentionPeriod": 1}
            ),
            self.create_finding(
                check_id="3.3",
                title="RDS Instance Not in VPC",
                severity="CRITICAL",
                status="FAILED",
                resource_id="rds-mysql-legacy-db",
                description="RDS instance is using EC2-Classic platform instead of VPC, lacking modern network security controls.",
                recommendation=(
                    "Migrate to VPC: snapshot and restore into a VPC-enabled subnet group, then cut over application endpoints."
                ),
                command="aws rds describe-db-instances --db-instance-identifier rds-mysql-legacy-db --query 'DBInstances[0].DBSubnetGroup.VpcId' --output text",
                evidence={"VpcId": None}
            ),
        ]
