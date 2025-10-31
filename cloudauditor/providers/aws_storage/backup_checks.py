import boto3
from typing import Dict, List, Any, Optional
from ..aws_checks.base_checker import BaseAWSChecker


class BackupChecker(BaseAWSChecker):
    """
    AWS Backup security checker implementation

    Implements AWS Backup specific checks from CIS AWS Storage
    Services Benchmark v1.0.0
    """

    def __init__(self, session: boto3.Session, region: str = 'us-east-1', use_mock: bool = True):
        """Initialize Backup checker"""
        super().__init__(session, region, use_mock)
        self.service_name = "AWS Backup"

        # Initialize service clients
        if session:
            self.backup_client = session.client('backup', region_name=region)
            self.iam_client = session.client('iam', region_name=region)

    def check_backup_storage_configuration(self) -> Dict[str, Any]:
        """
        Check AWS Storage Backups configuration
        
        Returns:
            Check result dictionary
        """
        try:
            if self.use_mock:
                return self.create_finding(
                    check_id="backup_1.1",
                    title="AWS Storage Backups (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:backup:storage",
                    description="AWS Storage Backups configuration needs review",
                    recommendation="Configure AWS Backup service for high resiliency",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            # Check if backup service is configured
            try:
                backup_vaults = self.backup_client.list_backup_vaults()
                if not backup_vaults.get('BackupVaultList'):
                    return self.create_finding(
                        check_id="backup_1.1",
                        title="AWS Storage Backups (Manual)",
                        severity="HIGH",
                        status="FAILED",
                        resource_id="aws:backup:storage",
                        description="No backup vaults found - AWS Backup service not configured",
                        recommendation="Configure AWS Backup service with backup vaults for high resiliency",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )
            except Exception as e:
                return self.create_finding(
                    check_id="backup_1.1",
                    title="AWS Storage Backups (Manual)",
                    severity="HIGH",
                    status="FAILED",
                    resource_id="aws:backup:storage",
                    description=f"Error checking backup configuration: {str(e)}",
                    recommendation="Configure AWS Backup service for high resiliency",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            return self.create_finding(
                check_id="backup_1.1",
                title="AWS Storage Backups (Manual)",
                severity="MEDIUM",
                status="PASSED",
                resource_id="aws:backup:storage",
                description="AWS Backup service is configured with backup vaults",
                recommendation="Continue monitoring backup configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

        except Exception as e:
            return self.create_finding(
                check_id="backup_1.1",
                title="AWS Storage Backups (Manual)",
                severity="HIGH",
                status="ERROR",
                resource_id="aws:backup:storage",
                description=f"Error checking backup storage configuration: {str(e)}",
                recommendation="Review AWS Backup service configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

    def check_backup_security_configuration(self) -> Dict[str, Any]:
        """
        Check AWS Backup security configuration
        
        Returns:
            Check result dictionary
        """
        try:
            if self.use_mock:
                return self.create_finding(
                    check_id="backup_1.2",
                    title="Ensure securing AWS Backups (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:backup:security",
                    description="AWS Backup security configuration needs review",
                    recommendation="Implement proper security measures for AWS Backups",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            # Check backup vault encryption
            try:
                backup_vaults = self.backup_client.list_backup_vaults()
                encrypted_vaults = 0
                total_vaults = len(backup_vaults.get('BackupVaultList', []))

                for vault in backup_vaults.get('BackupVaultList', []):
                    vault_details = self.backup_client.describe_backup_vault(
                        BackupVaultName=vault['BackupVaultName']
                    )
                    if vault_details.get('EncryptionKeyArn'):
                        encrypted_vaults += 1

                if total_vaults == 0:
                    return self.create_finding(
                        check_id="backup_1.2",
                        title="Ensure securing AWS Backups (Manual)",
                        severity="HIGH",
                        status="FAILED",
                        resource_id="aws:backup:security",
                        description="No backup vaults found",
                        recommendation="Create backup vaults with proper encryption",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

                if encrypted_vaults < total_vaults:
                    return self.create_finding(
                        check_id="backup_1.2",
                        title="Ensure securing AWS Backups (Manual)",
                        severity="MEDIUM",
                        status="WARNING",
                        resource_id="aws:backup:security",
                        description=f"Only {encrypted_vaults}/{total_vaults} backup vaults are encrypted",
                        recommendation="Enable encryption for all backup vaults",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

            except Exception as e:
                return self.create_finding(
                    check_id="backup_1.2",
                    title="Ensure securing AWS Backups (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:backup:security",
                    description=f"Error checking backup security: {str(e)}",
                    recommendation="Review backup vault encryption settings",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            return self.create_finding(
                check_id="backup_1.2",
                title="Ensure securing AWS Backups (Manual)",
                severity="MEDIUM",
                status="PASSED",
                resource_id="aws:backup:security",
                description="Backup vaults are properly encrypted",
                recommendation="Continue monitoring backup security configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

        except Exception as e:
            return self.create_finding(
                check_id="backup_1.2",
                title="Ensure securing AWS Backups (Manual)",
                severity="HIGH",
                status="ERROR",
                resource_id="aws:backup:security",
                description=f"Error checking backup security configuration: {str(e)}",
                recommendation="Review AWS Backup security configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

    def check_backup_template_naming(self) -> Dict[str, Any]:
        """
        Check backup template and naming configuration
        
        Returns:
            Check result dictionary
        """
        try:
            if self.use_mock:
                return self.create_finding(
                    check_id="backup_1.3",
                    title="Ensure to create backup template and name (Manual)",
                    severity="LOW",
                    status="INFO",
                    resource_id="aws:backup:template",
                    description="Backup template configuration is in place",
                    recommendation="Review backup template naming conventions",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            # Check backup plans (templates)
            try:
                backup_plans = self.backup_client.list_backup_plans()
                if not backup_plans.get('BackupPlansList'):
                    return self.create_finding(
                        check_id="backup_1.3",
                        title="Ensure to create backup template and name (Manual)",
                        severity="MEDIUM",
                        status="WARNING",
                        resource_id="aws:backup:template",
                        description="No backup plans found",
                        recommendation="Create backup plans with proper naming conventions",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

            except Exception as e:
                return self.create_finding(
                    check_id="backup_1.3",
                    title="Ensure to create backup template and name (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:backup:template",
                    description=f"Error checking backup plans: {str(e)}",
                    recommendation="Review backup plan configuration",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            return self.create_finding(
                check_id="backup_1.3",
                title="Ensure to create backup template and name (Manual)",
                severity="LOW",
                status="PASSED",
                resource_id="aws:backup:template",
                description="Backup plans are configured",
                recommendation="Review backup template naming conventions",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

        except Exception as e:
            return self.create_finding(
                check_id="backup_1.3",
                title="Ensure to create backup template and name (Manual)",
                severity="MEDIUM",
                status="ERROR",
                resource_id="aws:backup:template",
                description=f"Error checking backup template configuration: {str(e)}",
                recommendation="Review backup template configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

    def check_backup_iam_policies(self) -> Dict[str, Any]:
        """
        Check AWS Backup IAM policies
        
        Returns:
            Check result dictionary
        """
        try:
            if self.use_mock:
                return self.create_finding(
                    check_id="backup_1.4",
                    title="Ensure to create AWS IAM Policies (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:backup:iam-policies",
                    description="AWS Backup IAM policies need review",
                    recommendation="Create and configure appropriate IAM policies for AWS Backup",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            # Check for backup-related IAM policies
            try:
                policies = self.iam_client.list_policies(Scope='Local')
                backup_policies = [p for p in policies['Policies'] if 'backup' in p['PolicyName'].lower()]

                if not backup_policies:
                    return self.create_finding(
                        check_id="backup_1.4",
                        title="Ensure to create AWS IAM Policies (Manual)",
                        severity="MEDIUM",
                        status="WARNING",
                        resource_id="aws:backup:iam-policies",
                        description="No backup-specific IAM policies found",
                        recommendation="Create IAM policies specifically for AWS Backup operations",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

            except Exception as e:
                return self.create_finding(
                    check_id="backup_1.4",
                    title="Ensure to create AWS IAM Policies (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:backup:iam-policies",
                    description=f"Error checking IAM policies: {str(e)}",
                    recommendation="Review IAM policies for AWS Backup",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            return self.create_finding(
                check_id="backup_1.4",
                title="Ensure to create AWS IAM Policies (Manual)",
                severity="MEDIUM",
                status="PASSED",
                resource_id="aws:backup:iam-policies",
                description="Backup-specific IAM policies are configured",
                recommendation="Review IAM policies for AWS Backup regularly",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

        except Exception as e:
            return self.create_finding(
                check_id="backup_1.4",
                title="Ensure to create AWS IAM Policies (Manual)",
                severity="HIGH",
                status="ERROR",
                resource_id="aws:backup:iam-policies",
                description=f"Error checking backup IAM policies: {str(e)}",
                recommendation="Review AWS Backup IAM configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

    def check_backup_iam_roles(self) -> Dict[str, Any]:
        """
        Check AWS Backup IAM roles
        
        Returns:
            Check result dictionary
        """
        try:
            if self.use_mock:
                return self.create_finding(
                    check_id="backup_1.5",
                    title="Ensure to create IAM roles for Backup (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:backup:iam-roles",
                    description="AWS Backup IAM roles need review",
                    recommendation="Create and configure appropriate IAM roles for AWS Backup",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            # Check for backup-related IAM roles
            try:
                roles = self.iam_client.list_roles()
                backup_roles = [r for r in roles['Roles'] if 'backup' in r['RoleName'].lower()]

                if not backup_roles:
                    return self.create_finding(
                        check_id="backup_1.5",
                        title="Ensure to create IAM roles for Backup (Manual)",
                        severity="MEDIUM",
                        status="WARNING",
                        resource_id="aws:backup:iam-roles",
                        description="No backup-specific IAM roles found",
                        recommendation="Create IAM roles specifically for AWS Backup operations",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

            except Exception as e:
                return self.create_finding(
                    check_id="backup_1.5",
                    title="Ensure to create IAM roles for Backup (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:backup:iam-roles",
                    description=f"Error checking IAM roles: {str(e)}",
                    recommendation="Review IAM roles for AWS Backup",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            return self.create_finding(
                check_id="backup_1.5",
                title="Ensure to create IAM roles for Backup (Manual)",
                severity="MEDIUM",
                status="PASSED",
                resource_id="aws:backup:iam-roles",
                description="Backup-specific IAM roles are configured",
                recommendation="Review IAM roles for AWS Backup regularly",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

        except Exception as e:
            return self.create_finding(
                check_id="backup_1.5",
                title="Ensure to create IAM roles for Backup (Manual)",
                severity="HIGH",
                status="ERROR",
                resource_id="aws:backup:iam-roles",
                description=f"Error checking backup IAM roles: {str(e)}",
                recommendation="Review AWS Backup IAM configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

    def check_backup_service_linked_roles(self) -> Dict[str, Any]:
        """
        Check AWS Backup service linked roles
        
        Returns:
            Check result dictionary
        """
        try:
            if self.use_mock:
                return self.create_finding(
                    check_id="backup_1.6",
                    title="Ensure AWS Backup with Service Linked Roles (Manual)",
                    severity="LOW",
                    status="INFO",
                    resource_id="aws:backup:service-linked-roles",
                    description="Service Linked Roles for AWS Backup are configured",
                    recommendation="Review Service Linked Roles configuration",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            # Check for backup service linked roles
            try:
                roles = self.iam_client.list_roles()
                service_linked_roles = [r for r in roles['Roles'] if r.get('Path', '').startswith('/aws-service-role/') and 'backup' in r['RoleName'].lower()]

                if not service_linked_roles:
                    return self.create_finding(
                        check_id="backup_1.6",
                        title="Ensure AWS Backup with Service Linked Roles (Manual)",
                        severity="LOW",
                        status="INFO",
                        resource_id="aws:backup:service-linked-roles",
                        description="No backup service linked roles found",
                        recommendation="Consider using service linked roles for AWS Backup",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

            except Exception as e:
                return self.create_finding(
                    check_id="backup_1.6",
                    title="Ensure AWS Backup with Service Linked Roles (Manual)",
                    severity="LOW",
                    status="INFO",
                    resource_id="aws:backup:service-linked-roles",
                    description=f"Error checking service linked roles: {str(e)}",
                    recommendation="Review service linked roles for AWS Backup",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            return self.create_finding(
                check_id="backup_1.6",
                title="Ensure AWS Backup with Service Linked Roles (Manual)",
                severity="LOW",
                status="PASSED",
                resource_id="aws:backup:service-linked-roles",
                description="Backup service linked roles are configured",
                recommendation="Review Service Linked Roles configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

        except Exception as e:
            return self.create_finding(
                check_id="backup_1.6",
                title="Ensure AWS Backup with Service Linked Roles (Manual)",
                severity="MEDIUM",
                status="ERROR",
                resource_id="aws:backup:service-linked-roles",
                description=f"Error checking backup service linked roles: {str(e)}",
                recommendation="Review AWS Backup service linked roles configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

    def run_checks(self) -> List[Dict[str, Any]]:
        """
        Run all AWS Backup security checks

        Returns:
            List of check results
        """
        if self.use_mock:
            return self._get_mock_findings()

        checks = [
            self.check_backup_storage_configuration(),
            self.check_backup_security_configuration(),
            self.check_backup_template_naming(),
            self.check_backup_iam_policies(),
            self.check_backup_iam_roles(),
            self.check_backup_service_linked_roles()
        ]

        return checks

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """
        Get mock findings for AWS Backup

        Returns:
            List of mock findings
        """
        return [
            self.create_finding(
                check_id="backup_1.1",
                title="AWS Storage Backups (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:backup:storage",
                description="AWS Storage Backups configuration needs review",
                recommendation="Configure AWS Backup service for high resiliency",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="backup_1.2",
                title="Ensure securing AWS Backups (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:backup:security",
                description="AWS Backup security configuration needs review",
                recommendation="Implement proper security measures for AWS Backups",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="backup_1.3",
                title="Ensure to create backup template and name (Manual)",
                severity="LOW",
                status="INFO",
                resource_id="aws:backup:template",
                description="Backup template configuration is in place",
                recommendation="Review backup template naming conventions",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="backup_1.4",
                title="Ensure to create AWS IAM Policies (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:backup:iam-policies",
                description="AWS Backup IAM policies need review",
                recommendation="Create and configure appropriate IAM policies for AWS Backup",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="backup_1.5",
                title="Ensure to create IAM roles for Backup (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:backup:iam-roles",
                description="AWS Backup IAM roles need review",
                recommendation="Create and configure appropriate IAM roles for AWS Backup",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="backup_1.6",
                title="Ensure AWS Backup with Service Linked Roles (Manual)",
                severity="LOW",
                status="INFO",
                resource_id="aws:backup:service-linked-roles",
                description="Service Linked Roles for AWS Backup are configured",
                recommendation="Review Service Linked Roles configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )
        ]
