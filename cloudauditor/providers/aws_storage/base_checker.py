import boto3
from typing import Dict, List, Any, Optional
from ..aws_checks.base_checker import BaseAWSChecker


class StorageServicesChecker(BaseAWSChecker):
    """
    Base class for AWS Storage Services security checks

    Implements CIS AWS Storage Services Benchmark v1.0.0
    covering AWS Backup, EBS, EFS, FSx, S3, and Elastic Disaster Recovery
    """

    def __init__(self, session: boto3.Session, region: str = 'us-east-1', use_mock: bool = True):
        """
        Initialize StorageServicesChecker.
        """
        super().__init__(session, region, use_mock)
        self.compliance_standard = "CIS AWS Storage Services Benchmark v1.0.0"
        if session:
            self.backup_client = self.session.client('backup', region_name=region)
            self.ec2_client = self.session.client('ec2', region_name=region)
            self.efs_client = self.session.client('efs', region_name=region)
            self.fsx_client = self.session.client('fsx', region_name=region)
            self.s3_client = self.session.client('s3', region_name=region)
            self.drs_client = self.session.client('drs', region_name=region)
            self.iam_client = self.session.client('iam', region_name=region)
            self.cloudwatch_client = self.session.client('cloudwatch', region_name=region)
            self.sns_client = self.session.client('sns', region_name=region)

    def run_checks(self) -> List[Dict[str, Any]]:
        """
        Run all Storage Services security checks

        Returns:
            List of check results
        """
        if self.use_mock:
            return self._get_mock_findings()

        checks = []

        # AWS Backup checks
        checks.extend(self.get_backup_checks())

        # EBS checks
        checks.extend(self.get_ebs_checks())

        # EFS checks
        checks.extend(self.get_efs_checks())

        # FSx checks
        checks.extend(self.get_fsx_checks())

        # S3 checks
        checks.extend(self.get_s3_checks())

        # Elastic Disaster Recovery checks
        checks.extend(self.get_edr_checks())

        return checks

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """
        Get mock findings for Storage Services

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
                check_id="ebs_2.3",
                title="Ensure the proper configuration of EBS storage (Manual)",
                severity="HIGH",
                status="PASSED",
                resource_id="aws:ebs:storage",
                description="EBS storage is properly configured",
                recommendation="Continue monitoring EBS configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="efs_3.1",
                title="EFS (Manual)",
                severity="MEDIUM",
                status="INFO",
                resource_id="aws:efs:filesystem",
                description="EFS file system is configured",
                recommendation="Review EFS configuration regularly",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="s3_5.1",
                title="Amazon Simple Storage Service (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:s3:bucket",
                description="S3 bucket configuration needs review",
                recommendation="Configure S3 with proper access controls and encryption",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="edr_6.1",
                title="Ensure Elastic Disaster Recovery is Configured (Manual)",
                severity="HIGH",
                status="FAILED",
                resource_id="aws:edr:disaster-recovery",
                description="Elastic Disaster Recovery is not properly configured",
                recommendation="Configure AWS Elastic Disaster Recovery for high resiliency",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )
        ]

    def get_backup_checks(self) -> List[Dict[str, Any]]:
        """Get AWS Backup specific checks"""
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

    def get_ebs_checks(self) -> List[Dict[str, Any]]:
        """Get EBS specific checks"""
        return [
            self.create_finding(
                check_id="ebs_2.1",
                title="Ensure creating EC2 instance with EBS (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:ebs:ec2-instance",
                description="EC2 instance with EBS configuration needs review",
                recommendation="Ensure EC2 instances are properly configured with EBS volumes",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="ebs_2.2",
                title="Ensure configuring Security Groups (Manual)",
                severity="HIGH",
                status="FAILED",
                resource_id="aws:ebs:security-groups",
                description="Security groups for EBS are not properly configured",
                recommendation="Configure security groups to restrict traffic to necessary ports only",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="ebs_2.3",
                title="Ensure the proper configuration of EBS storage (Manual)",
                severity="HIGH",
                status="PASSED",
                resource_id="aws:ebs:storage",
                description="EBS storage is properly configured",
                recommendation="Continue monitoring EBS configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="ebs_2.4",
                title="Ensure the creation of a new volume (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:ebs:new-volume",
                description="New EBS volume creation process needs review",
                recommendation="Ensure proper volume creation with encryption and delete protection",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="ebs_2.5",
                title="Ensure creating snapshots of EBS volumes (Manual)",
                severity="HIGH",
                status="WARNING",
                resource_id="aws:ebs:snapshots",
                description="EBS volume snapshots are not being created regularly",
                recommendation="Implement regular EBS volume snapshots for data protection",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="ebs_2.6",
                title="Ensure Proper IAM Configuration for EC2 Instances (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:ebs:iam-configuration",
                description="IAM configuration for EC2 instances needs review",
                recommendation="Configure proper IAM policies and roles for EC2 instances",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="ebs_2.7",
                title="Ensure creating IAM User (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:ebs:iam-user",
                description="IAM user creation process needs review",
                recommendation="Ensure proper IAM user creation and management",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="ebs_2.8",
                title="Ensure the Creation of IAM Groups (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:ebs:iam-groups",
                description="IAM groups for EBS access need review",
                recommendation="Create and manage IAM groups for EBS access control",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="ebs_2.9",
                title="Ensure Granular Policy Creation (Manual)",
                severity="HIGH",
                status="FAILED",
                resource_id="aws:ebs:granular-policies",
                description="IAM policies are not granular enough for EBS access",
                recommendation="Create granular IAM policies following least privilege principle",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="ebs_2.10",
                title="Ensure Resource Access via Tag-based Policies (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:ebs:tag-based-policies",
                description="Tag-based access policies need implementation",
                recommendation="Implement tag-based IAM policies for EBS resource access",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="ebs_2.11",
                title="Ensure Secure Password Policy Implementation (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:ebs:password-policy",
                description="Password policy needs strengthening",
                recommendation="Implement strong password policies for IAM users",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="ebs_2.12",
                title="Ensure Monitoring EC2 and EBS with CloudWatch (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:ebs:cloudwatch-monitoring",
                description="CloudWatch monitoring for EC2 and EBS needs configuration",
                recommendation="Set up comprehensive CloudWatch monitoring for EC2 and EBS",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="ebs_2.13",
                title="Ensure creating an SNS subscription (Manual)",
                severity="LOW",
                status="INFO",
                resource_id="aws:ebs:sns-subscription",
                description="SNS subscription for EBS monitoring is configured",
                recommendation="Review SNS subscription configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )
        ]

    def get_efs_checks(self) -> List[Dict[str, Any]]:
        """Get EFS specific checks"""
        return [
            self.create_finding(
                check_id="efs_3.1",
                title="EFS (Manual)",
                severity="MEDIUM",
                status="INFO",
                resource_id="aws:efs:filesystem",
                description="EFS file system is configured",
                recommendation="Review EFS configuration regularly",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="efs_3.2",
                title="Ensure Implementation of EFS (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:efs:implementation",
                description="EFS implementation needs review",
                recommendation="Ensure proper EFS implementation with encryption",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="efs_3.3",
                title="Ensure EFS and VPC Integration (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:efs:vpc-integration",
                description="EFS and VPC integration needs review",
                recommendation="Ensure proper EFS and VPC integration for redundancy",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="efs_3.4",
                title="Ensure controlling Network access to EFS Services (Manual)",
                severity="HIGH",
                status="FAILED",
                resource_id="aws:efs:network-access",
                description="Network access controls for EFS are not properly configured",
                recommendation="Implement proper network access controls for EFS",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="efs_3.5",
                title="Ensure using Security Groups for VPC (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:efs:security-groups",
                description="Security groups for EFS VPC need configuration",
                recommendation="Configure security groups for EFS VPC access",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="efs_3.6",
                title="Ensure Secure Ports (Manual)",
                severity="HIGH",
                status="WARNING",
                resource_id="aws:efs:secure-ports",
                description="Port security for EFS needs review",
                recommendation="Ensure only necessary ports are open for EFS access",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="efs_3.7",
                title="Ensure File-Level Access Control with Mount Targets (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:efs:mount-targets",
                description="File-level access control with mount targets needs review",
                recommendation="Configure proper file-level access control with mount targets",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="efs_3.8",
                title="Ensure managing mount target security groups (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:efs:mount-target-security",
                description="Mount target security groups need management",
                recommendation="Properly manage security groups for mount targets",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="efs_3.9",
                title="Ensure using VPC endpoints - EFS (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:efs:vpc-endpoints",
                description="VPC endpoints for EFS need configuration",
                recommendation="Configure VPC endpoints for secure EFS access",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="efs_3.10",
                title="Ensure managing AWS EFS access points (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:efs:access-points",
                description="EFS access points need proper management",
                recommendation="Configure and manage EFS access points appropriately",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="efs_3.11",
                title="Ensure accessing Points and IAM Policies (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:efs:access-points-iam",
                description="IAM policies for EFS access points need review",
                recommendation="Configure proper IAM policies for EFS access points",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="efs_3.12",
                title="Ensure configuring IAM for AWS Elastic Disaster Recovery (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:efs:edr-iam",
                description="IAM configuration for EFS disaster recovery needs review",
                recommendation="Configure proper IAM for EFS disaster recovery",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )
        ]

    def get_fsx_checks(self) -> List[Dict[str, Any]]:
        """Get FSx specific checks"""
        return [
            self.create_finding(
                check_id="fsx_4.1",
                title="FSX (AWS Elastic File Cache) (Manual)",
                severity="MEDIUM",
                status="INFO",
                resource_id="aws:fsx:file-cache",
                description="AWS Elastic File Cache is configured",
                recommendation="Review FSx file cache configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="fsx_4.2",
                title="Amazon Elastic File Cache (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:fsx:elastic-file-cache",
                description="Elastic File Cache configuration needs review",
                recommendation="Ensure proper Elastic File Cache configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="fsx_4.3",
                title="Ensure the creation of an FSX Bucket (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:fsx:s3-bucket",
                description="S3 bucket for FSx needs creation",
                recommendation="Create and configure S3 bucket for FSx data storage",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="fsx_4.4",
                title="Ensure the creation of Elastic File Cache (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:fsx:create-cache",
                description="Elastic File Cache creation process needs review",
                recommendation="Ensure proper Elastic File Cache creation",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="fsx_4.5",
                title="Ensure installation and configuration of Lustre Client (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:fsx:lustre-client",
                description="Lustre client installation needs review",
                recommendation="Install and configure Lustre client properly",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="fsx_4.6",
                title="Ensure EC2 Kernel compatibility with Lustre (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:fsx:kernel-compatibility",
                description="EC2 kernel compatibility with Lustre needs verification",
                recommendation="Ensure EC2 kernel is compatible with Lustre",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="fsx_4.7",
                title="Ensure mounting FSx cache (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:fsx:mount-cache",
                description="FSx cache mounting process needs review",
                recommendation="Ensure proper FSx cache mounting",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="fsx_4.8",
                title="Ensure exporting cache to S3 (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:fsx:export-to-s3",
                description="Cache export to S3 needs configuration",
                recommendation="Configure proper cache export to S3",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="fsx_4.9",
                title="Ensure cleaning up FSx Resources (Manual)",
                severity="LOW",
                status="INFO",
                resource_id="aws:fsx:cleanup",
                description="FSx resource cleanup process is in place",
                recommendation="Review FSx resource cleanup procedures",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )
        ]

    def get_s3_checks(self) -> List[Dict[str, Any]]:
        """Get S3 specific checks"""
        return [
            self.create_finding(
                check_id="s3_5.1",
                title="Amazon Simple Storage Service (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:s3:bucket",
                description="S3 bucket configuration needs review",
                recommendation="Configure S3 with proper access controls and encryption",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="s3_5.2",
                title="Ensure direct data addition to S3 (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:s3:data-addition",
                description="Direct data addition to S3 process needs review",
                recommendation="Ensure secure direct data addition to S3",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="s3_5.3",
                title="Ensure Storage Classes are Configured (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:s3:storage-classes",
                description="S3 storage classes need proper configuration",
                recommendation="Configure appropriate S3 storage classes for cost optimization",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )
        ]

    def get_edr_checks(self) -> List[Dict[str, Any]]:
        """Get Elastic Disaster Recovery specific checks"""
        return [
            self.create_finding(
                check_id="edr_6.1",
                title="Ensure Elastic Disaster Recovery is Configured (Manual)",
                severity="HIGH",
                status="FAILED",
                resource_id="aws:edr:disaster-recovery",
                description="Elastic Disaster Recovery is not properly configured",
                recommendation="Configure AWS Elastic Disaster Recovery for high resiliency",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="edr_6.2",
                title="Ensure AWS Disaster Recovery Configuration (Manual)",
                severity="HIGH",
                status="WARNING",
                resource_id="aws:edr:configuration",
                description="AWS Disaster Recovery configuration needs review",
                recommendation="Review and update AWS Disaster Recovery configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="edr_6.3",
                title="Ensure functionality of Endpoint Detection and Response (EDR) (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:edr:endpoint-detection",
                description="Endpoint Detection and Response functionality needs review",
                recommendation="Ensure EDR functionality is properly configured",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="edr_6.4",
                title="Ensure configuration of replication settings (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:edr:replication-settings",
                description="Replication settings need configuration",
                recommendation="Configure proper replication settings for disaster recovery",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="edr_6.5",
                title="Ensure proper IAM configuration for AWS Elastic Disaster Recovery (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:edr:iam-configuration",
                description="IAM configuration for EDR needs review",
                recommendation="Configure proper IAM policies and roles for EDR",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="edr_6.6",
                title="Ensure installation of the AWS Replication Agent (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:edr:replication-agent",
                description="AWS Replication Agent installation needs review",
                recommendation="Install and configure AWS Replication Agent properly",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="edr_6.7",
                title="Ensure proper configuration of the Launch Settings (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:edr:launch-settings",
                description="Launch settings configuration needs review",
                recommendation="Configure proper launch settings for disaster recovery",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="edr_6.8",
                title="Ensure execution of a recovery drill (Manual)",
                severity="HIGH",
                status="FAILED",
                resource_id="aws:edr:recovery-drill",
                description="Recovery drill execution is overdue",
                recommendation="Execute regular recovery drills to test disaster recovery procedures",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="edr_6.9",
                title="Ensure Continuous Disaster Recovery Operations (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:edr:continuous-operations",
                description="Continuous disaster recovery operations need review",
                recommendation="Ensure continuous disaster recovery operations are maintained",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="edr_6.10",
                title="Ensure execution of a Disaster Recovery Failover (Manual)",
                severity="HIGH",
                status="WARNING",
                resource_id="aws:edr:failover",
                description="Disaster recovery failover process needs testing",
                recommendation="Test disaster recovery failover procedures",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="edr_6.11",
                title="Ensure execution of a failback (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:edr:failback",
                description="Failback process needs review",
                recommendation="Ensure proper failback procedures are in place",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="edr_6.12",
                title="Ensure CloudWatch Metrics for AWS EDR (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:edr:cloudwatch-metrics",
                description="CloudWatch metrics for EDR need configuration",
                recommendation="Configure CloudWatch metrics for EDR monitoring",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="edr_6.13",
                title="Ensure working of EDR (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:edr:functionality",
                description="EDR functionality needs verification",
                recommendation="Verify EDR is working properly",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )
        ]
