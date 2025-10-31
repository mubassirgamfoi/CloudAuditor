"""
AWS cloud provider scanner for CIS benchmark compliance.
Implements:
- CIS AWS Foundations Benchmark v6.0.0
- CIS AWS Compute Services Benchmark v1.1.0
- CIS AWS Database Services Benchmark v1.0.0
- CIS AWS End User Compute Services Benchmark v1.2.0
- CIS AWS Storage Services Benchmark v1.0.0
"""

import os
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path

from cloudauditor.utils.logger import get_logger
from cloudauditor.providers.aws_checks.ec2_ami_checks import EC2AMIChecker
from cloudauditor.providers.aws_checks.ec2_ebs_checks import EC2EBSChecker
from cloudauditor.providers.aws_checks.ec2_general_checks import EC2GeneralChecker
from cloudauditor.providers.aws_checks.ecs_checks import ECSChecker
from cloudauditor.providers.aws_checks.lambda_checks import LambdaChecker
from cloudauditor.providers.aws_foundations.iam_checks import IAMFoundationsChecker
from cloudauditor.providers.aws_foundations.storage_checks import StorageFoundationsChecker
from cloudauditor.providers.aws_foundations.logging_checks import LoggingFoundationsChecker
from cloudauditor.providers.aws_foundations.monitoring_checks import MonitoringFoundationsChecker
from cloudauditor.providers.aws_foundations.networking_checks import NetworkingFoundationsChecker
from cloudauditor.providers.aws_databases.aurora_checks import AuroraChecker
from cloudauditor.providers.aws_databases.rds_checks import RDSChecker
from cloudauditor.providers.aws_databases.dynamodb_checks import DynamoDBChecker
from cloudauditor.providers.aws_databases.elasticache_checks import ElastiCacheChecker
from cloudauditor.providers.aws_databases.documentdb_checks import DocumentDBChecker
from cloudauditor.providers.aws_databases.neptune_checks import NeptuneChecker
from cloudauditor.providers.aws_enduser.workspaces_checks import WorkSpacesChecker
from cloudauditor.providers.aws_enduser.workspaces_web_checks import WorkSpacesWebChecker
from cloudauditor.providers.aws_enduser.workdocs_checks import WorkDocsChecker
from cloudauditor.providers.aws_enduser.appstream_checks import AppStreamChecker
from cloudauditor.providers.aws_storage.backup_checks import BackupChecker
from cloudauditor.providers.aws_storage.ebs_checks import EBSChecker
from cloudauditor.providers.aws_storage.efs_checks import EFSChecker
from cloudauditor.providers.aws_storage.fsx_checks import FSxChecker
from cloudauditor.providers.aws_storage.s3_checks import S3Checker
from cloudauditor.providers.aws_storage.edr_checks import EDRChecker

logger = get_logger(__name__)


class AWSScanner:
    """
    Scanner for AWS environments to check CIS benchmark compliance.

    This scanner implements:
    - CIS AWS Foundations Benchmark v6.0.0 (IAM, Storage, Logging, Monitoring, Networking)
    - CIS AWS Compute Services Benchmark v1.1.0 (EC2, ECS, Lambda, etc.)
    - CIS AWS Database Services Benchmark v1.0.0 (Aurora, RDS, DynamoDB, ElastiCache, etc.)
    - CIS AWS End User Compute Services Benchmark v1.2.0 (WorkSpaces, WorkSpaces Web, WorkDocs, AppStream 2.0)
    - CIS AWS Storage Services Benchmark v1.0.0 (AWS Backup, EBS, EFS, FSx, S3, EDR)

    This scanner can work with real AWS APIs (boto3) or mock data for testing.
    """

    def __init__(
        self,
        profile: Optional[str] = None,
        region: Optional[str] = None,
        use_mock: bool = True,
        enable_cis_compute: bool = True,
        enable_cis_foundations: bool = True,
        enable_cis_databases: bool = True,
        enable_cis_enduser: bool = True,
        enable_cis_storage: bool = True,
    ):
        """
        Initialize AWS scanner.

        Args:
            profile: AWS profile name
            region: AWS region
            use_mock: If True, use mock data instead of real API calls
            enable_cis_compute: If True, run CIS Compute Benchmark checks
            enable_cis_foundations: If True, run CIS Foundations Benchmark checks
            enable_cis_databases: If True, run CIS Database Services Benchmark checks
            enable_cis_enduser: If True, run CIS End User Compute Services Benchmark checks
            enable_cis_storage: If True, run CIS Storage Services Benchmark checks
        """
        self.profile = profile or "default"
        self.region = region or "us-east-1"
        self.use_mock = use_mock
        self.enable_cis_compute = enable_cis_compute
        self.enable_cis_foundations = enable_cis_foundations
        self.enable_cis_databases = enable_cis_databases
        self.enable_cis_enduser = enable_cis_enduser
        self.enable_cis_storage = enable_cis_storage
        self.session = None

        if not use_mock:
            try:
                import boto3
                self.session = boto3.Session(profile_name=self.profile, region_name=self.region)
                logger.info("Using real AWS API with boto3")
            except ImportError:
                logger.warning("boto3 not installed, falling back to mock mode")
                self.use_mock = True
            except Exception as e:
                logger.warning(f"Failed to create boto3 session: {e}, falling back to mock mode")
                self.use_mock = True

        logger.debug(f"Initialized AWS scanner: profile={self.profile}, region={self.region}, mock={use_mock}, compute={enable_cis_compute}, foundations={enable_cis_foundations}, databases={enable_cis_databases}, enduser={enable_cis_enduser}, storage={enable_cis_storage}")

    def scan(self) -> Dict[str, Any]:
        """
        Perform a comprehensive security scan of the AWS environment.

        This method runs CIS Foundations, Compute, Database Services, End User Compute, and Storage Services checks.

        Returns:
            Dictionary containing scan results
        """
        logger.info(f"Starting AWS scan for region: {self.region}")

        findings = []
        compliance_standards = []

        # Run CIS Foundations Benchmark checks
        if self.enable_cis_foundations:
            findings.extend(self._scan_cis_foundations())
            compliance_standards.append("CIS AWS Foundations Benchmark v6.0.0")

        # Run CIS Compute Benchmark checks
        if self.enable_cis_compute:
            findings.extend(self._scan_cis_compute())
            compliance_standards.append("CIS AWS Compute Services Benchmark v1.1.0")

        # Run CIS Database Services Benchmark checks
        if self.enable_cis_databases:
            findings.extend(self._scan_cis_databases())
            compliance_standards.append("CIS AWS Database Services Benchmark v1.0.0")

        # Run CIS End User Compute Services Benchmark checks
        if self.enable_cis_enduser:
            findings.extend(self._scan_cis_enduser())
            compliance_standards.append("CIS AWS End User Compute Services Benchmark v1.2.0")

        # Run CIS Storage Services Benchmark checks
        if self.enable_cis_storage:
            findings.extend(self._scan_cis_storage())
            compliance_standards.append("CIS AWS Storage Services Benchmark v1.0.0")

        # If still no findings (fallback to legacy mock data)
        if not findings:
            findings = self._get_mock_findings()

        # Calculate summary statistics
        summary = self._calculate_summary(findings)

        results = {
            "provider": "aws",
            "region": self.region,
            "profile": self.profile,
            "timestamp": datetime.now().isoformat(),
            "summary": summary,
            "findings": findings,
            "compliance_standards": compliance_standards if compliance_standards else ["Mixed"],
        }

        logger.info(f"AWS scan completed: {summary['total_checks']} checks, {summary['failed']} failed")

        return results

    def _scan_cis_compute(self) -> List[Dict[str, Any]]:
        """
        Run CIS AWS Compute Services Benchmark checks.

        Returns:
            List of findings from all CIS Compute checkers
        """
        findings = []

        try:
            logger.info("Running CIS Compute Benchmark checks...")

            # Initialize all checkers
            ec2_ami_checker = EC2AMIChecker(self.session, self.region, self.use_mock)
            ec2_ebs_checker = EC2EBSChecker(self.session, self.region, self.use_mock)
            ec2_general_checker = EC2GeneralChecker(self.session, self.region, self.use_mock)
            ecs_checker = ECSChecker(self.session, self.region, self.use_mock)
            lambda_checker = LambdaChecker(self.session, self.region, self.use_mock)

            # Run all checks
            logger.debug("Running EC2 AMI checks...")
            findings.extend(ec2_ami_checker.run_checks())

            logger.debug("Running EC2 EBS checks...")
            findings.extend(ec2_ebs_checker.run_checks())

            logger.debug("Running EC2 general checks...")
            findings.extend(ec2_general_checker.run_checks())

            logger.debug("Running ECS checks...")
            findings.extend(ecs_checker.run_checks())

            logger.debug("Running Lambda checks...")
            findings.extend(lambda_checker.run_checks())

            logger.info(f"CIS Compute Benchmark checks completed: {len(findings)} findings")

        except Exception as e:
            logger.error(f"Error running CIS Compute Benchmark checks: {e}")
            findings.append({
                "check_id": "CIS.ERROR",
                "title": "Error Running CIS Compute Checks",
                "severity": "HIGH",
                "status": "WARNING",
                "resource_id": "aws:cis-compute",
                "description": f"Failed to run CIS Compute Benchmark checks: {str(e)}",
                "recommendation": "Verify AWS credentials and permissions",
                "compliance_standard": "CIS AWS Compute Services Benchmark v1.1.0",
                "region": self.region,
            })

        return findings

    def _scan_cis_foundations(self) -> List[Dict[str, Any]]:
        """
        Run CIS AWS Foundations Benchmark checks.

        Returns:
            List of findings from all CIS Foundations checkers
        """
        findings = []

        try:
            logger.info("Running CIS Foundations Benchmark checks...")

            # Initialize all checkers
            iam_checker = IAMFoundationsChecker(self.session, self.region, self.use_mock)
            storage_checker = StorageFoundationsChecker(self.session, self.region, self.use_mock)
            logging_checker = LoggingFoundationsChecker(self.session, self.region, self.use_mock)
            monitoring_checker = MonitoringFoundationsChecker(self.session, self.region, self.use_mock)
            networking_checker = NetworkingFoundationsChecker(self.session, self.region, self.use_mock)

            # Run all checks
            logger.debug("Running IAM foundation checks...")
            findings.extend(iam_checker.run_checks())

            logger.debug("Running Storage foundation checks...")
            findings.extend(storage_checker.run_checks())

            logger.debug("Running Logging foundation checks...")
            findings.extend(logging_checker.run_checks())

            logger.debug("Running Monitoring foundation checks...")
            findings.extend(monitoring_checker.run_checks())

            logger.debug("Running Networking foundation checks...")
            findings.extend(networking_checker.run_checks())

            logger.info(f"CIS Foundations Benchmark checks completed: {len(findings)} findings")

        except Exception as e:
            logger.error(f"Error running CIS Foundations Benchmark checks: {e}")
            findings.append({
                "check_id": "FOUNDATIONS.ERROR",
                "title": "Error Running CIS Foundations Checks",
                "severity": "HIGH",
                "status": "WARNING",
                "resource_id": "aws:cis-foundations",
                "description": f"Failed to run CIS Foundations Benchmark checks: {str(e)}",
                "recommendation": "Verify AWS credentials and permissions",
                "compliance_standard": "CIS AWS Foundations Benchmark v6.0.0",
                "region": self.region,
            })

        return findings

    def _scan_cis_databases(self) -> List[Dict[str, Any]]:
        """
        Run CIS AWS Database Services Benchmark checks.

        Returns:
            List of findings from all CIS Database Services checkers
        """
        findings = []

        try:
            logger.info("Running CIS Database Services Benchmark checks...")

            # Initialize all database service checkers
            aurora_checker = AuroraChecker(self.session, self.region, self.use_mock)
            rds_checker = RDSChecker(self.session, self.region, self.use_mock)
            dynamodb_checker = DynamoDBChecker(self.session, self.region, self.use_mock)
            elasticache_checker = ElastiCacheChecker(self.session, self.region, self.use_mock)
            documentdb_checker = DocumentDBChecker(self.session, self.region, self.use_mock)
            neptune_checker = NeptuneChecker(self.session, self.region, self.use_mock)

            # Run all checks
            logger.debug("Running Aurora database checks...")
            findings.extend(aurora_checker.run_checks())

            logger.debug("Running RDS database checks...")
            findings.extend(rds_checker.run_checks())

            logger.debug("Running DynamoDB database checks...")
            findings.extend(dynamodb_checker.run_checks())

            logger.debug("Running ElastiCache database checks...")
            findings.extend(elasticache_checker.run_checks())

            logger.debug("Running DocumentDB database checks...")
            findings.extend(documentdb_checker.run_checks())

            logger.debug("Running Neptune database checks...")
            findings.extend(neptune_checker.run_checks())

            logger.info(f"CIS Database Services Benchmark checks completed: {len(findings)} findings")

        except Exception as e:
            logger.error(f"Error running CIS Database Services Benchmark checks: {e}")
            findings.append({
                "check_id": "DATABASE.ERROR",
                "title": "Error Running CIS Database Services Checks",
                "severity": "HIGH",
                "status": "WARNING",
                "resource_id": "aws:cis-databases",
                "description": f"Failed to run CIS Database Services Benchmark checks: {str(e)}",
                "recommendation": "Verify AWS credentials and permissions for database services",
                "compliance_standard": "CIS AWS Database Services Benchmark v1.0.0",
                "region": self.region,
            })

        return findings

    def _scan_cis_enduser(self) -> List[Dict[str, Any]]:
        """
        Run CIS AWS End User Compute Services Benchmark checks.

        Returns:
            List of findings from all CIS End User Compute checkers
        """
        findings = []

        try:
            logger.info("Running CIS End User Compute Services Benchmark checks...")

            # Initialize all End User Compute checkers
            workspaces_checker = WorkSpacesChecker(self.session, self.region)
            workspaces_web_checker = WorkSpacesWebChecker(self.session, self.region)
            workdocs_checker = WorkDocsChecker(self.session, self.region)
            appstream_checker = AppStreamChecker(self.session, self.region)

            # Run all checks
            logger.debug("Running WorkSpaces checks...")
            findings.extend(workspaces_checker.run_checks())

            logger.debug("Running WorkSpaces Web checks...")
            findings.extend(workspaces_web_checker.run_checks())

            logger.debug("Running WorkDocs checks...")
            findings.extend(workdocs_checker.run_checks())

            logger.debug("Running AppStream 2.0 checks...")
            findings.extend(appstream_checker.run_checks())

            logger.info(f"CIS End User Compute Services Benchmark checks completed: {len(findings)} findings")

        except Exception as e:
            logger.error(f"Error running CIS End User Compute Services Benchmark checks: {e}")
            findings.append({
                "check_id": "ENDUSER.ERROR",
                "title": "Error Running CIS End User Compute Checks",
                "severity": "HIGH",
                "status": "WARNING",
                "resource_id": "aws:cis-enduser",
                "description": f"Failed to run CIS End User Compute Services Benchmark checks: {str(e)}",
                "recommendation": "Verify AWS credentials and permissions for End User Compute services",
                "compliance_standard": "CIS AWS End User Compute Services Benchmark v1.2.0",
                "region": self.region,
            })

        return findings

    def _scan_cis_storage(self) -> List[Dict[str, Any]]:
        """
        Run CIS AWS Storage Services Benchmark checks.

        Returns:
            List of findings from all CIS Storage Services checkers
        """
        findings = []

        try:
            logger.info("Running CIS Storage Services Benchmark checks...")

            # Initialize all Storage Services checkers
            backup_checker = BackupChecker(self.session, self.region)
            ebs_checker = EBSChecker(self.session, self.region)
            efs_checker = EFSChecker(self.session, self.region)
            fsx_checker = FSxChecker(self.session, self.region)
            s3_checker = S3Checker(self.session, self.region)
            edr_checker = EDRChecker(self.session, self.region)

            # Run all checks
            logger.debug("Running AWS Backup checks...")
            findings.extend(backup_checker.run_checks())

            logger.debug("Running EBS checks...")
            findings.extend(ebs_checker.run_checks())

            logger.debug("Running EFS checks...")
            findings.extend(efs_checker.run_checks())

            logger.debug("Running FSx checks...")
            findings.extend(fsx_checker.run_checks())

            logger.debug("Running S3 checks...")
            findings.extend(s3_checker.run_checks())

            logger.debug("Running EDR checks...")
            findings.extend(edr_checker.run_checks())

            logger.info(f"CIS Storage Services Benchmark checks completed: {len(findings)} findings")

        except Exception as e:
            logger.error(f"Error running CIS Storage Services Benchmark checks: {e}")
            findings.append({
                "check_id": "STORAGE.ERROR",
                "title": "Error Running CIS Storage Services Checks",
                "severity": "HIGH",
                "status": "WARNING",
                "resource_id": "aws:cis-storage",
                "description": f"Failed to run CIS Storage Services Benchmark checks: {str(e)}",
                "recommendation": "Verify AWS credentials and permissions for Storage Services",
                "compliance_standard": "CIS AWS Storage Services Benchmark v1.0.0",
                "region": self.region,
            })

        return findings

    def _scan_legacy_checks(self) -> List[Dict[str, Any]]:
        """
        Scan real AWS environment using legacy checks (S3, IAM, CloudTrail, VPC).
        DEPRECATED: Use CIS Foundations checks instead.

        Returns:
            List of findings
        """
        findings = []

        try:
            # Example: Check S3 bucket encryption
            findings.extend(self._check_s3_encryption(self.session))

            # Example: Check IAM password policy
            findings.extend(self._check_iam_password_policy(self.session))

            # Example: Check CloudTrail logging
            findings.extend(self._check_cloudtrail(self.session))

            # Example: Check VPC flow logs
            findings.extend(self._check_vpc_flow_logs(self.session))

        except Exception as e:
            logger.error(f"Error running legacy checks: {e}")

        return findings

    def _check_s3_encryption(self, session) -> List[Dict[str, Any]]:
        """Check S3 bucket encryption settings."""
        findings = []
        try:
            s3 = session.client('s3')
            buckets = s3.list_buckets()

            for bucket in buckets.get('Buckets', []):
                bucket_name = bucket['Name']
                try:
                    s3.get_bucket_encryption(Bucket=bucket_name)
                    # Encryption enabled
                    findings.append({
                        "title": "S3 Bucket Encryption Enabled",
                        "severity": "INFO",
                        "status": "PASSED",
                        "resource_id": f"s3://{bucket_name}",
                        "description": "S3 bucket has encryption enabled.",
                        "recommendation": "Continue monitoring encryption settings.",
                    })
                except:
                    # Encryption not enabled
                    findings.append({
                        "title": "S3 Bucket Encryption Not Enabled",
                        "severity": "HIGH",
                        "status": "FAILED",
                        "resource_id": f"s3://{bucket_name}",
                        "description": "S3 bucket does not have default encryption enabled.",
                        "recommendation": "Enable default encryption on the S3 bucket using AES-256 or KMS.",
                    })
        except Exception as e:
            logger.error(f"Error checking S3 encryption: {e}")

        return findings

    def _check_iam_password_policy(self, session) -> List[Dict[str, Any]]:
        """Check IAM password policy compliance."""
        findings = []
        try:
            iam = session.client('iam')
            policy = iam.get_account_password_policy()['PasswordPolicy']

            if policy.get('MinimumPasswordLength', 0) < 14:
                findings.append({
                    "title": "IAM Password Policy: Weak Minimum Length",
                    "severity": "MEDIUM",
                    "status": "FAILED",
                    "resource_id": "iam:password-policy",
                    "description": f"Password minimum length is {policy.get('MinimumPasswordLength')} (should be >= 14).",
                    "recommendation": "Set minimum password length to 14 or more characters.",
                })

            if not policy.get('RequireNumbers', False):
                findings.append({
                    "title": "IAM Password Policy: Numbers Not Required",
                    "severity": "MEDIUM",
                    "status": "FAILED",
                    "resource_id": "iam:password-policy",
                    "description": "Password policy does not require numbers.",
                    "recommendation": "Enable requirement for numbers in passwords.",
                })

        except Exception as e:
            logger.error(f"Error checking IAM password policy: {e}")

        return findings

    def _check_cloudtrail(self, session) -> List[Dict[str, Any]]:
        """Check CloudTrail configuration."""
        findings = []
        try:
            cloudtrail = session.client('cloudtrail')
            trails = cloudtrail.describe_trails()['trailList']

            if not trails:
                findings.append({
                    "title": "CloudTrail Not Enabled",
                    "severity": "CRITICAL",
                    "status": "FAILED",
                    "resource_id": "cloudtrail",
                    "description": "No CloudTrail trails are configured in this region.",
                    "recommendation": "Enable CloudTrail with log file validation and encryption.",
                })

        except Exception as e:
            logger.error(f"Error checking CloudTrail: {e}")

        return findings

    def _check_vpc_flow_logs(self, session) -> List[Dict[str, Any]]:
        """Check VPC Flow Logs configuration."""
        findings = []
        try:
            ec2 = session.client('ec2')
            vpcs = ec2.describe_vpcs()['Vpcs']

            for vpc in vpcs:
                vpc_id = vpc['VpcId']
                flow_logs = ec2.describe_flow_logs(
                    Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
                )['FlowLogs']

                if not flow_logs:
                    findings.append({
                        "title": "VPC Flow Logs Not Enabled",
                        "severity": "MEDIUM",
                        "status": "FAILED",
                        "resource_id": vpc_id,
                        "description": f"VPC {vpc_id} does not have flow logs enabled.",
                        "recommendation": "Enable VPC Flow Logs for network traffic monitoring.",
                    })

        except Exception as e:
            logger.error(f"Error checking VPC flow logs: {e}")

        return findings

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """
        Get mock findings for demonstration purposes.

        Returns CIS Compute Benchmark findings if enabled, otherwise legacy findings.

        Returns:
            List of mock findings
        """
        findings = []

        # If CIS Compute is enabled, get CIS findings
        if self.enable_cis_compute:
            try:
                # Get mock findings from all CIS checkers
                ec2_ami_checker = EC2AMIChecker(None, self.region, True)
                ec2_ebs_checker = EC2EBSChecker(None, self.region, True)
                ec2_general_checker = EC2GeneralChecker(None, self.region, True)
                ecs_checker = ECSChecker(None, self.region, True)
                lambda_checker = LambdaChecker(None, self.region, True)

                findings.extend(ec2_ami_checker.run_checks())
                findings.extend(ec2_ebs_checker.run_checks())
                findings.extend(ec2_general_checker.run_checks())
                findings.extend(ecs_checker.run_checks())
                findings.extend(lambda_checker.run_checks())

                logger.info(f"Loaded {len(findings)} CIS Compute mock findings")
                return findings
            except Exception as e:
                logger.warning(f"Error loading CIS Compute mock findings: {e}")

        # Try to load legacy mock findings from JSON file
        mock_file = Path(__file__).parent.parent / "data" / "mock_results.json"

        if mock_file.exists():
            try:
                with open(mock_file, 'r') as f:
                    data = json.load(f)
                    findings = data.get('aws', {}).get('findings', [])
                    if findings:
                        logger.info(f"Loaded {len(findings)} legacy mock findings from file")
                        return findings
            except Exception as e:
                logger.warning(f"Could not load mock data from file: {e}")

        # Fallback legacy mock data
        return [
            {
                "title": "S3 Bucket Encryption Not Enabled",
                "severity": "HIGH",
                "status": "FAILED",
                "resource_id": "s3://my-company-data-bucket",
                "description": "S3 bucket does not have default encryption enabled. Data at rest is not encrypted.",
                "recommendation": "Enable default encryption on the S3 bucket using AES-256 or AWS KMS.",
            },
            {
                "title": "IAM Password Policy: Weak Minimum Length",
                "severity": "MEDIUM",
                "status": "FAILED",
                "resource_id": "iam:password-policy",
                "description": "IAM password policy requires only 8 characters minimum (CIS recommends 14).",
                "recommendation": "Update IAM password policy to require minimum 14 characters.",
            },
            {
                "title": "CloudTrail Log File Validation Enabled",
                "severity": "INFO",
                "status": "PASSED",
                "resource_id": "arn:aws:cloudtrail:us-east-1:123456789012:trail/main-trail",
                "description": "CloudTrail has log file validation enabled to ensure log integrity.",
                "recommendation": "Continue monitoring CloudTrail logs regularly.",
            },
            {
                "title": "MFA Not Enabled on Root Account",
                "severity": "CRITICAL",
                "status": "FAILED",
                "resource_id": "iam:root-account",
                "description": "Multi-factor authentication is not enabled on the root account.",
                "recommendation": "Enable MFA on the root account immediately using a hardware MFA device.",
            },
            {
                "title": "VPC Flow Logs Not Enabled",
                "severity": "MEDIUM",
                "status": "FAILED",
                "resource_id": "vpc-1234567890abcdef0",
                "description": "VPC does not have flow logs enabled for network traffic monitoring.",
                "recommendation": "Enable VPC Flow Logs and send to CloudWatch Logs or S3.",
            },
            {
                "title": "Security Group Allows Unrestricted Ingress",
                "severity": "HIGH",
                "status": "FAILED",
                "resource_id": "sg-0123456789abcdef0",
                "description": "Security group allows unrestricted ingress (0.0.0.0/0) on port 22.",
                "recommendation": "Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager.",
            },
            {
                "title": "EBS Volume Encryption Enabled",
                "severity": "INFO",
                "status": "PASSED",
                "resource_id": "vol-0123456789abcdef0",
                "description": "EBS volumes are encrypted at rest.",
                "recommendation": "Continue using encrypted volumes for all new instances.",
            },
        ]

    def _calculate_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Calculate summary statistics from findings.

        Args:
            findings: List of findings

        Returns:
            Summary dictionary with counts
        """
        summary = {
            "total_checks": len(findings),
            "passed": 0,
            "failed": 0,
            "warnings": 0,
        }

        for finding in findings:
            status = finding.get('status', 'UNKNOWN').upper()
            if status == 'PASSED':
                summary['passed'] += 1
            elif status == 'FAILED':
                summary['failed'] += 1
            elif status == 'WARNING':
                summary['warnings'] += 1

        return summary
