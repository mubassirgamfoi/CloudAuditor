import boto3
from typing import Dict, List, Any, Optional
from ..aws_checks.base_checker import BaseAWSChecker


class S3Checker(BaseAWSChecker):
    """
    S3 security checker implementation

    Implements S3 specific checks from CIS AWS Storage
    Services Benchmark v1.0.0
    """

    def __init__(self, session: boto3.Session, region: str = 'us-east-1', use_mock: bool = True):
        """Initialize S3 checker"""
        super().__init__(session, region, use_mock)
        self.service_name = "S3"

        # Initialize service clients
        if session:
            self.s3_client = session.client('s3', region_name=region)

    def check_s3_configuration(self) -> Dict[str, Any]:
        """
        Check S3 configuration
        
        Returns:
            Check result dictionary
        """
        try:
            if self.use_mock:
                return self.create_finding(
                    check_id="s3_5.1",
                    title="Amazon Simple Storage Service (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:s3:bucket",
                    description="S3 bucket configuration needs review",
                    recommendation="Configure S3 with proper access controls and encryption",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            # Check S3 buckets
            try:
                buckets = self.s3_client.list_buckets()
                total_buckets = len(buckets['Buckets'])

                if total_buckets == 0:
                    return self.create_finding(
                        check_id="s3_5.1",
                        title="Amazon Simple Storage Service (Manual)",
                        severity="LOW",
                        status="INFO",
                        resource_id="aws:s3:bucket",
                        description="No S3 buckets found",
                        recommendation="Create S3 buckets when needed",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

            except Exception as e:
                return self.create_finding(
                    check_id="s3_5.1",
                    title="Amazon Simple Storage Service (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:s3:bucket",
                    description=f"Error checking S3 buckets: {str(e)}",
                    recommendation="Review S3 configuration",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            return self.create_finding(
                check_id="s3_5.1",
                title="Amazon Simple Storage Service (Manual)",
                severity="MEDIUM",
                status="PASSED",
                resource_id="aws:s3:bucket",
                description=f"Found {total_buckets} S3 buckets",
                recommendation="Review S3 configuration regularly",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

        except Exception as e:
            return self.create_finding(
                check_id="s3_5.1",
                title="Amazon Simple Storage Service (Manual)",
                severity="HIGH",
                status="ERROR",
                resource_id="aws:s3:bucket",
                description=f"Error checking S3 configuration: {str(e)}",
                recommendation="Review S3 configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

    def check_s3_data_addition(self) -> Dict[str, Any]:
        """
        Check S3 direct data addition configuration
        
        Returns:
            Check result dictionary
        """
        try:
            if self.use_mock:
                return self.create_finding(
                    check_id="s3_5.2",
                    title="Ensure direct data addition to S3 (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:s3:data-addition",
                    description="Direct data addition to S3 process needs review",
                    recommendation="Ensure secure direct data addition to S3",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            # Check S3 buckets for public access
            try:
                buckets = self.s3_client.list_buckets()
                public_buckets = 0
                total_buckets = len(buckets['Buckets'])

                for bucket in buckets['Buckets']:
                    try:
                        # Check if bucket has public access
                        public_access = self.s3_client.get_public_access_block(
                            Bucket=bucket['Name']
                        )
                        if not public_access['PublicAccessBlockConfiguration']['BlockPublicAcls']:
                            public_buckets += 1
                    except:
                        # If we can't check public access, assume it might be public
                        public_buckets += 1

                if total_buckets == 0:
                    return self.create_finding(
                        check_id="s3_5.2",
                        title="Ensure direct data addition to S3 (Manual)",
                        severity="LOW",
                        status="INFO",
                        resource_id="aws:s3:data-addition",
                        description="No S3 buckets found",
                        recommendation="Create S3 buckets when needed",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

                if public_buckets > 0:
                    return self.create_finding(
                        check_id="s3_5.2",
                        title="Ensure direct data addition to S3 (Manual)",
                        severity="HIGH",
                        status="FAILED",
                        resource_id="aws:s3:data-addition",
                        description=f"Found {public_buckets}/{total_buckets} buckets with potential public access",
                        recommendation="Enable public access blocking for all S3 buckets",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

            except Exception as e:
                return self.create_finding(
                    check_id="s3_5.2",
                    title="Ensure direct data addition to S3 (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:s3:data-addition",
                    description=f"Error checking S3 public access: {str(e)}",
                    recommendation="Review S3 public access configuration",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            return self.create_finding(
                check_id="s3_5.2",
                title="Ensure direct data addition to S3 (Manual)",
                severity="MEDIUM",
                status="PASSED",
                resource_id="aws:s3:data-addition",
                description="S3 buckets have proper public access controls",
                recommendation="Continue monitoring S3 public access configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

        except Exception as e:
            return self.create_finding(
                check_id="s3_5.2",
                title="Ensure direct data addition to S3 (Manual)",
                severity="HIGH",
                status="ERROR",
                resource_id="aws:s3:data-addition",
                description=f"Error checking S3 data addition: {str(e)}",
                recommendation="Review S3 data addition configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

    def check_s3_storage_classes(self) -> Dict[str, Any]:
        """
        Check S3 storage classes configuration
        
        Returns:
            Check result dictionary
        """
        try:
            if self.use_mock:
                return self.create_finding(
                    check_id="s3_5.3",
                    title="Ensure Storage Classes are Configured (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:s3:storage-classes",
                    description="S3 storage classes need proper configuration",
                    recommendation="Configure appropriate S3 storage classes for cost optimization",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            # Check S3 buckets for lifecycle policies
            try:
                buckets = self.s3_client.list_buckets()
                buckets_with_lifecycle = 0
                total_buckets = len(buckets['Buckets'])

                for bucket in buckets['Buckets']:
                    try:
                        lifecycle = self.s3_client.get_bucket_lifecycle_configuration(
                            Bucket=bucket['Name']
                        )
                        if lifecycle.get('Rules'):
                            buckets_with_lifecycle += 1
                    except:
                        # No lifecycle configuration
                        pass

                if total_buckets == 0:
                    return self.create_finding(
                        check_id="s3_5.3",
                        title="Ensure Storage Classes are Configured (Manual)",
                        severity="LOW",
                        status="INFO",
                        resource_id="aws:s3:storage-classes",
                        description="No S3 buckets found",
                        recommendation="Create S3 buckets when needed",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

                if buckets_with_lifecycle < total_buckets:
                    return self.create_finding(
                        check_id="s3_5.3",
                        title="Ensure Storage Classes are Configured (Manual)",
                        severity="MEDIUM",
                        status="WARNING",
                        resource_id="aws:s3:storage-classes",
                        description=f"Only {buckets_with_lifecycle}/{total_buckets} buckets have lifecycle policies",
                        recommendation="Configure lifecycle policies for all S3 buckets to optimize storage costs",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

            except Exception as e:
                return self.create_finding(
                    check_id="s3_5.3",
                    title="Ensure Storage Classes are Configured (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:s3:storage-classes",
                    description=f"Error checking S3 lifecycle policies: {str(e)}",
                    recommendation="Review S3 lifecycle configuration",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            return self.create_finding(
                check_id="s3_5.3",
                title="Ensure Storage Classes are Configured (Manual)",
                severity="MEDIUM",
                status="PASSED",
                resource_id="aws:s3:storage-classes",
                description="S3 buckets have proper lifecycle policies configured",
                recommendation="Continue monitoring S3 storage class configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

        except Exception as e:
            return self.create_finding(
                check_id="s3_5.3",
                title="Ensure Storage Classes are Configured (Manual)",
                severity="HIGH",
                status="ERROR",
                resource_id="aws:s3:storage-classes",
                description=f"Error checking S3 storage classes: {str(e)}",
                recommendation="Review S3 storage class configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

    def run_checks(self) -> List[Dict[str, Any]]:
        """
        Run all S3 security checks

        Returns:
            List of check results
        """
        if self.use_mock:
            return self._get_mock_findings()

        checks = [
            self.check_s3_configuration(),
            self.check_s3_data_addition(),
            self.check_s3_storage_classes()
        ]

        return checks

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """
        Get mock findings for S3

        Returns:
            List of mock findings
        """
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
