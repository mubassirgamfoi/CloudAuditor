import boto3
from typing import Dict, List, Any, Optional
from ..aws_checks.base_checker import BaseAWSChecker


class FSxChecker(BaseAWSChecker):
    """
    FSx security checker implementation

    Implements FSx specific checks from CIS AWS Storage
    Services Benchmark v1.0.0
    """

    def __init__(self, session: boto3.Session, region: str = 'us-east-1', use_mock: bool = True):
        """Initialize FSx checker"""
        super().__init__(session, region, use_mock)
        self.service_name = "FSx"

        # Initialize service clients
        if session:
            self.fsx_client = session.client('fsx', region_name=region)
            self.s3_client = session.client('s3', region_name=region)

    def check_fsx_file_cache(self) -> Dict[str, Any]:
        """
        Check FSx file cache configuration
        
        Returns:
            Check result dictionary
        """
        try:
            if self.use_mock:
                return self.create_finding(
                    check_id="fsx_4.1",
                    title="FSX (AWS Elastic File Cache) (Manual)",
                    severity="MEDIUM",
                    status="INFO",
                    resource_id="aws:fsx:file-cache",
                    description="AWS Elastic File Cache is configured",
                    recommendation="Review FSx file cache configuration",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            # Check FSx file caches
            try:
                file_caches = self.fsx_client.describe_file_caches()
                total_caches = len(file_caches['FileCaches'])

                if total_caches == 0:
                    return self.create_finding(
                        check_id="fsx_4.1",
                        title="FSX (AWS Elastic File Cache) (Manual)",
                        severity="LOW",
                        status="INFO",
                        resource_id="aws:fsx:file-cache",
                        description="No FSx file caches found",
                        recommendation="Create FSx file caches when needed",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

            except Exception as e:
                return self.create_finding(
                    check_id="fsx_4.1",
                    title="FSX (AWS Elastic File Cache) (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:fsx:file-cache",
                    description=f"Error checking FSx file caches: {str(e)}",
                    recommendation="Review FSx file cache configuration",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            return self.create_finding(
                check_id="fsx_4.1",
                title="FSX (AWS Elastic File Cache) (Manual)",
                severity="MEDIUM",
                status="PASSED",
                resource_id="aws:fsx:file-cache",
                description=f"Found {total_caches} FSx file caches",
                recommendation="Review FSx file cache configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

        except Exception as e:
            return self.create_finding(
                check_id="fsx_4.1",
                title="FSX (AWS Elastic File Cache) (Manual)",
                severity="HIGH",
                status="ERROR",
                resource_id="aws:fsx:file-cache",
                description=f"Error checking FSx file cache: {str(e)}",
                recommendation="Review FSx file cache configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

    def check_elastic_file_cache(self) -> Dict[str, Any]:
        """
        Check Elastic File Cache configuration
        
        Returns:
            Check result dictionary
        """
        try:
            if self.use_mock:
                return self.create_finding(
                    check_id="fsx_4.2",
                    title="Amazon Elastic File Cache (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:fsx:elastic-file-cache",
                    description="Elastic File Cache configuration needs review",
                    recommendation="Ensure proper Elastic File Cache configuration",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            # Check FSx file caches for proper configuration
            try:
                file_caches = self.fsx_client.describe_file_caches()
                unencrypted_caches = 0
                total_caches = len(file_caches['FileCaches'])

                for cache in file_caches['FileCaches']:
                    if not cache.get('KmsKeyId'):
                        unencrypted_caches += 1

                if total_caches == 0:
                    return self.create_finding(
                        check_id="fsx_4.2",
                        title="Amazon Elastic File Cache (Manual)",
                        severity="LOW",
                        status="INFO",
                        resource_id="aws:fsx:elastic-file-cache",
                        description="No FSx file caches found",
                        recommendation="Create FSx file caches when needed",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

                if unencrypted_caches > 0:
                    return self.create_finding(
                        check_id="fsx_4.2",
                        title="Amazon Elastic File Cache (Manual)",
                        severity="HIGH",
                        status="FAILED",
                        resource_id="aws:fsx:elastic-file-cache",
                        description=f"Found {unencrypted_caches}/{total_caches} unencrypted file caches",
                        recommendation="Enable encryption for all FSx file caches",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

            except Exception as e:
                return self.create_finding(
                    check_id="fsx_4.2",
                    title="Amazon Elastic File Cache (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:fsx:elastic-file-cache",
                    description=f"Error checking FSx file caches: {str(e)}",
                    recommendation="Review FSx file cache configuration",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            return self.create_finding(
                check_id="fsx_4.2",
                title="Amazon Elastic File Cache (Manual)",
                severity="MEDIUM",
                status="PASSED",
                resource_id="aws:fsx:elastic-file-cache",
                description="All FSx file caches are properly encrypted",
                recommendation="Continue monitoring FSx file cache configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

        except Exception as e:
            return self.create_finding(
                check_id="fsx_4.2",
                title="Amazon Elastic File Cache (Manual)",
                severity="HIGH",
                status="ERROR",
                resource_id="aws:fsx:elastic-file-cache",
                description=f"Error checking Elastic File Cache: {str(e)}",
                recommendation="Review FSx file cache configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

    def check_fsx_s3_bucket(self) -> Dict[str, Any]:
        """
        Check FSx S3 bucket configuration
        
        Returns:
            Check result dictionary
        """
        try:
            if self.use_mock:
                return self.create_finding(
                    check_id="fsx_4.3",
                    title="Ensure the creation of an FSX Bucket (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:fsx:s3-bucket",
                    description="S3 bucket for FSx needs creation",
                    recommendation="Create and configure S3 bucket for FSx data storage",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            # Check S3 buckets for FSx usage
            try:
                buckets = self.s3_client.list_buckets()
                fsx_buckets = 0
                total_buckets = len(buckets['Buckets'])

                for bucket in buckets['Buckets']:
                    # Check if bucket name suggests FSx usage
                    if 'fsx' in bucket['Name'].lower() or 'lustre' in bucket['Name'].lower():
                        fsx_buckets += 1

                if total_buckets == 0:
                    return self.create_finding(
                        check_id="fsx_4.3",
                        title="Ensure the creation of an FSX Bucket (Manual)",
                        severity="LOW",
                        status="INFO",
                        resource_id="aws:fsx:s3-bucket",
                        description="No S3 buckets found",
                        recommendation="Create S3 buckets when needed",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

                if fsx_buckets == 0:
                    return self.create_finding(
                        check_id="fsx_4.3",
                        title="Ensure the creation of an FSX Bucket (Manual)",
                        severity="MEDIUM",
                        status="WARNING",
                        resource_id="aws:fsx:s3-bucket",
                        description="No S3 buckets found for FSx usage",
                        recommendation="Create S3 bucket for FSx data storage",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

            except Exception as e:
                return self.create_finding(
                    check_id="fsx_4.3",
                    title="Ensure the creation of an FSX Bucket (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:fsx:s3-bucket",
                    description=f"Error checking S3 buckets: {str(e)}",
                    recommendation="Review S3 bucket configuration",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            return self.create_finding(
                check_id="fsx_4.3",
                title="Ensure the creation of an FSX Bucket (Manual)",
                severity="MEDIUM",
                status="PASSED",
                resource_id="aws:fsx:s3-bucket",
                description=f"Found {fsx_buckets} S3 buckets for FSx usage",
                recommendation="Continue monitoring S3 bucket configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

        except Exception as e:
            return self.create_finding(
                check_id="fsx_4.3",
                title="Ensure the creation of an FSX Bucket (Manual)",
                severity="HIGH",
                status="ERROR",
                resource_id="aws:fsx:s3-bucket",
                description=f"Error checking FSx S3 bucket: {str(e)}",
                recommendation="Review S3 bucket configuration for FSx",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

    def run_checks(self) -> List[Dict[str, Any]]:
        """
        Run all FSx security checks

        Returns:
            List of check results
        """
        if self.use_mock:
            return self._get_mock_findings()

        checks = [
            self.check_fsx_file_cache(),
            self.check_elastic_file_cache(),
            self.check_fsx_s3_bucket()
        ]

        return checks

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """
        Get mock findings for FSx

        Returns:
            List of mock findings
        """
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
            )
        ]
