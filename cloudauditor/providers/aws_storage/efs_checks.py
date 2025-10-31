import boto3
from typing import Dict, List, Any, Optional
from ..aws_checks.base_checker import BaseAWSChecker


class EFSChecker(BaseAWSChecker):
    """
    EFS security checker implementation

    Implements EFS specific checks from CIS AWS Storage
    Services Benchmark v1.0.0
    """

    def __init__(self, session: boto3.Session, region: str = 'us-east-1', use_mock: bool = True):
        """Initialize EFS checker"""
        super().__init__(session, region, use_mock)
        self.service_name = "EFS"

        # Initialize service clients
        if session:
            self.efs_client = session.client('efs', region_name=region)
            self.ec2_client = session.client('ec2', region_name=region)
            self.iam_client = session.client('iam', region_name=region)

    def check_efs_configuration(self) -> Dict[str, Any]:
        """
        Check EFS configuration
        
        Returns:
            Check result dictionary
        """
        try:
            if self.use_mock:
                return self.create_finding(
                    check_id="efs_3.1",
                    title="EFS (Manual)",
                    severity="MEDIUM",
                    status="INFO",
                    resource_id="aws:efs:filesystem",
                    description="EFS file system is configured",
                    recommendation="Review EFS configuration regularly",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            # Check EFS file systems
            try:
                file_systems = self.efs_client.describe_file_systems()
                total_fs = len(file_systems['FileSystems'])

                if total_fs == 0:
                    return self.create_finding(
                        check_id="efs_3.1",
                        title="EFS (Manual)",
                        severity="LOW",
                        status="INFO",
                        resource_id="aws:efs:filesystem",
                        description="No EFS file systems found",
                        recommendation="Create EFS file systems when needed",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

            except Exception as e:
                return self.create_finding(
                    check_id="efs_3.1",
                    title="EFS (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:efs:filesystem",
                    description=f"Error checking EFS file systems: {str(e)}",
                    recommendation="Review EFS configuration",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            return self.create_finding(
                check_id="efs_3.1",
                title="EFS (Manual)",
                severity="MEDIUM",
                status="PASSED",
                resource_id="aws:efs:filesystem",
                description=f"Found {total_fs} EFS file systems",
                recommendation="Review EFS configuration regularly",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

        except Exception as e:
            return self.create_finding(
                check_id="efs_3.1",
                title="EFS (Manual)",
                severity="HIGH",
                status="ERROR",
                resource_id="aws:efs:filesystem",
                description=f"Error checking EFS configuration: {str(e)}",
                recommendation="Review EFS configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

    def check_efs_implementation(self) -> Dict[str, Any]:
        """
        Check EFS implementation
        
        Returns:
            Check result dictionary
        """
        try:
            if self.use_mock:
                return self.create_finding(
                    check_id="efs_3.2",
                    title="Ensure Implementation of EFS (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:efs:implementation",
                    description="EFS implementation needs review",
                    recommendation="Ensure proper EFS implementation with encryption",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            # Check EFS file systems for encryption
            try:
                file_systems = self.efs_client.describe_file_systems()
                unencrypted_fs = 0
                total_fs = len(file_systems['FileSystems'])

                for fs in file_systems['FileSystems']:
                    if not fs.get('Encrypted', False):
                        unencrypted_fs += 1

                if total_fs == 0:
                    return self.create_finding(
                        check_id="efs_3.2",
                        title="Ensure Implementation of EFS (Manual)",
                        severity="LOW",
                        status="INFO",
                        resource_id="aws:efs:implementation",
                        description="No EFS file systems found",
                        recommendation="Create EFS file systems when needed",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

                if unencrypted_fs > 0:
                    return self.create_finding(
                        check_id="efs_3.2",
                        title="Ensure Implementation of EFS (Manual)",
                        severity="HIGH",
                        status="FAILED",
                        resource_id="aws:efs:implementation",
                        description=f"Found {unencrypted_fs}/{total_fs} unencrypted EFS file systems",
                        recommendation="Enable encryption for all EFS file systems",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

            except Exception as e:
                return self.create_finding(
                    check_id="efs_3.2",
                    title="Ensure Implementation of EFS (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:efs:implementation",
                    description=f"Error checking EFS implementation: {str(e)}",
                    recommendation="Review EFS implementation",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            return self.create_finding(
                check_id="efs_3.2",
                title="Ensure Implementation of EFS (Manual)",
                severity="MEDIUM",
                status="PASSED",
                resource_id="aws:efs:implementation",
                description="All EFS file systems are properly encrypted",
                recommendation="Continue monitoring EFS implementation",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

        except Exception as e:
            return self.create_finding(
                check_id="efs_3.2",
                title="Ensure Implementation of EFS (Manual)",
                severity="HIGH",
                status="ERROR",
                resource_id="aws:efs:implementation",
                description=f"Error checking EFS implementation: {str(e)}",
                recommendation="Review EFS implementation",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

    def check_efs_vpc_integration(self) -> Dict[str, Any]:
        """
        Check EFS and VPC integration
        
        Returns:
            Check result dictionary
        """
        try:
            if self.use_mock:
                return self.create_finding(
                    check_id="efs_3.3",
                    title="Ensure EFS and VPC Integration (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:efs:vpc-integration",
                    description="EFS and VPC integration needs review",
                    recommendation="Ensure proper EFS and VPC integration for redundancy",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            # Check EFS mount targets across availability zones
            try:
                file_systems = self.efs_client.describe_file_systems()
                for fs in file_systems['FileSystems']:
                    mount_targets = self.efs_client.describe_mount_targets(
                        FileSystemId=fs['FileSystemId']
                    )
                    azs = set()
                    for mt in mount_targets['MountTargets']:
                        azs.add(mt['AvailabilityZoneId'])
                    
                    if len(azs) < 2:
                        return self.create_finding(
                            check_id="efs_3.3",
                            title="Ensure EFS and VPC Integration (Manual)",
                            severity="MEDIUM",
                            status="WARNING",
                            resource_id="aws:efs:vpc-integration",
                            description=f"EFS {fs['FileSystemId']} has mount targets in only {len(azs)} availability zone(s)",
                            recommendation="Create mount targets in multiple availability zones for redundancy",
                            compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                        )

            except Exception as e:
                return self.create_finding(
                    check_id="efs_3.3",
                    title="Ensure EFS and VPC Integration (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:efs:vpc-integration",
                    description=f"Error checking EFS VPC integration: {str(e)}",
                    recommendation="Review EFS and VPC integration",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            return self.create_finding(
                check_id="efs_3.3",
                title="Ensure EFS and VPC Integration (Manual)",
                severity="MEDIUM",
                status="PASSED",
                resource_id="aws:efs:vpc-integration",
                description="EFS is properly integrated with VPC across multiple AZs",
                recommendation="Continue monitoring EFS and VPC integration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

        except Exception as e:
            return self.create_finding(
                check_id="efs_3.3",
                title="Ensure EFS and VPC Integration (Manual)",
                severity="HIGH",
                status="ERROR",
                resource_id="aws:efs:vpc-integration",
                description=f"Error checking EFS VPC integration: {str(e)}",
                recommendation="Review EFS and VPC integration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

    def run_checks(self) -> List[Dict[str, Any]]:
        """
        Run all EFS security checks

        Returns:
            List of check results
        """
        if self.use_mock:
            return self._get_mock_findings()

        checks = [
            self.check_efs_configuration(),
            self.check_efs_implementation(),
            self.check_efs_vpc_integration()
        ]

        return checks

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """
        Get mock findings for EFS

        Returns:
            List of mock findings
        """
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
            )
        ]
