import boto3
from typing import Dict, List, Any, Optional
from ..aws_checks.base_checker import BaseAWSChecker


class EBSChecker(BaseAWSChecker):
    """
    EBS security checker implementation

    Implements EBS specific checks from CIS AWS Storage
    Services Benchmark v1.0.0
    """

    def __init__(self, session: boto3.Session, region: str = 'us-east-1', use_mock: bool = True):
        """Initialize EBS checker"""
        super().__init__(session, region, use_mock)
        self.service_name = "EBS"

        # Initialize service clients
        if session:
            self.ec2_client = session.client('ec2', region_name=region)
            self.iam_client = session.client('iam', region_name=region)
            self.cloudwatch_client = session.client('cloudwatch', region_name=region)
            self.sns_client = session.client('sns', region_name=region)

    def check_ec2_instance_with_ebs(self) -> Dict[str, Any]:
        """
        Check EC2 instance with EBS configuration
        
        Returns:
            Check result dictionary
        """
        try:
            if self.use_mock:
                return self.create_finding(
                    check_id="ebs_2.1",
                    title="Ensure creating EC2 instance with EBS (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:ebs:ec2-instance",
                    description="EC2 instance with EBS configuration needs review",
                    recommendation="Ensure EC2 instances are properly configured with EBS volumes",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            # Check EC2 instances with EBS volumes
            try:
                instances = self.ec2_client.describe_instances()
                instances_with_ebs = 0
                total_instances = 0

                for reservation in instances['Reservations']:
                    for instance in reservation['Instances']:
                        if instance['State']['Name'] in ['running', 'stopped']:
                            total_instances += 1
                            if instance.get('BlockDeviceMappings'):
                                instances_with_ebs += 1

                if total_instances == 0:
                    return self.create_finding(
                        check_id="ebs_2.1",
                        title="Ensure creating EC2 instance with EBS (Manual)",
                        severity="LOW",
                        status="INFO",
                        resource_id="aws:ebs:ec2-instance",
                        description="No EC2 instances found",
                        recommendation="Create EC2 instances with EBS volumes when needed",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

                if instances_with_ebs < total_instances:
                    return self.create_finding(
                        check_id="ebs_2.1",
                        title="Ensure creating EC2 instance with EBS (Manual)",
                        severity="MEDIUM",
                        status="WARNING",
                        resource_id="aws:ebs:ec2-instance",
                        description=f"Only {instances_with_ebs}/{total_instances} instances have EBS volumes",
                        recommendation="Ensure all EC2 instances are configured with EBS volumes",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

            except Exception as e:
                return self.create_finding(
                    check_id="ebs_2.1",
                    title="Ensure creating EC2 instance with EBS (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:ebs:ec2-instance",
                    description=f"Error checking EC2 instances: {str(e)}",
                    recommendation="Review EC2 instance configuration",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            return self.create_finding(
                check_id="ebs_2.1",
                title="Ensure creating EC2 instance with EBS (Manual)",
                severity="MEDIUM",
                status="PASSED",
                resource_id="aws:ebs:ec2-instance",
                description="All EC2 instances are configured with EBS volumes",
                recommendation="Continue monitoring EC2 instance configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

        except Exception as e:
            return self.create_finding(
                check_id="ebs_2.1",
                title="Ensure creating EC2 instance with EBS (Manual)",
                severity="HIGH",
                status="ERROR",
                resource_id="aws:ebs:ec2-instance",
                description=f"Error checking EC2 instance with EBS: {str(e)}",
                recommendation="Review EC2 instance configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

    def check_security_groups_configuration(self) -> Dict[str, Any]:
        """
        Check security groups configuration for EBS
        
        Returns:
            Check result dictionary
        """
        try:
            if self.use_mock:
                return self.create_finding(
                    check_id="ebs_2.2",
                    title="Ensure configuring Security Groups (Manual)",
                    severity="HIGH",
                    status="FAILED",
                    resource_id="aws:ebs:security-groups",
                    description="Security groups for EBS are not properly configured",
                    recommendation="Configure security groups to restrict traffic to necessary ports only",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            # Check security groups for overly permissive rules
            try:
                security_groups = self.ec2_client.describe_security_groups()
                overly_permissive = 0
                total_sgs = len(security_groups['SecurityGroups'])

                for sg in security_groups['SecurityGroups']:
                    for rule in sg.get('IpPermissions', []):
                        # Check for overly permissive rules (0.0.0.0/0)
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                overly_permissive += 1
                                break

                if overly_permissive > 0:
                    return self.create_finding(
                        check_id="ebs_2.2",
                        title="Ensure configuring Security Groups (Manual)",
                        severity="HIGH",
                        status="FAILED",
                        resource_id="aws:ebs:security-groups",
                        description=f"Found {overly_permissive} security groups with overly permissive rules",
                        recommendation="Restrict security group rules to specific IP ranges",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

            except Exception as e:
                return self.create_finding(
                    check_id="ebs_2.2",
                    title="Ensure configuring Security Groups (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:ebs:security-groups",
                    description=f"Error checking security groups: {str(e)}",
                    recommendation="Review security group configuration",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            return self.create_finding(
                check_id="ebs_2.2",
                title="Ensure configuring Security Groups (Manual)",
                severity="HIGH",
                status="PASSED",
                resource_id="aws:ebs:security-groups",
                description="Security groups are properly configured",
                recommendation="Continue monitoring security group configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

        except Exception as e:
            return self.create_finding(
                check_id="ebs_2.2",
                title="Ensure configuring Security Groups (Manual)",
                severity="HIGH",
                status="ERROR",
                resource_id="aws:ebs:security-groups",
                description=f"Error checking security groups configuration: {str(e)}",
                recommendation="Review security group configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

    def check_ebs_storage_configuration(self) -> Dict[str, Any]:
        """
        Check EBS storage configuration
        
        Returns:
            Check result dictionary
        """
        try:
            if self.use_mock:
                return self.create_finding(
                    check_id="ebs_2.3",
                    title="Ensure the proper configuration of EBS storage (Manual)",
                    severity="HIGH",
                    status="PASSED",
                    resource_id="aws:ebs:storage",
                    description="EBS storage is properly configured",
                    recommendation="Continue monitoring EBS configuration",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            # Check EBS volumes configuration
            try:
                volumes = self.ec2_client.describe_volumes()
                unencrypted_volumes = 0
                total_volumes = len(volumes['Volumes'])

                for volume in volumes['Volumes']:
                    if not volume.get('Encrypted', False):
                        unencrypted_volumes += 1

                if total_volumes == 0:
                    return self.create_finding(
                        check_id="ebs_2.3",
                        title="Ensure the proper configuration of EBS storage (Manual)",
                        severity="LOW",
                        status="INFO",
                        resource_id="aws:ebs:storage",
                        description="No EBS volumes found",
                        recommendation="Create EBS volumes when needed",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

                if unencrypted_volumes > 0:
                    return self.create_finding(
                        check_id="ebs_2.3",
                        title="Ensure the proper configuration of EBS storage (Manual)",
                        severity="HIGH",
                        status="FAILED",
                        resource_id="aws:ebs:storage",
                        description=f"Found {unencrypted_volumes}/{total_volumes} unencrypted EBS volumes",
                        recommendation="Enable encryption for all EBS volumes",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

            except Exception as e:
                return self.create_finding(
                    check_id="ebs_2.3",
                    title="Ensure the proper configuration of EBS storage (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:ebs:storage",
                    description=f"Error checking EBS volumes: {str(e)}",
                    recommendation="Review EBS volume configuration",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            return self.create_finding(
                check_id="ebs_2.3",
                title="Ensure the proper configuration of EBS storage (Manual)",
                severity="HIGH",
                status="PASSED",
                resource_id="aws:ebs:storage",
                description="All EBS volumes are properly encrypted",
                recommendation="Continue monitoring EBS configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

        except Exception as e:
            return self.create_finding(
                check_id="ebs_2.3",
                title="Ensure the proper configuration of EBS storage (Manual)",
                severity="HIGH",
                status="ERROR",
                resource_id="aws:ebs:storage",
                description=f"Error checking EBS storage configuration: {str(e)}",
                recommendation="Review EBS storage configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

    def check_new_volume_creation(self) -> Dict[str, Any]:
        """
        Check new volume creation configuration
        
        Returns:
            Check result dictionary
        """
        try:
            if self.use_mock:
                return self.create_finding(
                    check_id="ebs_2.4",
                    title="Ensure the creation of a new volume (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:ebs:new-volume",
                    description="New EBS volume creation process needs review",
                    recommendation="Ensure proper volume creation with encryption and delete protection",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            # Check EBS volumes for proper configuration
            try:
                volumes = self.ec2_client.describe_volumes()
                volumes_without_delete_protection = 0
                total_volumes = len(volumes['Volumes'])

                for volume in volumes['Volumes']:
                    if not volume.get('DeleteOnTermination', False):
                        volumes_without_delete_protection += 1

                if total_volumes == 0:
                    return self.create_finding(
                        check_id="ebs_2.4",
                        title="Ensure the creation of a new volume (Manual)",
                        severity="LOW",
                        status="INFO",
                        resource_id="aws:ebs:new-volume",
                        description="No EBS volumes found",
                        recommendation="Create EBS volumes when needed",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

                if volumes_without_delete_protection < total_volumes:
                    return self.create_finding(
                        check_id="ebs_2.4",
                        title="Ensure the creation of a new volume (Manual)",
                        severity="MEDIUM",
                        status="WARNING",
                        resource_id="aws:ebs:new-volume",
                        description=f"Some volumes have delete on termination enabled",
                        recommendation="Consider disabling delete on termination for critical volumes",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

            except Exception as e:
                return self.create_finding(
                    check_id="ebs_2.4",
                    title="Ensure the creation of a new volume (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:ebs:new-volume",
                    description=f"Error checking EBS volumes: {str(e)}",
                    recommendation="Review EBS volume configuration",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            return self.create_finding(
                check_id="ebs_2.4",
                title="Ensure the creation of a new volume (Manual)",
                severity="MEDIUM",
                status="PASSED",
                resource_id="aws:ebs:new-volume",
                description="EBS volumes are properly configured",
                recommendation="Continue monitoring EBS volume configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

        except Exception as e:
            return self.create_finding(
                check_id="ebs_2.4",
                title="Ensure the creation of a new volume (Manual)",
                severity="HIGH",
                status="ERROR",
                resource_id="aws:ebs:new-volume",
                description=f"Error checking new volume creation: {str(e)}",
                recommendation="Review EBS volume creation process",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

    def check_ebs_snapshots(self) -> Dict[str, Any]:
        """
        Check EBS volume snapshots
        
        Returns:
            Check result dictionary
        """
        try:
            if self.use_mock:
                return self.create_finding(
                    check_id="ebs_2.5",
                    title="Ensure creating snapshots of EBS volumes (Manual)",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="aws:ebs:snapshots",
                    description="EBS volume snapshots are not being created regularly",
                    recommendation="Implement regular EBS volume snapshots for data protection",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            # Check EBS snapshots
            try:
                snapshots = self.ec2_client.describe_snapshots(OwnerIds=['self'])
                total_snapshots = len(snapshots['Snapshots'])

                if total_snapshots == 0:
                    return self.create_finding(
                        check_id="ebs_2.5",
                        title="Ensure creating snapshots of EBS volumes (Manual)",
                        severity="HIGH",
                        status="FAILED",
                        resource_id="aws:ebs:snapshots",
                        description="No EBS snapshots found",
                        recommendation="Create regular snapshots of EBS volumes for data protection",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

            except Exception as e:
                return self.create_finding(
                    check_id="ebs_2.5",
                    title="Ensure creating snapshots of EBS volumes (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:ebs:snapshots",
                    description=f"Error checking EBS snapshots: {str(e)}",
                    recommendation="Review EBS snapshot configuration",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            return self.create_finding(
                check_id="ebs_2.5",
                title="Ensure creating snapshots of EBS volumes (Manual)",
                severity="HIGH",
                status="PASSED",
                resource_id="aws:ebs:snapshots",
                description=f"Found {total_snapshots} EBS snapshots",
                recommendation="Continue regular EBS volume snapshots",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

        except Exception as e:
            return self.create_finding(
                check_id="ebs_2.5",
                title="Ensure creating snapshots of EBS volumes (Manual)",
                severity="HIGH",
                status="ERROR",
                resource_id="aws:ebs:snapshots",
                description=f"Error checking EBS snapshots: {str(e)}",
                recommendation="Review EBS snapshot configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

    def run_checks(self) -> List[Dict[str, Any]]:
        """
        Run all EBS security checks

        Returns:
            List of check results
        """
        if self.use_mock:
            return self._get_mock_findings()

        checks = [
            self.check_ec2_instance_with_ebs(),
            self.check_security_groups_configuration(),
            self.check_ebs_storage_configuration(),
            self.check_new_volume_creation(),
            self.check_ebs_snapshots()
        ]

        return checks

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """
        Get mock findings for EBS

        Returns:
            List of mock findings
        """
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
            )
        ]
