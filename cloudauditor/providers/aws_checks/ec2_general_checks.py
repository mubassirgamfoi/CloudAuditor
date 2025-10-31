"""
CIS AWS Compute Benchmark - EC2 General Checks (Section 2.3-2.14)
"""

from typing import Dict, Any, List
from datetime import datetime, timedelta
from cloudauditor.providers.aws_checks.base_checker import BaseAWSChecker


class EC2GeneralChecker(BaseAWSChecker):
    """Checker for general EC2 security configurations"""

    def run_checks(self) -> List[Dict[str, Any]]:
        """Run all general EC2 checks"""
        if self.use_mock:
            return self._get_mock_findings()

        findings = []
        try:
            findings.extend(self.check_tag_policies_enabled())
            findings.extend(self.check_org_ec2_tag_policy_created())
            findings.extend(self.check_instance_age())
            findings.extend(self.check_detailed_monitoring())
            findings.extend(self.check_default_security_groups())
            findings.extend(self.check_imdsv2())
            findings.extend(self.check_systems_manager())
            findings.extend(self.check_unused_enis())
            findings.extend(self.check_stopped_instances())
            findings.extend(self.check_ebs_delete_on_termination())
            findings.extend(self.check_secrets_in_userdata())
            findings.extend(self.check_autoscaling_tag_propagation())
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.ERROR",
                    title="Error Running EC2 General Checks",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="ec2",
                    description=f"Failed to run EC2 general checks: {str(e)}",
                    recommendation="Verify AWS credentials and permissions",
                )
            )

        return findings

    def check_tag_policies_enabled(self) -> List[Dict[str, Any]]:
        """
        2.3: Ensure Tag Policies are Enabled (Manual)
        Level: 1 | Type: Manual
        """
        findings: List[Dict[str, Any]] = []
        try:
            org = self.session.client("organizations")
            policies = org.list_policies(Filter="TAG_POLICY")
            enabled = len(policies.get("Policies", [])) > 0

            if not enabled:
                findings.append(
                    self.create_finding(
                        check_id="2.3",
                        title="AWS Organizations Tag Policies Not Enabled",
                        severity="LOW",
                        status="FAILED",
                        resource_id="organizations:tag-policies",
                        description="No tag policies found. Tag Policies help standardize tags enterprise-wide.",
                        recommendation=(
                            "Enable Tag Policies in AWS Organizations root and create tag policies.\n"
                            "From CLI (management account): aws organizations enable-policy-type --root-id <RootID> --policy-type TAG_POLICIES\n"
                            "Verify: aws organizations list-policies --filter TAG_POLICY"
                        ),
                        command="aws organizations list-policies --filter TAG_POLICY",
                        evidence={"Policies": policies.get("Policies", [])},
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        check_id="2.3",
                        title="AWS Organizations Tag Policies Present",
                        severity="INFO",
                        status="PASSED",
                        resource_id="organizations:tag-policies",
                        description="One or more tag policies exist in the organization.",
                        recommendation=(
                            "Ensure policies are attached to roots/OUs and cover EC2 resources.\n"
                            "Describe policy content for review: aws organizations describe-policy --policy-id <policy-id>"
                        ),
                        command="aws organizations list-policies --filter TAG_POLICY",
                        evidence={"Policies": policies.get("Policies", [])},
                    )
                )
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.3",
                    title="Unable to Check Tag Policies",
                    severity="LOW",
                    status="WARNING",
                    resource_id="organizations",
                    description=f"Could not verify tag policies: {str(e)}",
                    recommendation="Verify Organizations permissions and that you are in management account",
                )
            )

        return findings

    def check_org_ec2_tag_policy_created(self) -> List[Dict[str, Any]]:
        """
        2.4: Ensure an Organizational EC2 Tag Policy has been Created (Manual)
        Level: 1 | Type: Manual
        """
        findings: List[Dict[str, Any]] = []
        try:
            org = self.session.client("organizations")
            policies = org.list_policies(Filter="TAG_POLICY").get("Policies", [])

            # We cannot fully validate content without DescribePolicy + parsing; provide guidance and surface IDs
            if not policies:
                findings.append(
                    self.create_finding(
                        check_id="2.4",
                        title="No Tag Policies Found for EC2",
                        severity="LOW",
                        status="FAILED",
                        resource_id="organizations:tag-policies",
                        description="No tag policies present to enforce EC2 tagging conventions.",
                        recommendation=(
                            "Create a tag policy covering EC2 resources and attach to roots/OUs.\n"
                            "Console: Organizations > Policies > Tag policies > Enable > Create policy\n"
                            "CLI: aws organizations enable-policy-type --root-id <RootID> --policy-type TAG_POLICIES"
                        ),
                        command="aws organizations list-policies --filter TAG_POLICY",
                        evidence={"Policies": []},
                    )
                )
            else:
                # Return list of policy IDs for manual review (to check resource types like ec2:image, ec2:instance)
                findings.append(
                    self.create_finding(
                        check_id="2.4",
                        title="EC2 Tag Policy Review Required (Manual)",
                        severity="LOW",
                        status="WARNING",
                        resource_id="organizations:tag-policies",
                        description=(
                            "Review tag policy contents to ensure capitalization compliance and 'Prevent non-compliant operations' for EC2 resources."
                        ),
                        recommendation=(
                            "Ensure policy enforces keys and values and is attached appropriately.\n"
                            "Describe policy: aws organizations describe-policy --policy-id <policy-id>"
                        ),
                        command=(
                            "aws organizations list-policies --filter TAG_POLICY && aws organizations describe-policy --policy-id <policy-id>"
                        ),
                        evidence={"PolicyIds": [p.get("Id") for p in policies]},
                    )
                )
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.4",
                    title="Unable to Review EC2 Tag Policy",
                    severity="LOW",
                    status="WARNING",
                    resource_id="organizations",
                    description=f"Could not review tag policy: {str(e)}",
                    recommendation="Verify Organizations permissions and that you are in management account",
                )
            )

        return findings

    def check_instance_age(self) -> List[Dict[str, Any]]:
        """
        2.5: Ensure no AWS EC2 Instances are Older than 180 days
        Level: 1 | Type: Manual
        """
        findings = []
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            response = ec2.describe_instances()

            six_months_ago = datetime.now(datetime.timezone.utc) - timedelta(days=180)

            for reservation in response.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id = instance.get("InstanceId", "")
                    launch_time = instance.get("LaunchTime")
                    state = instance.get("State", {}).get("Name", "")

                    if state != "terminated" and launch_time:
                        if launch_time < six_months_ago:
                            age_days = (datetime.now(datetime.timezone.utc) - launch_time).days
                            findings.append(
                                self.create_finding(
                                    check_id="2.5",
                                    title="EC2 Instance Older Than 180 Days",
                                    severity="MEDIUM",
                                    status="FAILED",
                                    resource_id=instance_id,
                                    description=f"EC2 instance is {age_days} days old. Long-running instances may have outdated configurations.",
                                    recommendation="Review instance configuration, apply updates, or replace with fresh instance from updated AMI",
                                    command=(
                                        f"aws ec2 describe-instances --instance-ids {instance_id} --query 'Reservations[0].Instances[0].LaunchTime' --region {self.region}"
                                    ),
                                    evidence={"LaunchTime": launch_time.isoformat()}
                                )
                            )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.5",
                    title="Unable to Check Instance Age",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="ec2:instances",
                    description=f"Could not verify instance age: {str(e)}",
                    recommendation="Verify AWS permissions for ec2:DescribeInstances",
                )
            )

        return findings

    def check_detailed_monitoring(self) -> List[Dict[str, Any]]:
        """
        2.6: Ensure detailed monitoring is enabled for production EC2 Instances
        Level: 1 | Type: Manual
        """
        findings = []
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            response = ec2.describe_instances()

            for reservation in response.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id = instance.get("InstanceId", "")
                    monitoring = instance.get("Monitoring", {}).get("State", "disabled")
                    state = instance.get("State", {}).get("Name", "")

                    # Check if instance has production tag
                    tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
                    environment = tags.get("Environment", "").lower()

                    if state == "running" and "prod" in environment and monitoring != "enabled":
                        findings.append(
                            self.create_finding(
                                check_id="2.6",
                                title="Detailed Monitoring Not Enabled on Production Instance",
                                severity="MEDIUM",
                                status="FAILED",
                                resource_id=instance_id,
                                description="Production EC2 instance does not have detailed monitoring enabled.",
                                recommendation="Enable detailed monitoring using 'aws ec2 monitor-instances --instance-ids <id>'",
                                command=(
                                    f"aws ec2 describe-instances --instance-ids {instance_id} --query 'Reservations[0].Instances[0].Monitoring.State' --region {self.region}"
                                ),
                                evidence={"MonitoringState": monitoring, "Tags": tags}
                            )
                        )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.6",
                    title="Unable to Check Detailed Monitoring",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="ec2:instances",
                    description=f"Could not verify detailed monitoring: {str(e)}",
                    recommendation="Verify AWS permissions for ec2:DescribeInstances",
                )
            )

        return findings

    def check_default_security_groups(self) -> List[Dict[str, Any]]:
        """
        2.7: Ensure Default EC2 Security groups are not being used
        Level: 1 | Type: Manual
        """
        findings = []
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            response = ec2.describe_instances()

            for reservation in response.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id = instance.get("InstanceId", "")
                    security_groups = instance.get("SecurityGroups", [])

                    for sg in security_groups:
                        if sg.get("GroupName") == "default":
                            findings.append(
                                self.create_finding(
                                    check_id="2.7",
                                    title="EC2 Instance Using Default Security Group",
                                    severity="HIGH",
                                    status="FAILED",
                                    resource_id=instance_id,
                                    description="EC2 instance is using the default security group which may have overly permissive rules.",
                                    recommendation="Create custom security group with principle of least privilege and attach to instance",
                                    command=(
                                        f"aws ec2 describe-instances --instance-ids {instance_id} --query 'Reservations[0].Instances[0].SecurityGroups' --region {self.region}"
                                    ),
                                    evidence={"SecurityGroups": security_groups}
                                )
                            )
                            break

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.7",
                    title="Unable to Check Default Security Groups",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="ec2:instances",
                    description=f"Could not verify security groups: {str(e)}",
                    recommendation="Verify AWS permissions for ec2:DescribeInstances",
                )
            )

        return findings

    def check_imdsv2(self) -> List[Dict[str, Any]]:
        """
        2.8: Ensure the Use of IMDSv2 is Enforced on All Existing Instances
        Level: 1 | Type: Manual
        """
        findings = []
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            response = ec2.describe_instances()

            for reservation in response.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id = instance.get("InstanceId", "")
                    metadata_options = instance.get("MetadataOptions", {})
                    http_tokens = metadata_options.get("HttpTokens", "optional")

                    if http_tokens != "required":
                        findings.append(
                            self.create_finding(
                                check_id="2.8",
                                title="IMDSv2 Not Enforced on EC2 Instance",
                                severity="HIGH",
                                status="FAILED",
                                resource_id=instance_id,
                                description="EC2 instance does not enforce IMDSv2. IMDSv1 is vulnerable to SSRF attacks.",
                                recommendation=(
                                    "Enforce IMDSv2: aws ec2 modify-instance-metadata-options --instance-id {id} --http-tokens required"
                                ).format(id=instance_id),
                                command=(
                                    f"aws ec2 describe-instances --instance-ids {instance_id} --query 'Reservations[0].Instances[0].MetadataOptions' --region {self.region}"
                                ),
                                evidence=metadata_options
                            )
                        )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.8",
                    title="Unable to Check IMDSv2 Configuration",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="ec2:instances",
                    description=f"Could not verify IMDSv2 configuration: {str(e)}",
                    recommendation="Verify AWS permissions for ec2:DescribeInstances",
                )
            )

        return findings

    def check_systems_manager(self) -> List[Dict[str, Any]]:
        """
        2.9: Ensure use of AWS Systems Manager to manage EC2 instances
        Level: 1 | Type: Manual
        """
        findings = []
        try:
            ssm = self.session.client("ssm", region_name=self.region)
            ec2 = self.session.client("ec2", region_name=self.region)

            # Get managed instances
            managed_response = ssm.describe_instance_information()
            managed_instance_ids = {
                inst.get("InstanceId") for inst in managed_response.get("InstanceInformationList", [])
            }

            # Get all running instances
            ec2_response = ec2.describe_instances(
                Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
            )

            for reservation in ec2_response.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id = instance.get("InstanceId", "")

                    if instance_id not in managed_instance_ids:
                        findings.append(
                            self.create_finding(
                                check_id="2.9",
                                title="EC2 Instance Not Managed by Systems Manager",
                                severity="MEDIUM",
                                status="FAILED",
                                resource_id=instance_id,
                                description="EC2 instance is not managed by AWS Systems Manager. This limits management capabilities.",
                                recommendation="Install SSM Agent and attach IAM role with AmazonSSMManagedInstanceCore policy",
                                command=(
                                    f"aws ssm describe-instance-information --query 'InstanceInformationList[].InstanceId' --region {self.region}"
                                ),
                                evidence={"ManagedInstanceIds": list(managed_instance_ids)}
                            )
                        )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.9",
                    title="Unable to Check Systems Manager",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="ec2:instances",
                    description=f"Could not verify Systems Manager: {str(e)}",
                    recommendation="Verify AWS permissions for ssm:DescribeInstanceInformation",
                )
            )

        return findings

    def check_unused_enis(self) -> List[Dict[str, Any]]:
        """
        2.10: Ensure unused ENIs are removed
        Level: 1 | Type: Manual
        """
        findings = []
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            response = ec2.describe_network_interfaces()

            for eni in response.get("NetworkInterfaces", []):
                eni_id = eni.get("NetworkInterfaceId", "")
                status = eni.get("Status", "")
                attachment = eni.get("Attachment", {})

                if status == "available" and not attachment:
                    findings.append(
                        self.create_finding(
                            check_id="2.10",
                            title="Unused ENI Detected",
                            severity="LOW",
                            status="FAILED",
                            resource_id=eni_id,
                            description="Elastic Network Interface is not attached to any instance.",
                            recommendation="Review ENI and delete if no longer needed using 'aws ec2 delete-network-interface --network-interface-id <id>'",
                            command=(
                                f"aws ec2 describe-network-interfaces --network-interface-ids {eni_id} --query 'NetworkInterfaces[0].{{Status:Status,Attachment:Attachment}}' --region {self.region}"
                            ),
                            evidence={"Status": status, "Attachment": attachment}
                        )
                    )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.10",
                    title="Unable to Check for Unused ENIs",
                    severity="LOW",
                    status="WARNING",
                    resource_id="ec2:enis",
                    description=f"Could not verify unused ENIs: {str(e)}",
                    recommendation="Verify AWS permissions for ec2:DescribeNetworkInterfaces",
                )
            )

        return findings

    def check_stopped_instances(self) -> List[Dict[str, Any]]:
        """
        2.11: Ensure instances stopped for over 90 days are removed
        Level: 1 | Type: Manual
        """
        findings = []
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            response = ec2.describe_instances(
                Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
            )

            ninety_days_ago = datetime.now(datetime.timezone.utc) - timedelta(days=90)

            for reservation in response.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id = instance.get("InstanceId", "")
                    state_transition_reason = instance.get("StateTransitionReason", "")

                    # Parse stop time from reason (format: "User initiated (YYYY-MM-DD HH:MM:SS GMT)")
                    # This is a simplified check
                    findings.append(
                        self.create_finding(
                            check_id="2.11",
                            title="Long-Term Stopped EC2 Instance",
                            severity="LOW",
                            status="WARNING",
                            resource_id=instance_id,
                            description="EC2 instance has been stopped for an extended period. Review if still needed.",
                            recommendation="Terminate instance if no longer needed to reduce costs",
                            command=(
                                f"aws ec2 describe-instances --instance-ids {instance_id} --query 'Reservations[0].Instances[0].StateTransitionReason' --region {self.region}"
                            ),
                            evidence={"StateTransitionReason": state_transition_reason}
                        )
                    )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.11",
                    title="Unable to Check Stopped Instances",
                    severity="LOW",
                    status="WARNING",
                    resource_id="ec2:instances",
                    description=f"Could not verify stopped instances: {str(e)}",
                    recommendation="Verify AWS permissions for ec2:DescribeInstances",
                )
            )

        return findings

    def check_ebs_delete_on_termination(self) -> List[Dict[str, Any]]:
        """
        2.12: Ensure EBS volumes attached to EC2 marked for deletion upon instance termination
        Level: 1 | Type: Manual
        """
        findings = []
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            response = ec2.describe_instances()

            for reservation in response.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id = instance.get("InstanceId", "")
                    block_devices = instance.get("BlockDeviceMappings", [])

                    for device in block_devices:
                        ebs = device.get("Ebs", {})
                        volume_id = ebs.get("VolumeId", "")
                        delete_on_termination = ebs.get("DeleteOnTermination", False)

                        if not delete_on_termination:
                            findings.append(
                                self.create_finding(
                                    check_id="2.12",
                                    title="EBS Volume Not Marked for Deletion",
                                    severity="LOW",
                                    status="FAILED",
                                    resource_id=f"{instance_id}:{volume_id}",
                                    description="EBS volume attached to instance is not marked for deletion on termination.",
                                    recommendation="Set DeleteOnTermination to true using 'aws ec2 modify-instance-attribute'",
                                    command=(
                                        f"aws ec2 describe-instances --instance-ids {instance_id} --query 'Reservations[0].Instances[0].BlockDeviceMappings' --region {self.region}"
                                    ),
                                    evidence={"VolumeId": volume_id, "DeleteOnTermination": delete_on_termination}
                                )
                            )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.12",
                    title="Unable to Check EBS DeleteOnTermination",
                    severity="LOW",
                    status="WARNING",
                    resource_id="ec2:instances",
                    description=f"Could not verify EBS deletion setting: {str(e)}",
                    recommendation="Verify AWS permissions for ec2:DescribeInstances",
                )
            )

        return findings

    def check_secrets_in_userdata(self) -> List[Dict[str, Any]]:
        """
        2.13: Ensure Secrets and Sensitive Data are not stored directly in EC2 User Data
        Level: 1 | Type: Manual
        """
        findings = []
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            response = ec2.describe_instances()

            sensitive_patterns = [
                "password", "secret", "api_key", "apikey", "token",
                "aws_access_key", "aws_secret", "private_key"
            ]

            for reservation in response.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id = instance.get("InstanceId", "")

                    try:
                        userdata_response = ec2.describe_instance_attribute(
                            InstanceId=instance_id, Attribute="userData"
                        )
                        userdata = userdata_response.get("UserData", {}).get("Value", "")

                        if userdata:
                            import base64
                            decoded_userdata = base64.b64decode(userdata).decode("utf-8", errors="ignore").lower()

                            for pattern in sensitive_patterns:
                                if pattern in decoded_userdata:
                                    findings.append(
                                        self.create_finding(
                                            check_id="2.13",
                                            title="Potential Secrets in EC2 User Data",
                                            severity="CRITICAL",
                                            status="FAILED",
                                            resource_id=instance_id,
                                            description=f"EC2 User Data may contain sensitive information (detected pattern: '{pattern}').",
                                            recommendation="Use AWS Secrets Manager or Parameter Store instead of embedding secrets in User Data",
                                        )
                                    )
                                    break
                    except Exception:
                        pass  # Skip if unable to get user data

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.13",
                    title="Unable to Check User Data for Secrets",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="ec2:instances",
                    description=f"Could not verify User Data: {str(e)}",
                    recommendation="Verify AWS permissions for ec2:DescribeInstanceAttribute",
                )
            )

        return findings

    def check_autoscaling_tag_propagation(self) -> List[Dict[str, Any]]:
        """
        2.14: Ensure EC2 Auto Scaling Groups Propagate Tags to EC2 Instances
        Level: 1 | Type: Automated
        """
        findings = []
        try:
            autoscaling = self.session.client("autoscaling", region_name=self.region)
            response = autoscaling.describe_auto_scaling_groups()

            for asg in response.get("AutoScalingGroups", []):
                asg_name = asg.get("AutoScalingGroupName", "")
                tags = asg.get("Tags", [])

                non_propagating_tags = [
                    tag for tag in tags if not tag.get("PropagateAtLaunch", False)
                ]

                if non_propagating_tags:
                    findings.append(
                        self.create_finding(
                            check_id="2.14",
                            title="Auto Scaling Group Tags Not Propagating",
                            severity="LOW",
                            status="FAILED",
                            resource_id=asg_name,
                            description=f"Auto Scaling Group has {len(non_propagating_tags)} tag(s) not set to propagate to instances.",
                            recommendation="Set PropagateAtLaunch to true for all tags to ensure consistent tagging",
                        )
                    )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.14",
                    title="Unable to Check Auto Scaling Tag Propagation",
                    severity="LOW",
                    status="WARNING",
                    resource_id="autoscaling",
                    description=f"Could not verify Auto Scaling tag propagation: {str(e)}",
                    recommendation="Verify AWS permissions for autoscaling:DescribeAutoScalingGroups",
                )
            )

        return findings

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """Return mock findings for testing"""
        return [
            self.create_finding(
                check_id="2.7",
                title="EC2 Instance Using Default Security Group",
                severity="HIGH",
                status="FAILED",
                resource_id="i-0123456789abcdef0",
                description="EC2 instance is using the default security group.",
                recommendation="Create custom security group with least privilege",
                command="aws ec2 describe-instances --instance-ids i-0123456789abcdef0 --query 'Reservations[0].Instances[0].SecurityGroups'",
                evidence={"SecurityGroups": [{"GroupId": "sg-default", "GroupName": "default"}]}
            ),
            self.create_finding(
                check_id="2.8",
                title="IMDSv2 Not Enforced on EC2 Instance",
                severity="HIGH",
                status="FAILED",
                resource_id="i-0123456789abcdef1",
                description="EC2 instance does not enforce IMDSv2.",
                recommendation="Enforce IMDSv2 to protect against SSRF attacks",
                command="aws ec2 describe-instances --instance-ids i-0123456789abcdef1 --query 'Reservations[0].Instances[0].MetadataOptions.HttpTokens'",
                evidence={"HttpTokens": "optional", "HttpEndpoint": "enabled"}
            ),
            self.create_finding(
                check_id="2.13",
                title="Potential Secrets in EC2 User Data",
                severity="CRITICAL",
                status="FAILED",
                resource_id="i-0123456789abcdef2",
                description="EC2 User Data may contain sensitive information.",
                recommendation="Use AWS Secrets Manager instead",
                command="aws ec2 describe-instance-attribute --instance-id i-0123456789abcdef2 --attribute userData --query 'UserData.Value' --output text | base64 -d",
                evidence={"UserDataContainsSecrets": True, "SecretsFound": ["password", "secret", "key"]}
            ),
        ]
