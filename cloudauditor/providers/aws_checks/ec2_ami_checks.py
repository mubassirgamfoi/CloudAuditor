"""
CIS AWS Compute Benchmark - EC2 AMI Checks (Section 2.1)
"""

from typing import Dict, Any, List
from datetime import datetime, timedelta
from cloudauditor.providers.aws_checks.base_checker import BaseAWSChecker


class EC2AMIChecker(BaseAWSChecker):
    """Checker for EC2 AMI security configurations"""

    def run_checks(self) -> List[Dict[str, Any]]:
        """Run all EC2 AMI checks"""
        if self.use_mock:
            return self._get_mock_findings()

        findings = []
        try:
            findings.extend(self.check_ami_naming_convention())
            findings.extend(self.check_ami_encryption())
            findings.extend(self.check_approved_amis())
            findings.extend(self.check_ami_age())
            findings.extend(self.check_ami_public_access())
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.1.ERROR",
                    title="Error Running EC2 AMI Checks",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="ec2:amis",
                    description=f"Failed to run EC2 AMI checks: {str(e)}",
                    recommendation="Verify AWS credentials and permissions",
                )
            )

        return findings

    def check_ami_naming_convention(self) -> List[Dict[str, Any]]:
        """
        2.1.1: Ensure Consistent Naming Convention is used for Organizational AMI
        Level: 1 | Type: Manual
        """
        findings = []
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            response = ec2.describe_images(Owners=["self"])

            naming_pattern = r"^[a-z]+-[a-z]+-v\d+\.\d+\.\d+$"  # Example: app-prod-v1.0.0
            import re

            for image in response.get("Images", []):
                image_name = image.get("Name", "")
                image_id = image.get("ImageId", "")

                if not re.match(naming_pattern, image_name):
                    findings.append(
                        self.create_finding(
                            check_id="2.1.1",
                            title="AMI Naming Convention Not Followed",
                            severity="LOW",
                            status="FAILED",
                            resource_id=image_id,
                            description=f"AMI '{image_name}' does not follow organizational naming convention.",
                            recommendation="Rename AMI to follow standard naming convention (e.g., app-env-vX.Y.Z)",
                            command=(
                                f"aws ec2 describe-images --image-ids {image_id} --query 'Images[0].Name' --region {self.region}"
                            ),
                            evidence={"Name": image_name}
                        )
                    )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.1.1",
                    title="Unable to Check AMI Naming Convention",
                    severity="LOW",
                    status="WARNING",
                    resource_id="ec2:amis",
                    description=f"Could not verify AMI naming convention: {str(e)}",
                    recommendation="Verify AWS permissions for ec2:DescribeImages",
                )
            )

        return findings

    def check_ami_encryption(self) -> List[Dict[str, Any]]:
        """
        2.1.2: Ensure Amazon Machine Images (AMIs) are encrypted
        Level: 1 | Type: Automated
        """
        findings = []
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            response = ec2.describe_images(
                Owners=["self"],
                Filters=[{"Name": "block-device-mapping.encrypted", "Values": ["false"]}],
            )

            for image in response.get("Images", []):
                image_id = image.get("ImageId", "")
                image_name = image.get("Name", "N/A")

                findings.append(
                    self.create_finding(
                        check_id="2.1.2",
                        title="AMI EBS Snapshots Not Encrypted",
                        severity="HIGH",
                        status="FAILED",
                        resource_id=image_id,
                        description=f"AMI '{image_name}' has unencrypted EBS snapshots. Data at rest is not encrypted.",
                        recommendation="Copy AMI with encryption enabled using 'aws ec2 copy-image --encrypted'",
                    )
                )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.1.2",
                    title="Unable to Check AMI Encryption",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="ec2:amis",
                    description=f"Could not verify AMI encryption: {str(e)}",
                    recommendation="Verify AWS permissions for ec2:DescribeImages",
                )
            )

        return findings

    def check_approved_amis(self) -> List[Dict[str, Any]]:
        """
        2.1.3: Ensure Only Approved Amazon Machine Images (AMIs) are Used
        Level: 1 | Type: Manual
        """
        findings: List[Dict[str, Any]] = []
        # Manual validation: reviewers should verify usage of approved/golden AMIs via tag or allowlist.
        findings.append(
            self.create_finding(
                check_id="2.1.3",
                title="Approved/Golden AMIs Policy Requires Review (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="ec2:amis",
                description=(
                    "Verify that only approved/golden AMIs are used. Maintain an allowlist (e.g., via tags Approved=true) "
                    "and enforce in pipelines and provisioning."
                ),
                recommendation=(
                    "Document the list of approved AMIs, tag them (Approved=true, Owner=Platform), and enforce via IaC/policies."
                ),
                command=(
                    "aws ec2 describe-images --owners self --filters Name=tag:Approved,Values=true "
                    "--query 'Images[].{ImageId:ImageId,Name:Name,Approved:Tags[?Key==`Approved`].Value|[0]}'"
                ),
                evidence={"ApprovedImages": []}
            )
        )
        return findings

    def check_ami_age(self) -> List[Dict[str, Any]]:
        """
        2.1.4: Ensure Images (AMI) are not older than 90 days
        Level: 1 | Type: Automated
        """
        findings = []
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            response = ec2.describe_images(Owners=["self"])

            ninety_days_ago = datetime.now() - timedelta(days=90)

            for image in response.get("Images", []):
                image_id = image.get("ImageId", "")
                image_name = image.get("Name", "N/A")
                creation_date_str = image.get("CreationDate", "")

                if creation_date_str:
                    # Parse creation date (format: 2023-01-15T10:30:00.000Z)
                    creation_date = datetime.strptime(
                        creation_date_str.split(".")[0], "%Y-%m-%dT%H:%M:%S"
                    )

                    if creation_date < ninety_days_ago:
                        age_days = (datetime.now() - creation_date).days
                        findings.append(
                            self.create_finding(
                                check_id="2.1.4",
                                title="AMI Older Than 90 Days",
                                severity="MEDIUM",
                                status="FAILED",
                                resource_id=image_id,
                                description=f"AMI '{image_name}' is {age_days} days old. Outdated AMIs may lack security patches.",
                                recommendation="Create new AMI from updated instance and deregister old AMI",
                            )
                        )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.1.4",
                    title="Unable to Check AMI Age",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="ec2:amis",
                    description=f"Could not verify AMI age: {str(e)}",
                    recommendation="Verify AWS permissions for ec2:DescribeImages",
                )
            )

        return findings

    def check_ami_public_access(self) -> List[Dict[str, Any]]:
        """
        2.1.5: Ensure Images are not Publicly Available
        Level: 1 | Type: Manual
        """
        findings = []
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            response = ec2.describe_images(Owners=["self"])

            for image in response.get("Images", []):
                image_id = image.get("ImageId", "")
                image_name = image.get("Name", "N/A")
                is_public = image.get("Public", False)

                if is_public:
                    findings.append(
                        self.create_finding(
                            check_id="2.1.5",
                            title="AMI is Publicly Accessible",
                            severity="CRITICAL",
                            status="FAILED",
                            resource_id=image_id,
                            description=f"AMI '{image_name}' is publicly accessible. This may expose organizational data.",
                            recommendation="Make AMI private using 'aws ec2 modify-image-attribute --image-id <id> --launch-permission Remove=[{Group=all}]'",
                            command=(
                                f"aws ec2 describe-images --image-ids {image_id} --query 'Images[0].Public' --region {self.region}"
                            ),
                            evidence={"Public": True, "Name": image_name}
                        )
                    )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.1.5",
                    title="Unable to Check AMI Public Access",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="ec2:amis",
                    description=f"Could not verify AMI public access: {str(e)}",
                    recommendation="Verify AWS permissions for ec2:DescribeImages",
                )
            )

        return findings

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """Return mock findings for testing"""
        return [
            self.create_finding(
                check_id="2.1.2",
                title="AMI EBS Snapshots Not Encrypted",
                severity="HIGH",
                status="FAILED",
                resource_id="ami-0123456789abcdef0",
                description="AMI 'web-app-v1.0' has unencrypted EBS snapshots. Data at rest is not encrypted.",
                recommendation="Copy AMI with encryption enabled using 'aws ec2 copy-image --encrypted'",
                command="aws ec2 describe-images --image-ids ami-0123456789abcdef0 --query 'Images[0].BlockDeviceMappings[0].Ebs.Encrypted'",
                evidence={"Encrypted": False, "SnapshotId": "snap-0123456789abcdef0", "VolumeSize": 8}
            ),
            self.create_finding(
                check_id="2.1.4",
                title="AMI Older Than 90 Days",
                severity="MEDIUM",
                status="FAILED",
                resource_id="ami-0123456789abcdef1",
                description="AMI 'api-backend-v2.0' is 145 days old. Outdated AMIs may lack security patches.",
                recommendation="Create new AMI from updated instance and deregister old AMI",
                command="aws ec2 describe-images --image-ids ami-0123456789abcdef1 --query 'Images[0].CreationDate'",
                evidence={"CreationDate": "2024-06-01T10:30:00.000Z", "DaysOld": 145, "Name": "api-backend-v2.0"}
            ),
            self.create_finding(
                check_id="2.1.3",
                title="Approved/Golden AMIs Policy Requires Review (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="ec2:amis",
                description="Manual verification that only approved AMIs are used (via tags/allowlist).",
                recommendation="Maintain and enforce an approved AMI allowlist; tag with Approved=true.",
                command=(
                    "aws ec2 describe-images --owners self --filters Name=tag:Approved,Values=true --query 'Images[].ImageId'"
                ),
                evidence={"ApprovedImages": ["ami-0approved123", "ami-0approved456"]}
            ),
        ]
