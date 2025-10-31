"""
CIS AWS Compute Benchmark - EC2 EBS Checks (Section 2.2)
"""

from typing import Dict, Any, List
from cloudauditor.providers.aws_checks.base_checker import BaseAWSChecker


class EC2EBSChecker(BaseAWSChecker):
    """Checker for EC2 EBS security configurations"""

    def run_checks(self) -> List[Dict[str, Any]]:
        """Run all EC2 EBS checks"""
        if self.use_mock:
            return self._get_mock_findings()

        findings = []
        try:
            findings.extend(self.check_ebs_encryption_enabled())
            findings.extend(self.check_ebs_snapshot_public_access())
            findings.extend(self.check_ebs_snapshot_encryption())
            findings.extend(self.check_unused_ebs_volumes())
            findings.extend(self.check_snapshot_sharing_review_manual())
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.2.ERROR",
                    title="Error Running EC2 EBS Checks",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="ec2:ebs",
                    description=f"Failed to run EC2 EBS checks: {str(e)}",
                    recommendation="Verify AWS credentials and permissions",
                )
            )

        return findings

    def check_snapshot_sharing_review_manual(self) -> List[Dict[str, Any]]:
        """
        2.2.M1 (Manual): Review EBS snapshot sharing to external accounts
        Level: 1 | Type: Manual
        """
        findings: List[Dict[str, Any]] = []
        findings.append(
            self.create_finding(
                check_id="2.2.M1",
                title="EBS Snapshot Cross-Account Sharing Review (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id=f"ec2:{self.region}:snapshots",
                description="Verify snapshots are not shared broadly and only with approved external accounts.",
                recommendation="Remove unnecessary createVolume permissions and enforce approvals for sharing.",
                command=(
                    f"aws ec2 describe-snapshots --owner-ids self --region {self.region}; "
                    "aws ec2 describe-snapshot-attribute --snapshot-id <snap-id> --attribute createVolumePermission"
                ),
                evidence={"CreateVolumePermission": [{"UserId": "123456789012"}]}
            )
        )
        return findings

    def check_ebs_encryption_enabled(self) -> List[Dict[str, Any]]:
        """
        2.2.1: Ensure EBS volume encryption is enabled
        Level: 1 | Type: Automated
        """
        findings = []
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            response = ec2.get_ebs_encryption_by_default()

            if not response.get("EbsEncryptionByDefault", False):
                findings.append(
                    self.create_finding(
                        check_id="2.2.1",
                        title="EBS Encryption By Default Not Enabled",
                        severity="HIGH",
                        status="FAILED",
                        resource_id=f"ec2:ebs:encryption:{self.region}",
                        description="EBS encryption by default is not enabled for this region. New volumes will not be automatically encrypted.",
                        recommendation=(
                            "Enable EBS encryption by default and set a default KMS key if required: "
                            f"aws ec2 enable-ebs-encryption-by-default --region {self.region}; "
                            f"aws ec2 modify-ebs-default-kms-key-id --kms-key-id <kms-arn> --region {self.region}"
                        ),
                        command=f"aws ec2 get-ebs-encryption-by-default --region {self.region}",
                        evidence=response
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        check_id="2.2.1",
                        title="EBS Encryption By Default Enabled",
                        severity="INFO",
                        status="PASSED",
                        resource_id=f"ec2:ebs:encryption:{self.region}",
                        description="EBS encryption by default is enabled for this region.",
                        recommendation="Continue monitoring EBS encryption settings",
                    )
                )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.2.1",
                    title="Unable to Check EBS Encryption Setting",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="ec2:ebs",
                    description=f"Could not verify EBS encryption setting: {str(e)}",
                    recommendation="Verify AWS permissions for ec2:GetEbsEncryptionByDefault",
                )
            )

        return findings

    def check_ebs_snapshot_public_access(self) -> List[Dict[str, Any]]:
        """
        2.2.2: Ensure Public Access to EBS Snapshots is Disabled
        Level: 1 | Type: Automated
        """
        findings = []
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            response = ec2.describe_snapshots(OwnerIds=["self"])

            for snapshot in response.get("Snapshots", []):
                snapshot_id = snapshot.get("SnapshotId", "")

                # Check snapshot permissions
                try:
                    perms = ec2.describe_snapshot_attribute(
                        SnapshotId=snapshot_id, Attribute="createVolumePermission"
                    )

                    create_volume_perms = perms.get("CreateVolumePermissions", [])

                    # Check if snapshot is public
                    for perm in create_volume_perms:
                        if perm.get("Group") == "all":
                            findings.append(
                                self.create_finding(
                                    check_id="2.2.2",
                                    title="EBS Snapshot is Publicly Accessible",
                                    severity="CRITICAL",
                                    status="FAILED",
                                    resource_id=snapshot_id,
                                    description="EBS snapshot is publicly accessible. This may expose sensitive data.",
                                    recommendation="Remove public access using 'aws ec2 modify-snapshot-attribute --snapshot-id <id> --create-volume-permission Remove=[{{Group=all}}]'",
                                )
                                )
                except Exception:
                    pass  # Skip if unable to get permissions

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.2.2",
                    title="Unable to Check EBS Snapshot Public Access",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="ec2:snapshots",
                    description=f"Could not verify EBS snapshot public access: {str(e)}",
                    recommendation="Verify AWS permissions for ec2:DescribeSnapshots and ec2:DescribeSnapshotAttribute",
                )
            )

        return findings

    def check_ebs_snapshot_encryption(self) -> List[Dict[str, Any]]:
        """
        2.2.3: Ensure EBS volume snapshots are encrypted
        Level: 1 | Type: Automated
        """
        findings = []
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            response = ec2.describe_snapshots(OwnerIds=["self"])

            for snapshot in response.get("Snapshots", []):
                snapshot_id = snapshot.get("SnapshotId", "")
                encrypted = snapshot.get("Encrypted", False)
                description = snapshot.get("Description", "N/A")

                if not encrypted:
                    findings.append(
                        self.create_finding(
                            check_id="2.2.3",
                            title="EBS Snapshot Not Encrypted",
                            severity="HIGH",
                            status="FAILED",
                            resource_id=snapshot_id,
                            description=f"EBS snapshot '{description}' is not encrypted. Data at rest is not protected.",
                            recommendation="Create new encrypted snapshot from volume and delete unencrypted snapshot",
                        )
                    )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.2.3",
                    title="Unable to Check EBS Snapshot Encryption",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="ec2:snapshots",
                    description=f"Could not verify EBS snapshot encryption: {str(e)}",
                    recommendation="Verify AWS permissions for ec2:DescribeSnapshots",
                )
            )

        return findings

    def check_unused_ebs_volumes(self) -> List[Dict[str, Any]]:
        """
        2.2.4: Ensure unused EBS volumes are removed
        Level: 1 | Type: Manual
        """
        findings = []
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            response = ec2.describe_volumes()

            for volume in response.get("Volumes", []):
                volume_id = volume.get("VolumeId", "")
                state = volume.get("State", "")
                attachments = volume.get("Attachments", [])

                # Check if volume is available (not attached)
                if state == "available" and len(attachments) == 0:
                    findings.append(
                        self.create_finding(
                            check_id="2.2.4",
                            title="Unused EBS Volume Detected",
                            severity="LOW",
                            status="FAILED",
                            resource_id=volume_id,
                            description="EBS volume is not attached to any instance. Unused volumes incur unnecessary costs.",
                            recommendation="Review volume and delete if no longer needed using 'aws ec2 delete-volume --volume-id <id>'",
                            command=(
                                f"aws ec2 describe-volumes --volume-ids {volume_id} --query 'Volumes[0].{{State:State,Attachments:Attachments}}' --region {self.region}"
                            ),
                            evidence={"State": state, "Attachments": attachments}
                        )
                    )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.2.4",
                    title="Unable to Check for Unused EBS Volumes",
                    severity="LOW",
                    status="WARNING",
                    resource_id="ec2:volumes",
                    description=f"Could not verify unused EBS volumes: {str(e)}",
                    recommendation="Verify AWS permissions for ec2:DescribeVolumes",
                )
            )

        return findings

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """Return mock findings for testing"""
        return [
            self.create_finding(
                check_id="2.2.1",
                title="EBS Encryption By Default Not Enabled",
                severity="HIGH",
                status="FAILED",
                resource_id=f"ec2:ebs:encryption:{self.region}",
                description="EBS encryption by default is not enabled for this region.",
                recommendation="Enable EBS encryption by default",
                command="aws ec2 get-ebs-encryption-by-default --region us-east-1",
                evidence={"EbsEncryptionByDefault": False}
            ),
            self.create_finding(
                check_id="2.2.3",
                title="EBS Snapshot Not Encrypted",
                severity="HIGH",
                status="FAILED",
                resource_id="snap-0123456789abcdef0",
                description="EBS snapshot 'prod-db-backup' is not encrypted.",
                recommendation="Create new encrypted snapshot and delete unencrypted snapshot",
                command="aws ec2 describe-snapshots --snapshot-ids snap-0123456789abcdef0 --query 'Snapshots[0].Encrypted'",
                evidence={"Encrypted": False, "SnapshotId": "snap-0123456789abcdef0", "Description": "prod-db-backup"}
            ),
            self.create_finding(
                check_id="2.2.4",
                title="Unused EBS Volume Detected",
                severity="LOW",
                status="FAILED",
                resource_id="vol-0123456789abcdef0",
                description="EBS volume is not attached to any instance.",
                recommendation="Review volume and delete if no longer needed",
                command="aws ec2 describe-volumes --volume-ids vol-0123456789abcdef0 --query 'Volumes[0].Attachments'",
                evidence={"Attachments": [], "State": "available", "VolumeId": "vol-0123456789abcdef0"}
            ),
        ]
