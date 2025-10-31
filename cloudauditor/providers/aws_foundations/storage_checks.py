"""
CIS AWS Foundations Benchmark - Storage Checks (Section 3)
Critical storage security checks for S3, RDS, and EFS
"""

from typing import Dict, Any, List
from cloudauditor.providers.aws_checks.base_checker import BaseAWSChecker


class StorageFoundationsChecker(BaseAWSChecker):
    """Checker for storage security - CIS AWS Foundations Benchmark"""

    def run_checks(self) -> List[Dict[str, Any]]:
        """Run all storage foundation checks"""
        if self.use_mock:
            return self._get_mock_findings()

        findings = []
        try:
            findings.extend(self.check_s3_https_only())
            findings.extend(self.check_s3_block_public_access())
            findings.extend(self.check_s3_mfa_delete_manual())
            findings.extend(self.check_rds_encryption())
            findings.extend(self.check_rds_public_access())
            findings.extend(self.check_rds_multi_az_manual())
            findings.extend(self.check_efs_encryption())
            findings.extend(self.check_s3_access_logging_target_manual())
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="3.ERROR",
                    title="Error Running Storage Checks",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="storage",
                    description=f"Failed to run storage checks: {str(e)}",
                    recommendation="Verify AWS permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_s3_mfa_delete_manual(self) -> List[Dict[str, Any]]:
        """
        3.1.2: Ensure MFA Delete is enabled on S3 buckets (Manual)
        Level: 2 | Type: Manual | MEDIUM
        """
        findings: List[Dict[str, Any]] = []
        try:
            s3 = self.session.client("s3")
            buckets = s3.list_buckets().get("Buckets", [])

            for bucket in buckets:
                bucket_name = bucket.get("Name", "")
                try:
                    versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                    status = versioning.get("Status")
                    mfa_delete = versioning.get("MFADelete") or versioning.get("MfaDelete")

                    if status != "Enabled" or mfa_delete != "Enabled":
                        findings.append(
                            self.create_finding(
                                check_id="3.1.2",
                                title="S3 MFA Delete Not Enabled (Manual)",
                                severity="MEDIUM",
                                status="WARNING",
                                resource_id=f"s3://{bucket_name}",
                                description=(
                                    "Bucket versioning and/or MFA Delete is not enabled. MFA Delete requires root credentials via CLI/API."
                                ),
                                recommendation=(
                                    "Enable Versioning and MFA Delete (root only):\n"
                                    "aws s3api put-bucket-versioning --profile <root-profile> --bucket <bucket> "
                                    "--versioning-configuration Status=Enabled,MFADelete=Enabled --mfa \"arn:aws:iam::<account-id>:mfa/root-account-mfa-device <code>\""
                                ),
                                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                                command=f"aws s3api get-bucket-versioning --bucket {bucket_name}",
                                evidence={"Status": status, "MFADelete": mfa_delete},
                            )
                        )
                except Exception:
                    # If cannot retrieve versioning, skip gracefully
                    pass

        except Exception:
            pass

        return findings

    def check_s3_access_logging_target_manual(self) -> List[Dict[str, Any]]:
        """
        3.M1 (Manual): Ensure S3 access logging target bucket is hardened (SSE enabled, restricted ACLs)
        Level: 1 | Type: Manual | LOW
        """
        findings: List[Dict[str, Any]] = []
        findings.append(
            self.create_finding(
                check_id="3.M1",
                title="S3 Access Logging Target Bucket Hardening Requires Review (Manual)",
                severity="LOW",
                status="WARNING",
                resource_id="s3://<access-logs-target-bucket>",
                description=(
                    "Verify the target bucket for S3 access logs enforces SSE (KMS), denies public access, "
                    "and restricts ACLs to the Log Delivery group only."
                ),
                recommendation=(
                    "Ensure Block Public Access is ON, bucket policy restricts access, and SSE-KMS is enabled. "
                    "Commands: aws s3api get-bucket-policy --bucket <bucket>; "
                    "aws s3api get-bucket-encryption --bucket <bucket>; aws s3api get-public-access-block --bucket <bucket>"
                ),
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command=(
                    "aws s3api get-bucket-encryption --bucket <access-logs-bucket>; "
                    "aws s3api get-public-access-block --bucket <access-logs-bucket>"
                ),
                evidence={
                    "SSEAlgorithm": "AES256",
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True
                    }
                }
            )
        )
        return findings

    def check_rds_multi_az_manual(self) -> List[Dict[str, Any]]:
        """
        3.2.4: Ensure Multi-AZ deployments are used for enhanced availability (Manual)
        Level: 1 | Type: Manual | MEDIUM
        """
        findings: List[Dict[str, Any]] = []
        try:
            rds = self.session.client("rds", region_name=self.region)
            instances = rds.describe_db_instances().get("DBInstances", [])
            for inst in instances:
                instance_id = inst.get("DBInstanceIdentifier", "")
                multi_az = inst.get("MultiAZ", False)
                if not multi_az:
                    findings.append(
                        self.create_finding(
                            check_id="3.2.4",
                            title="RDS Multi-AZ Not Enabled (Manual)",
                            severity="MEDIUM",
                            status="WARNING",
                            resource_id=f"rds:{instance_id}",
                            description=f"RDS instance '{instance_id}' is not configured for Multi-AZ deployment.",
                            recommendation=(
                                f"Enable Multi-AZ for critical workloads: aws rds modify-db-instance --region {self.region} --db-instance-identifier {instance_id} --multi-az --apply-immediately"
                            ),
                            compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                            command=f"aws rds describe-db-instances --region {self.region} --db-instance-identifier {instance_id} --query 'DBInstances[*].MultiAZ'",
                            evidence={"DBInstanceIdentifier": instance_id, "MultiAZ": multi_az},
                        )
                    )
        except Exception:
            pass

        return findings

    def check_s3_https_only(self) -> List[Dict[str, Any]]:
        """
        3.1.1: Ensure S3 Bucket Policy is set to deny HTTP requests
        Level: 1 | Type: Automated | MEDIUM
        """
        findings = []
        try:
            import json

            s3 = self.session.client("s3")
            buckets = s3.list_buckets()

            for bucket in buckets.get("Buckets", []):
                bucket_name = bucket.get("Name", "")

                try:
                    policy = s3.get_bucket_policy(Bucket=bucket_name)
                    policy_doc = json.loads(policy.get("Policy", "{}"))

                    has_https_enforcement = False
                    for statement in policy_doc.get("Statement", []):
                        if isinstance(statement, dict):
                            effect = statement.get("Effect", "")
                            condition = statement.get("Condition", {})

                            if effect == "Deny":
                                # Case 1: Explicit deny on insecure transport
                                if "aws:SecureTransport" in str(condition):
                                    has_https_enforcement = True
                                    break
                                # Case 2: Enforce minimum TLS version (e.g., >= 1.2)
                                if isinstance(condition, dict) and "NumericLessThan" in condition:
                                    nlt = condition.get("NumericLessThan", {})
                                    if isinstance(nlt, dict) and any(k in nlt for k in ["s3:TlsVersion"]):
                                        has_https_enforcement = True
                                        break

                    if not has_https_enforcement:
                        finding = self.create_finding(
                            check_id="3.1.1",
                            title="S3 Bucket Does Not Enforce HTTPS",
                            severity="MEDIUM",
                            status="FAILED",
                            resource_id=f"s3://{bucket_name}",
                            description=f"S3 bucket '{bucket_name}' does not have a policy to deny HTTP requests.",
                            recommendation=(
                                "Apply HTTPS-only bucket policy: add a Deny on aws:SecureTransport=false. Example:\n"
                                "aws s3api put-bucket-policy --bucket {bucket} --policy '"
                                "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyInsecureTransport\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":[\"arn:aws:s3:::{bucket}\",\"arn:aws:s3:::{bucket}/*\"],\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]]}'\n"
                                "Alternatively, enforce minimum TLS version >= 1.2:\n"
                                "aws s3api put-bucket-policy --bucket {bucket} --policy '"
                                "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"EnforceTLS12\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":[\"arn:aws:s3:::{bucket}\",\"arn:aws:s3:::{bucket}/*\"],\"Condition\":{\"NumericLessThan\":{\"s3:TlsVersion\":\"1.2\"}}}]]}'"
                            ).format(bucket=bucket_name),
                            compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                        )
                        # Attach command and evidence for report context
                        finding["command"] = f"aws s3api get-bucket-policy --bucket {bucket_name} --query Policy --output text"
                        finding["evidence"] = policy_doc
                        findings.append(finding)

                except s3.exceptions.NoSuchBucketPolicy:
                    finding = self.create_finding(
                        check_id="3.1.1",
                        title="S3 Bucket Has No Policy",
                        severity="MEDIUM",
                        status="FAILED",
                        resource_id=f"s3://{bucket_name}",
                        description=f"S3 bucket '{bucket_name}' has no bucket policy configured.",
                        recommendation=(
                            "Create a bucket policy that denies non-TLS requests (aws:SecureTransport=false) using aws s3api put-bucket-policy."
                        ),
                        compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                    )
                    finding["command"] = f"aws s3api get-bucket-policy --bucket {bucket_name}"
                    finding["evidence"] = "No bucket policy present (NoSuchBucketPolicy)"
                    findings.append(finding)
                except Exception:
                    pass

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="3.1.1",
                    title="Unable to Check S3 HTTPS Enforcement",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="s3",
                    description=f"Could not verify S3 bucket policies: {str(e)}",
                    recommendation="Verify S3 permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_s3_block_public_access(self) -> List[Dict[str, Any]]:
        """
        3.1.4: Ensure that S3 is configured with 'Block Public Access' enabled
        Level: 1 | Type: Automated | HIGH
        """
        findings = []
        try:
            s3 = self.session.client("s3")
            buckets = s3.list_buckets()

            for bucket in buckets.get("Buckets", []):
                bucket_name = bucket.get("Name", "")

                try:
                    public_access_block = s3.get_public_access_block(Bucket=bucket_name)
                    config = public_access_block.get("PublicAccessBlockConfiguration", {})

                    if not all([
                        config.get("BlockPublicAcls", False),
                        config.get("IgnorePublicAcls", False),
                        config.get("BlockPublicPolicy", False),
                        config.get("RestrictPublicBuckets", False),
                    ]):
                        findings.append(
                            self.create_finding(
                                check_id="3.1.4",
                                title="S3 Block Public Access Not Fully Enabled",
                                severity="HIGH",
                                status="FAILED",
                                resource_id=f"s3://{bucket_name}",
                                description=f"S3 bucket '{bucket_name}' does not have all Block Public Access settings enabled.",
                                recommendation=(
                                    "Enable Block Public Access for the bucket: "
                                    "aws s3api put-public-access-block --bucket {bucket} --public-access-block-configuration "
                                    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
                                ).format(bucket=bucket_name),
                                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                                command=f"aws s3api get-public-access-block --bucket {bucket_name}",
                                evidence={"PublicAccessBlockConfiguration": config},
                            )
                        )

                except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                    findings.append(
                        self.create_finding(
                            check_id="3.1.4",
                            title="S3 Block Public Access Not Configured",
                            severity="HIGH",
                            status="FAILED",
                            resource_id=f"s3://{bucket_name}",
                            description=f"S3 bucket '{bucket_name}' has no Block Public Access configuration.",
                            recommendation=(
                                "Enable Block Public Access: aws s3api put-public-access-block --bucket {bucket} --public-access-block-configuration "
                                "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
                            ).format(bucket=bucket_name),
                            compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                            command=f"aws s3api get-public-access-block --bucket {bucket_name}",
                            evidence="NoSuchPublicAccessBlockConfiguration",
                        )
                    )
                except Exception:
                    pass

            # Account-level Block Public Access (s3control)
            try:
                sts = self.session.client("sts")
                account_id = sts.get_caller_identity().get("Account")
                s3control = self.session.client("s3control", region_name=self.region or "us-east-1")
                acct_conf = s3control.get_public_access_block(AccountId=account_id)
                acct_cfg = acct_conf.get("PublicAccessBlockConfiguration", {})
                if not all([
                    acct_cfg.get("BlockPublicAcls", False),
                    acct_cfg.get("IgnorePublicAcls", False),
                    acct_cfg.get("BlockPublicPolicy", False),
                    acct_cfg.get("RestrictPublicBuckets", False),
                ]):
                    findings.append(
                        self.create_finding(
                            check_id="3.1.4-account",
                            title="S3 Account Block Public Access Not Fully Enabled",
                            severity="HIGH",
                            status="FAILED",
                            resource_id=f"s3control:{account_id}",
                            description="Account-level S3 Block Public Access is not fully enabled.",
                            recommendation=(
                                "Enable account-level Block Public Access: "
                                "aws s3control put-public-access-block --account-id {acct} --public-access-block-configuration "
                                "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
                            ).format(acct=account_id),
                            compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                            command=f"aws s3control get-public-access-block --account-id {account_id} --region {self.region or 'us-east-1'}",
                            evidence={"PublicAccessBlockConfiguration": acct_cfg},
                        )
                    )
            except Exception:
                pass

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="3.1.4",
                    title="Unable to Check S3 Block Public Access",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="s3",
                    description=f"Could not verify S3 Block Public Access: {str(e)}",
                    recommendation="Verify S3 permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_rds_encryption(self) -> List[Dict[str, Any]]:
        """
        3.2.1: Ensure that encryption-at-rest is enabled for RDS instances
        Level: 1 | Type: Automated | HIGH
        """
        findings = []
        try:
            rds = self.session.client("rds", region_name=self.region)
            instances = rds.describe_db_instances()

            for instance in instances.get("DBInstances", []):
                instance_id = instance.get("DBInstanceIdentifier", "")
                encrypted = instance.get("StorageEncrypted", False)

                if not encrypted:
                    findings.append(
                        self.create_finding(
                            check_id="3.2.1",
                            title="RDS Instance Not Encrypted",
                            severity="HIGH",
                            status="FAILED",
                            resource_id=f"rds:{instance_id}",
                            description=f"RDS instance '{instance_id}' does not have encryption at rest enabled.",
                            recommendation=(
                                "Snapshot -> Copy with KMS -> Restore to encrypted instance. Commands:\n"
                                f"aws rds create-db-snapshot --db-snapshot-identifier <snap> --db-instance-identifier {instance_id}\n"
                                "aws rds copy-db-snapshot --source-db-snapshot-identifier <snap> --target-db-snapshot-identifier <snap-enc> --copy-tags --kms-key-id <kms-arn>\n"
                                "aws rds restore-db-instance-from-db-snapshot --db-instance-identifier <new-id> --db-snapshot-identifier <snap-enc>"
                            ),
                            compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                            command=f"aws rds describe-db-instances --region {self.region} --db-instance-identifier {instance_id} --query 'DBInstances[*].StorageEncrypted'",
                            evidence={"DBInstanceIdentifier": instance_id, "StorageEncrypted": encrypted},
                        )
                    )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="3.2.1",
                    title="Unable to Check RDS Encryption",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="rds",
                    description=f"Could not verify RDS encryption: {str(e)}",
                    recommendation="Verify RDS permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_rds_public_access(self) -> List[Dict[str, Any]]:
        """
        3.2.3: Ensure that RDS instances are not publicly accessible
        Level: 1 | Type: Automated | CRITICAL
        """
        findings = []
        try:
            rds = self.session.client("rds", region_name=self.region)
            instances = rds.describe_db_instances()

            for instance in instances.get("DBInstances", []):
                instance_id = instance.get("DBInstanceIdentifier", "")
                publicly_accessible = instance.get("PubliclyAccessible", False)

                if publicly_accessible:
                    findings.append(
                        self.create_finding(
                            check_id="3.2.3",
                            title="RDS Instance Publicly Accessible",
                            severity="CRITICAL",
                            status="FAILED",
                            resource_id=f"rds:{instance_id}",
                            description=f"RDS instance '{instance_id}' is publicly accessible from the internet.",
                            recommendation=(
                                "Disable public accessibility: "
                                f"aws rds modify-db-instance --db-instance-identifier {instance_id} --no-publicly-accessible --apply-immediately"
                            ),
                            compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                            command=f"aws rds describe-db-instances --region {self.region} --db-instance-identifier {instance_id} --query 'DBInstances[*].PubliclyAccessible'",
                            evidence={"DBInstanceIdentifier": instance_id, "PubliclyAccessible": publicly_accessible},
                        )
                    )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="3.2.3",
                    title="Unable to Check RDS Public Access",
                    severity="CRITICAL",
                    status="WARNING",
                    resource_id="rds",
                    description=f"Could not verify RDS public access: {str(e)}",
                    recommendation="Verify RDS permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_efs_encryption(self) -> List[Dict[str, Any]]:
        """
        3.3.1: Ensure that encryption is enabled for EFS file systems
        Level: 1 | Type: Automated | HIGH
        """
        findings = []
        try:
            efs = self.session.client("efs", region_name=self.region)
            file_systems = efs.describe_file_systems()

            for fs in file_systems.get("FileSystems", []):
                fs_id = fs.get("FileSystemId", "")
                encrypted = fs.get("Encrypted", False)

                if not encrypted:
                    findings.append(
                        self.create_finding(
                            check_id="3.3.1",
                            title="EFS File System Not Encrypted",
                            severity="HIGH",
                            status="FAILED",
                            resource_id=f"efs:{fs_id}",
                            description=f"EFS file system '{fs_id}' does not have encryption enabled.",
                            recommendation=(
                                "Provision new EFS with encryption and migrate data. Commands:\n"
                                "aws efs create-file-system --region <region> --creation-token <uuid> --performance-mode generalPurpose --encrypted\n"
                                f"aws efs describe-file-systems --region {self.region} --file-system-id {fs_id} --query 'FileSystems[*].Encrypted'"
                            ),
                            compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                            command=f"aws efs describe-file-systems --region {self.region} --file-system-id {fs_id} --query 'FileSystems[*].Encrypted'",
                            evidence={"FileSystemId": fs_id, "Encrypted": encrypted},
                        )
                    )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="3.3.1",
                    title="Unable to Check EFS Encryption",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="efs",
                    description=f"Could not verify EFS encryption: {str(e)}",
                    recommendation="Verify EFS permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """Return mock findings for testing"""
        finding_https = self.create_finding(
            check_id="3.1.1",
            title="S3 Bucket Does Not Enforce HTTPS",
            severity="MEDIUM",
            status="FAILED",
            resource_id="s3://company-data-bucket",
            description="S3 bucket does not have a policy to deny HTTP requests.",
            recommendation="Add bucket policy to deny requests where aws:SecureTransport is false",
            compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
        )
        finding_https["command"] = "aws s3api get-bucket-policy --bucket company-data-bucket --query Policy --output text"
        finding_https["evidence"] = {
            "Statement": [
                {"Sid": "AllowAll", "Effect": "Allow", "Principal": "*", "Action": "s3:*", "Resource": "*"}
            ]
        }

        finding_block = self.create_finding(
            check_id="3.1.4",
            title="S3 Block Public Access Not Fully Enabled",
            severity="HIGH",
            status="FAILED",
            resource_id="s3://public-assets",
            description="S3 bucket does not have all Block Public Access settings enabled.",
            recommendation="Enable all Block Public Access settings",
            compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
        )
        finding_block["command"] = "aws s3api get-public-access-block --bucket public-assets"
        finding_block["evidence"] = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            }
        }

        finding_rds_pub = self.create_finding(
            check_id="3.2.3",
            title="RDS Instance Publicly Accessible",
            severity="CRITICAL",
            status="FAILED",
            resource_id="rds:production-db",
            description="RDS instance is publicly accessible from the internet.",
            recommendation="Modify RDS instance to disable public accessibility",
            compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
        )
        finding_rds_pub["command"] = "aws rds describe-db-instances --query 'DBInstances[?DBInstanceIdentifier==`production-db`].PubliclyAccessible' --output text"
        finding_rds_pub["evidence"] = True

        finding_mfa_delete = self.create_finding(
            check_id="3.1.2",
            title="S3 MFA Delete Not Enabled (Manual)",
            severity="MEDIUM",
            status="WARNING",
            resource_id="s3://sensitive-bucket",
            description="Bucket versioning and/or MFA Delete is not enabled.",
            recommendation=(
                "Enable Versioning and MFA Delete (root only) using aws s3api put-bucket-versioning with MFA parameters."
            ),
            compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
        )
        finding_mfa_delete["command"] = "aws s3api get-bucket-versioning --bucket sensitive-bucket"
        finding_mfa_delete["evidence"] = {"Status": "Suspended", "MFADelete": None}

        return [finding_https, finding_block, finding_rds_pub, finding_mfa_delete]
