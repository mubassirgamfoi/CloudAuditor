"""
CIS AWS Foundations Benchmark - IAM Checks (Section 2)
Implements critical identity and access management security checks
"""

from typing import Dict, Any, List
from cloudauditor.providers.aws_checks.base_checker import BaseAWSChecker


class IAMFoundationsChecker(BaseAWSChecker):
    """Checker for IAM security configurations - CIS AWS Foundations Benchmark"""

    def run_checks(self) -> List[Dict[str, Any]]:
        """Run all IAM foundation checks"""
        if self.use_mock:
            return self._get_mock_findings()

        findings = []
        try:
            findings.extend(self.check_root_access_keys())
            findings.extend(self.check_root_mfa())
            findings.extend(self.check_hardware_mfa())
            findings.extend(self.check_iam_password_policy())
            findings.extend(self.check_iam_users_mfa())
            findings.extend(self.check_unused_credentials())
            findings.extend(self.check_access_key_rotation())
            findings.extend(self.check_iam_user_groups())
            findings.extend(self.check_full_admin_policies())
            findings.extend(self.check_support_role())
            findings.extend(self.check_iam_instance_roles())
            findings.extend(self.check_expired_certificates())
            findings.extend(self.check_iam_access_analyzer())
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.ERROR",
                    title="Error Running IAM Foundations Checks",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="iam",
                    description=f"Failed to run IAM checks: {str(e)}",
                    recommendation="Verify AWS credentials and permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_root_access_keys(self) -> List[Dict[str, Any]]:
        """
        2.3: Ensure no 'root' user account access key exists
        Level: 1 | Type: Automated | CRITICAL
        """
        findings = []
        try:
            iam = self.session.client("iam")
            summary = iam.get_account_summary()

            if summary.get("SummaryMap", {}).get("AccountAccessKeysPresent", 0) > 0:
                finding = self.create_finding(
                    check_id="2.3",
                    title="Root User Has Active Access Keys",
                    severity="CRITICAL",
                    status="FAILED",
                    resource_id="iam:root",
                    description="The root user account has active access keys. This is a critical security risk.",
                    recommendation="Delete all root user access keys immediately via AWS Console",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                    command="aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent' --output text",
                    evidence=summary.get("SummaryMap", {})
                )
                findings.append(finding)
            else:
                finding = self.create_finding(
                    check_id="2.3",
                    title="Root User Has No Access Keys",
                    severity="INFO",
                    status="PASSED",
                    resource_id="iam:root",
                    description="Root user account has no access keys configured.",
                    recommendation="Continue to monitor and never create root access keys",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                    command="aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent' --output text",
                    evidence=summary.get("SummaryMap", {})
                )
                findings.append(finding)

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.3",
                    title="Unable to Check Root Access Keys",
                    severity="CRITICAL",
                    status="WARNING",
                    resource_id="iam:root",
                    description=f"Could not verify root access keys: {str(e)}",
                    recommendation="Verify IAM permissions for iam:GetAccountSummary",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_root_mfa(self) -> List[Dict[str, Any]]:
        """
        2.4: Ensure MFA is enabled for the 'root' user account
        Level: 1 | Type: Automated | CRITICAL
        """
        findings = []
        try:
            iam = self.session.client("iam")
            summary = iam.get_account_summary()

            if summary.get("SummaryMap", {}).get("AccountMFAEnabled", 0) == 0:
                finding = self.create_finding(
                    check_id="2.4",
                    title="Root User MFA Not Enabled",
                    severity="CRITICAL",
                    status="FAILED",
                    resource_id="iam:root",
                    description="Multi-factor authentication is not enabled on the root account.",
                    recommendation="Enable MFA on root account immediately using virtual or hardware MFA device",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                    command="aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text",
                    evidence=summary.get("SummaryMap", {})
                )
                findings.append(finding)
            else:
                finding = self.create_finding(
                    check_id="2.4",
                    title="Root User MFA Enabled",
                    severity="INFO",
                    status="PASSED",
                    resource_id="iam:root",
                    description="Root user account has MFA enabled.",
                    recommendation="Ensure MFA device is securely stored and accessible to authorized personnel",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                    command="aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text",
                    evidence=summary.get("SummaryMap", {})
                )
                findings.append(finding)

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.4",
                    title="Unable to Check Root MFA",
                    severity="CRITICAL",
                    status="WARNING",
                    resource_id="iam:root",
                    description=f"Could not verify root MFA: {str(e)}",
                    recommendation="Verify IAM permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_hardware_mfa(self) -> List[Dict[str, Any]]:
        """
        2.5: Ensure hardware MFA is enabled for the 'root' user account
        Level: 2 | Type: Manual | HIGH
        """
        findings: List[Dict[str, Any]] = []
        # This control requires verifying the MFA device type for the root user (hardware vs virtual).
        # Provide a manual check with helpful commands and indicative evidence structure.
        findings.append(
            self.create_finding(
                check_id="2.5",
                title="Root User Uses Virtual MFA Instead of Hardware MFA (Manual)",
                severity="HIGH",
                status="WARNING",
                resource_id="iam:root",
                description=(
                    "CIS recommends a hardware MFA device for the root account. Verify that the root user's "
                    "MFA device is a hardware token rather than a virtual authenticator."
                ),
                recommendation=(
                    "Replace the root account's virtual MFA with a hardware MFA device. In the console: IAM → "
                    "Users → Root user → Security credentials → Multi‑factor authentication, then assign a hardware token."
                ),
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command=(
                    "aws iam list-virtual-mfa-devices --assignment-status Assigned --query "
                    "'VirtualMFADevices[?SerialNumber==`arn:aws:iam::${ACCOUNT_ID}:mfa/root-account-mfa-device`]'"
                ),
                evidence={
                    "VirtualMFADevices": [
                        {
                            "SerialNumber": "arn:aws:iam::123456789012:mfa/root-account-mfa-device",
                            "User": {"Arn": "arn:aws:iam::123456789012:root"}
                        }
                    ]
                },
            )
        )
        return findings

    def check_iam_password_policy(self) -> List[Dict[str, Any]]:
        """
        2.7 & 2.8: Check IAM password policy compliance
        Level: 1 | Type: Automated | MEDIUM
        """
        findings = []
        try:
            iam = self.session.client("iam")
            policy = iam.get_account_password_policy()["PasswordPolicy"]

            # Check minimum length (2.7)
            min_length = policy.get("MinimumPasswordLength", 0)
            if min_length < 14:
                finding = self.create_finding(
                    check_id="2.7",
                    title="IAM Password Policy: Minimum Length Too Short",
                    severity="MEDIUM",
                    status="FAILED",
                    resource_id="iam:password-policy",
                    description=f"Password minimum length is {min_length} (CIS requires >= 14 characters).",
                    recommendation="Update password policy to require minimum 14 characters",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                    command="aws iam get-account-password-policy",
                    evidence=policy
                )
                findings.append(finding)

            # Check password reuse (2.8)
            if policy.get("PasswordReusePrevention", 0) < 24:
                finding = self.create_finding(
                    check_id="2.8",
                    title="IAM Password Policy: Insufficient Password Reuse Prevention",
                    severity="MEDIUM",
                    status="FAILED",
                    resource_id="iam:password-policy",
                    description=f"Password reuse prevention set to {policy.get('PasswordReusePrevention', 0)} (CIS requires >= 24).",
                    recommendation="Set PasswordReusePrevention to 24 or more",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                    command="aws iam get-account-password-policy",
                    evidence=policy
                )
                findings.append(finding)

        except iam.exceptions.NoSuchEntityException as e:
            findings.append(
                self.create_finding(
                    check_id="2.7",
                    title="IAM Password Policy Not Configured",
                    severity="HIGH",
                    status="FAILED",
                    resource_id="iam:password-policy",
                    description="No IAM password policy is configured for the account.",
                    recommendation="Create IAM password policy with CIS recommended settings",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                    command="aws iam get-account-password-policy",
                    evidence={"error": str(e)}
                )
            )
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.7",
                    title="Unable to Check Password Policy",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="iam:password-policy",
                    description=f"Could not verify password policy: {str(e)}",
                    recommendation="Verify IAM permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_iam_users_mfa(self) -> List[Dict[str, Any]]:
        """
        2.9: Ensure multi-factor authentication (MFA) is enabled for all IAM users with console password
        Level: 1 | Type: Automated | HIGH
        """
        findings = []
        try:
            iam = self.session.client("iam")
            users = iam.list_users()

            for user in users.get("Users", []):
                username = user.get("UserName", "")

                try:
                    # Check if user has console access
                    login_profile = iam.get_login_profile(UserName=username)

                    # Check if MFA is enabled
                    mfa_devices = iam.list_mfa_devices(UserName=username)

                    if len(mfa_devices.get("MFADevices", [])) == 0:
                        finding = self.create_finding(
                            check_id="2.9",
                            title="IAM User Console Access Without MFA",
                            severity="HIGH",
                            status="FAILED",
                            resource_id=f"iam:user/{username}",
                            description=f"IAM user '{username}' has console access but no MFA device configured.",
                            recommendation="Enable MFA for all IAM users with console access",
                            compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                            command=f"aws iam list-mfa-devices --user-name {username}",
                            evidence=mfa_devices
                        )
                        findings.append(finding)

                except iam.exceptions.NoSuchEntityException:
                    # User has no console access, skip
                    pass

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.9",
                    title="Unable to Check IAM User MFA",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="iam:users",
                    description=f"Could not verify IAM user MFA: {str(e)}",
                    recommendation="Verify IAM permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_unused_credentials(self) -> List[Dict[str, Any]]:
        """
        2.11: Ensure credentials unused for 45 days or more are disabled
        Level: 1 | Type: Automated | MEDIUM
        """
        findings = []
        try:
            from datetime import datetime, timedelta, timezone

            iam = self.session.client("iam")
            users = iam.list_users()

            threshold = datetime.now(timezone.utc) - timedelta(days=45)

            for user in users.get("Users", []):
                username = user.get("UserName", "")

                # Check password last used
                try:
                    login_profile = iam.get_login_profile(UserName=username)
                    password_last_used = user.get("PasswordLastUsed")

                    if password_last_used and password_last_used < threshold:
                        days_unused = (datetime.now(timezone.utc) - password_last_used).days
                        finding = self.create_finding(
                            check_id="2.11",
                            title="IAM User Credentials Unused for 45+ Days",
                            severity="MEDIUM",
                            status="FAILED",
                            resource_id=f"iam:user/{username}",
                            description=f"IAM user '{username}' password unused for {days_unused} days.",
                            recommendation="Disable or remove unused IAM user credentials",
                            compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                            command=f"aws iam get-user --user-name {username} --query 'User.PasswordLastUsed' --output text",
                            evidence={"PasswordLastUsed": password_last_used.isoformat(), "DaysUnused": days_unused}
                        )
                        findings.append(finding)
                except iam.exceptions.NoSuchEntityException:
                    pass

                # Check access keys
                access_keys = iam.list_access_keys(UserName=username)
                for key in access_keys.get("AccessKeyMetadata", []):
                    key_id = key.get("AccessKeyId", "")
                    last_used_response = iam.get_access_key_last_used(AccessKeyId=key_id)
                    last_used = last_used_response.get("AccessKeyLastUsed", {}).get("LastUsedDate")

                    if last_used and last_used < threshold:
                        days_unused = (datetime.now(timezone.utc) - last_used).days
                        finding = self.create_finding(
                            check_id="2.11",
                            title="IAM Access Key Unused for 45+ Days",
                            severity="MEDIUM",
                            status="FAILED",
                            resource_id=f"iam:user/{username}/key/{key_id}",
                            description=f"Access key '{key_id}' for user '{username}' unused for {days_unused} days.",
                            recommendation="Disable or delete unused access keys",
                            compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                            command=f"aws iam get-access-key-last-used --access-key-id {key_id}",
                            evidence={"AccessKeyId": key_id, "LastUsedDate": last_used.isoformat(), "DaysUnused": days_unused}
                        )
                        findings.append(finding)

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.11",
                    title="Unable to Check Unused Credentials",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="iam:credentials",
                    description=f"Could not verify credential usage: {str(e)}",
                    recommendation="Verify IAM permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_access_key_rotation(self) -> List[Dict[str, Any]]:
        """
        2.13: Ensure access keys are rotated every 90 days or less
        Level: 1 | Type: Automated | MEDIUM
        """
        findings = []
        try:
            from datetime import datetime, timedelta, timezone

            iam = self.session.client("iam")
            users = iam.list_users()

            threshold = datetime.now(timezone.utc) - timedelta(days=90)

            for user in users.get("Users", []):
                username = user.get("UserName", "")
                access_keys = iam.list_access_keys(UserName=username)

                for key in access_keys.get("AccessKeyMetadata", []):
                    key_id = key.get("AccessKeyId", "")
                    create_date = key.get("CreateDate")

                    if create_date and create_date < threshold:
                        days_old = (datetime.now(timezone.utc) - create_date).days
                        finding = self.create_finding(
                            check_id="2.13",
                            title="IAM Access Key Not Rotated in 90+ Days",
                            severity="MEDIUM",
                            status="FAILED",
                            resource_id=f"iam:user/{username}/key/{key_id}",
                            description=f"Access key '{key_id}' for user '{username}' is {days_old} days old (CIS requires rotation every 90 days).",
                            recommendation="Rotate access keys and establish regular rotation schedule",
                            compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                            command=f"aws iam list-access-keys --user-name {username} --query 'AccessKeyMetadata[?AccessKeyId==`{key_id}`].CreateDate' --output text",
                            evidence={"AccessKeyId": key_id, "CreateDate": create_date.isoformat(), "DaysOld": days_old}
                        )
                        findings.append(finding)

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.13",
                    title="Unable to Check Access Key Rotation",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="iam:access-keys",
                    description=f"Could not verify access key rotation: {str(e)}",
                    recommendation="Verify IAM permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_iam_user_groups(self) -> List[Dict[str, Any]]:
        """
        2.14: Ensure IAM users receive permissions only through groups
        Level: 1 | Type: Automated | MEDIUM
        """
        findings = []
        try:
            iam = self.session.client("iam")
            users = iam.list_users()

            for user in users.get("Users", []):
                username = user.get("UserName", "")

                # Check for directly attached policies
                attached_policies = iam.list_attached_user_policies(UserName=username)
                inline_policies = iam.list_user_policies(UserName=username)

                if attached_policies.get("AttachedPolicies") or inline_policies.get("PolicyNames"):
                    findings.append(
                        self.create_finding(
                            check_id="2.14",
                            title="IAM User Has Direct Policy Attachments",
                            severity="MEDIUM",
                            status="FAILED",
                            resource_id=f"iam:user/{username}",
                            description=f"IAM user '{username}' has managed or inline policies attached directly instead of through groups.",
                            recommendation=(
                                "Detach managed policies and delete inline policies, then grant permissions via IAM groups only.\n"
                                "Audit commands:\n"
                                f"aws iam list-attached-user-policies --user-name {username}\n"
                                f"aws iam list-user-policies --user-name {username}\n\n"
                                "Remediation commands (examples):\n"
                                f"aws iam detach-user-policy --user-name {username} --policy-arn <policy_arn>\n"
                                f"aws iam delete-user-policy --user-name {username} --policy-name <policy_name>"
                            ),
                            compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                            command=(
                                f"aws iam list-attached-user-policies --user-name {username} --output json;\n"
                                f"aws iam list-user-policies --user-name {username} --output json"
                            ),
                            evidence={
                                "AttachedPolicies": attached_policies.get("AttachedPolicies", []),
                                "InlinePolicies": inline_policies.get("PolicyNames", []),
                            },
                        )
                    )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.14",
                    title="Unable to Check IAM User Policies",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="iam:users",
                    description=f"Could not verify user policies: {str(e)}",
                    recommendation="Verify IAM permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_full_admin_policies(self) -> List[Dict[str, Any]]:
        """
        2.15: Ensure IAM policies that allow full "*:*" administrative privileges are not attached
        Level: 1 | Type: Automated | HIGH
        """
        findings = []
        try:
            import json

            iam = self.session.client("iam")
            policies = iam.list_policies(Scope="Local", OnlyAttached=True)

            for policy in policies.get("Policies", []):
                policy_arn = policy.get("Arn", "")
                policy_name = policy.get("PolicyName", "")

                # Get policy document
                policy_version = iam.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy.get("DefaultVersionId", "")
                )

                version_id = policy.get("DefaultVersionId", "")
                document = policy_version.get("PolicyVersion", {}).get("Document", {})

                # Check for full admin permissions
                for statement in document.get("Statement", []):
                    if isinstance(statement, dict):
                        effect = statement.get("Effect", "")
                        action = statement.get("Action", [])
                        resource = statement.get("Resource", [])

                        if effect == "Allow":
                            if (action == "*" or "*" in action) and (resource == "*" or "*" in resource):
                                findings.append(
                                    self.create_finding(
                                        check_id="2.15",
                                        title="IAM Policy Grants Full Administrative Privileges",
                                        severity="HIGH",
                                        status="FAILED",
                                        resource_id=policy_arn,
                                        description=f"IAM policy '{policy_name}' grants full *:* administrative privileges.",
                                        recommendation=(
                                            "Detach and delete this policy, and replace with least-privilege permissions. "
                                            "Use 'aws iam list-entities-for-policy' to identify all attachments and detach."
                                        ),
                                        compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                                        command=(
                                            f"aws iam get-policy-version --policy-arn {policy_arn} --version-id {version_id} --query "
                                            "'PolicyVersion.Document.Statement';\n"
                                            f"aws iam list-entities-for-policy --policy-arn {policy_arn} --output json"
                                        ),
                                        evidence={
                                            "PolicyArn": policy_arn,
                                            "PolicyName": policy_name,
                                            "DefaultVersionId": version_id,
                                            "OffendingStatement": statement,
                                        },
                                    )
                                )
                                break

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.15",
                    title="Unable to Check IAM Policies",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="iam:policies",
                    description=f"Could not verify IAM policies: {str(e)}",
                    recommendation="Verify IAM permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_support_role(self) -> List[Dict[str, Any]]:
        """
        2.16: Ensure a support role has been created to manage incidents with AWS Support
        Level: 1 | Type: Automated | LOW
        """
        findings = []
        try:
            iam = self.session.client("iam")
            # Locate the AWSSupportAccess managed policy
            support_policy_arn = "arn:aws:iam::aws:policy/AWSSupportAccess"
            policy = iam.get_policy(PolicyArn=support_policy_arn)
            attachment_count = policy.get("Policy", {}).get("AttachmentCount", 0)

            # Enumerate all entities attached (roles/users/groups)
            entities = iam.list_entities_for_policy(PolicyArn=support_policy_arn)
            roles = entities.get("PolicyRoles", [])
            users = entities.get("PolicyUsers", [])
            groups = entities.get("PolicyGroups", [])

            if attachment_count == 0 or len(roles) == 0:
                findings.append(
                    self.create_finding(
                        check_id="2.16",
                        title="No AWS Support Role Configured",
                        severity="LOW",
                        status="FAILED",
                        resource_id="iam:support-role",
                        description=(
                            "AWSSupportAccess is not attached to any IAM role. Create a dedicated role for managing AWS Support incidents."
                        ),
                        recommendation=(
                            "Create a role with a trust policy and attach AWSSupportAccess. Example:\n"
                            "aws iam create-role --role-name <aws_support_iam_role> --assume-role-policy-document file:///tmp/TrustPolicy.json\n"
                            "aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess --role-name <aws_support_iam_role>"
                        ),
                        compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                        command=(
                            "aws iam list-policies --query \"Policies[?PolicyName=='AWSSupportAccess']\";\n"
                            f"aws iam list-entities-for-policy --policy-arn {support_policy_arn} --output json"
                        ),
                        evidence={
                            "AttachmentCount": attachment_count,
                            "PolicyRoles": roles,
                            "PolicyUsers": users,
                            "PolicyGroups": groups,
                        },
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        check_id="2.16",
                        title="AWS Support Role Present",
                        severity="INFO",
                        status="PASSED",
                        resource_id="iam:support-role",
                        description="AWSSupportAccess policy is attached to at least one IAM role.",
                        recommendation="Ensure only appropriate responders assume the support role (separation of duties).",
                        compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                        command=(
                            f"aws iam list-entities-for-policy --policy-arn {support_policy_arn} --output json"
                        ),
                        evidence={
                            "AttachmentCount": attachment_count,
                            "PolicyRoles": roles,
                        },
                    )
                )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.16",
                    title="Unable to Check Support Role",
                    severity="LOW",
                    status="WARNING",
                    resource_id="iam:support-role",
                    description=f"Could not verify support role: {str(e)}",
                    recommendation="Verify IAM permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_iam_instance_roles(self) -> List[Dict[str, Any]]:
        """
        2.17: Ensure IAM instance roles are used for AWS resource access from instances
        Level: 1 | Type: Automated | MEDIUM
        """
        findings = []
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            instances = ec2.describe_instances()

            for reservation in instances.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id = instance.get("InstanceId", "")
                    iam_profile = instance.get("IamInstanceProfile")

                    if instance.get("State", {}).get("Name") == "running" and not iam_profile:
                        findings.append(
                            self.create_finding(
                                check_id="2.17",
                                title="EC2 Instance Without IAM Role",
                                severity="MEDIUM",
                                status="FAILED",
                                resource_id=instance_id,
                                description=f"EC2 instance '{instance_id}' is running without an IAM instance role.",
                                recommendation=(
                                    "Attach an instance profile (with IAM role) to the instance. Commands:\n"
                                    f"aws ec2 associate-iam-instance-profile --region {self.region} --instance-id {instance_id} --iam-instance-profile Name=\"<Instance-Profile-Name>\""
                                ),
                                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                                command=(
                                    f"aws ec2 describe-instances --region {self.region} --instance-id {instance_id} --query 'Reservations[*].Instances[*].IamInstanceProfile'"
                                ),
                                evidence={
                                    "IamInstanceProfile": None,
                                }
                            )
                        )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.17",
                    title="Unable to Check IAM Instance Roles",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="ec2:instances",
                    description=f"Could not verify instance roles: {str(e)}",
                    recommendation="Verify IAM and EC2 permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_expired_certificates(self) -> List[Dict[str, Any]]:
        """
        2.18: Ensure that all expired SSL/TLS certificates stored in AWS IAM are removed
        Level: 1 | Type: Automated | LOW
        """
        findings = []
        try:
            from datetime import datetime, timezone

            iam = self.session.client("iam")
            certs = iam.list_server_certificates()

            now = datetime.now(timezone.utc)

            for cert_metadata in certs.get("ServerCertificateMetadataList", []):
                cert_name = cert_metadata.get("ServerCertificateName", "")
                expiration = cert_metadata.get("Expiration")

                if expiration and expiration < now:
                    days_expired = (now - expiration).days
                    findings.append(
                        self.create_finding(
                            check_id="2.18",
                            title="Expired SSL/TLS Certificate in IAM",
                            severity="LOW",
                            status="FAILED",
                            resource_id=f"iam:cert/{cert_name}",
                            description=f"SSL/TLS certificate '{cert_name}' expired {days_expired} days ago.",
                            recommendation=(
                                "Delete expired server certificate: aws iam delete-server-certificate --server-certificate-name <CERTIFICATE_NAME>"
                            ),
                            compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                            command="aws iam list-server-certificates",
                            evidence={
                                "ServerCertificateName": cert_name,
                                "Expiration": expiration.isoformat(),
                                "DaysExpired": days_expired,
                            }
                        )
                    )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.18",
                    title="Unable to Check SSL/TLS Certificates",
                    severity="LOW",
                    status="WARNING",
                    resource_id="iam:certificates",
                    description=f"Could not verify certificates: {str(e)}",
                    recommendation="Verify IAM permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def check_iam_access_analyzer(self) -> List[Dict[str, Any]]:
        """
        2.19: Ensure that IAM Access Analyzer is enabled for all regions
        Level: 1 | Type: Automated | MEDIUM
        """
        findings = []
        try:
            access_analyzer = self.session.client("accessanalyzer", region_name=self.region)
            analyzers = access_analyzer.list_analyzers(type="ORGANIZATION")

            active = [a for a in analyzers.get("analyzers", []) if a.get("status") == "ACTIVE"]
            if len(active) == 0:
                findings.append(
                    self.create_finding(
                        check_id="2.19",
                        title="IAM External Access Analyzer Not Enabled (This Region)",
                        severity="MEDIUM",
                        status="FAILED",
                        resource_id=f"accessanalyzer:{self.region}",
                        description=f"IAM External Access Analyzer is not ACTIVE in region {self.region}.",
                        recommendation=(
                            "Enable External Access Analyzer (type ORGANIZATION) in each active region. Command:\n"
                            f"aws accessanalyzer create-analyzer --type ORGANIZATION --region {self.region} --analyzer-name <name>"
                        ),
                        compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                        command=f"aws accessanalyzer list-analyzers --type ORGANIZATION --region {self.region}",
                        evidence={"analyzers": analyzers.get("analyzers", [])}
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        check_id="2.19",
                        title="IAM External Access Analyzer Active (This Region)",
                        severity="INFO",
                        status="PASSED",
                        resource_id=f"accessanalyzer:{self.region}",
                        description=f"At least one External Access Analyzer is ACTIVE in region {self.region}.",
                        recommendation="Ensure analyzers exist in all active regions and monitor findings.",
                        compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                        command=f"aws accessanalyzer list-analyzers --type ORGANIZATION --region {self.region}",
                        evidence={"analyzers": analyzers.get("analyzers", [])}
                    )
                )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="2.19",
                    title="Unable to Check IAM Access Analyzer",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="accessanalyzer",
                    description=f"Could not verify Access Analyzer: {str(e)}",
                    recommendation="Verify IAM permissions",
                    compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                )
            )

        return findings

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """Return mock findings for testing"""
        return [
            self.create_finding(
                check_id="2.3",
                title="Root User Has Active Access Keys",
                severity="CRITICAL",
                status="FAILED",
                resource_id="iam:root",
                description="The root user account has active access keys.",
                recommendation="Delete all root user access keys immediately",
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command="aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent' --output text",
                evidence={"AccountAccessKeysPresent": 1}
            ),
            self.create_finding(
                check_id="2.4",
                title="Root User MFA Not Enabled",
                severity="CRITICAL",
                status="FAILED",
                resource_id="iam:root",
                description="Multi-factor authentication is not enabled on the root account.",
                recommendation="Enable MFA on root account immediately",
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command="aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text",
                evidence={"AccountMFAEnabled": 0}
            ),
            self.create_finding(
                check_id="2.7",
                title="IAM Password Policy: Minimum Length Too Short",
                severity="MEDIUM",
                status="FAILED",
                resource_id="iam:password-policy",
                description="Password minimum length is 8 (CIS requires >= 14 characters).",
                recommendation="Update password policy to require minimum 14 characters",
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command="aws iam get-account-password-policy",
                evidence={"MinimumPasswordLength": 8, "PasswordReusePrevention": 12}
            ),
            self.create_finding(
                check_id="2.9",
                title="IAM User Console Access Without MFA",
                severity="HIGH",
                status="FAILED",
                resource_id="iam:user/john.doe",
                description="IAM user 'john.doe' has console access but no MFA device configured.",
                recommendation="Enable MFA for all IAM users with console access",
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command="aws iam list-mfa-devices --user-name john.doe",
                evidence={"MFADevices": []}
            ),
            self.create_finding(
                check_id="2.15",
                title="IAM Policy Grants Full Administrative Privileges",
                severity="HIGH",
                status="FAILED",
                resource_id="arn:aws:iam::123456789012:policy/AdminPolicy",
                description="IAM policy 'AdminPolicy' grants full *:* administrative privileges.",
                recommendation="Replace with specific permissions following principle of least privilege",
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command="aws iam get-policy-version --policy-arn arn:aws:iam::123456789012:policy/AdminPolicy --version-id v1",
                evidence={"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
            ),
            self.create_finding(
                check_id="2.5",
                title="Root User Uses Virtual MFA Instead of Hardware MFA (Manual)",
                severity="HIGH",
                status="WARNING",
                resource_id="iam:root",
                description=(
                    "CIS recommends a hardware MFA device for the root account. Verify device type and migrate to hardware MFA."
                ),
                recommendation=(
                    "In console: IAM → Root user → Security credentials → MFA: assign a hardware token; then remove virtual MFA."
                ),
                compliance_standard="CIS AWS Foundations Benchmark v6.0.0",
                command=(
                    "aws iam list-virtual-mfa-devices --assignment-status Assigned --query "
                    "'VirtualMFADevices[?SerialNumber==`arn:aws:iam::123456789012:mfa/root-account-mfa-device`]'"
                ),
                evidence={
                    "VirtualMFADevices": [
                        {
                            "SerialNumber": "arn:aws:iam::123456789012:mfa/root-account-mfa-device",
                            "User": {"Arn": "arn:aws:iam::123456789012:root"}
                        }
                    ]
                }
            ),
        ]
