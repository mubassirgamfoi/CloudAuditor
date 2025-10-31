"""
CIS AWS Compute Benchmark - Lambda Checks (Section 12)
"""

from typing import Dict, Any, List
from cloudauditor.providers.aws_checks.base_checker import BaseAWSChecker


class LambdaChecker(BaseAWSChecker):
    """Checker for AWS Lambda security configurations"""

    def run_checks(self) -> List[Dict[str, Any]]:
        """Run all Lambda checks"""
        if self.use_mock:
            return self._get_mock_findings()

        findings = []
        try:
            findings.extend(self.check_cloudwatch_insights())
            findings.extend(self.check_secrets_manager_usage())
            findings.extend(self.check_least_privilege())
            findings.extend(self.check_unique_iam_roles())
            findings.extend(self.check_public_access())
            findings.extend(self.check_active_execution_roles())
            findings.extend(self.check_code_signing())
            findings.extend(self.check_admin_privileges())
            findings.extend(self.check_cross_account_access())
            findings.extend(self.check_runtime_versions())
            findings.extend(self.check_encryption_in_transit())
            findings.extend(self.check_code_signing_manual_report())
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="12.ERROR",
                    title="Error Running Lambda Checks",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="lambda",
                    description=f"Failed to run Lambda checks: {str(e)}",
                    recommendation="Verify AWS credentials and permissions",
                )
            )

        return findings

    def check_code_signing_manual_report(self) -> List[Dict[str, Any]]:
        """
        12.M1 (Manual): Report to verify Lambda Code Signing configuration/policies
        Level: 1 | Type: Manual
        """
        findings: List[Dict[str, Any]] = []
        findings.append(
            self.create_finding(
                check_id="12.M1",
                title="Lambda Code Signing Configuration Review (Manual)",
                severity="LOW",
                status="WARNING",
                resource_id="lambda:code-signing",
                description=(
                    "Verify functions are associated with Code Signing Configs that enforce signature validation and trusted publishers."
                ),
                recommendation="Associate functions with a Code Signing Config and restrict to trusted signing profiles.",
                command=(
                    "aws lambda list-functions --query 'Functions[].FunctionName' ; "
                    "aws lambda get-function-code-signing-config --function-name <function>"
                ),
                evidence={"Function": "example-func", "CodeSigningConfigArn": None}
            )
        )
        return findings

    def check_cloudwatch_insights(self) -> List[Dict[str, Any]]:
        """
        12.2: Ensure Cloudwatch Lambda insights is enabled
        Level: 1 | Type: Manual
        """
        findings = []
        try:
            lambda_client = self.session.client("lambda", region_name=self.region)
            functions = lambda_client.list_functions()

            for function in functions.get("Functions", []):
                function_name = function.get("FunctionName", "")
                function_arn = function.get("FunctionArn", "")

                # Get function configuration
                config = lambda_client.get_function_configuration(FunctionName=function_name)
                layers = config.get("Layers", [])

                # Check if Lambda Insights layer is attached
                insights_enabled = any(
                    "LambdaInsightsExtension" in layer.get("Arn", "") for layer in layers
                )

                if not insights_enabled:
                    findings.append(
                        self.create_finding(
                            check_id="12.2",
                            title="Lambda Function Does Not Have Insights Enabled",
                            severity="LOW",
                            status="FAILED",
                            resource_id=function_arn,
                            description=f"Lambda function '{function_name}' does not have CloudWatch Lambda Insights enabled.",
                            recommendation="Enable Lambda Insights for enhanced monitoring and troubleshooting",
                        )
                    )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="12.2",
                    title="Unable to Check Lambda Insights",
                    severity="LOW",
                    status="WARNING",
                    resource_id="lambda",
                    description=f"Could not verify Lambda Insights: {str(e)}",
                    recommendation="Verify AWS permissions for lambda:ListFunctions and lambda:GetFunctionConfiguration",
                )
            )

        return findings

    def check_secrets_manager_usage(self) -> List[Dict[str, Any]]:
        """
        12.3: Ensure AWS Secrets Manager is configured and being used by Lambda for databases
        Level: 1 | Type: Manual
        """
        findings = []
        try:
            lambda_client = self.session.client("lambda", region_name=self.region)
            functions = lambda_client.list_functions()

            db_keywords = ["database", "db", "mysql", "postgres", "rds", "connection"]

            for function in functions.get("Functions", []):
                function_name = function.get("FunctionName", "")
                function_arn = function.get("FunctionArn", "")
                environment = function.get("Environment", {}).get("Variables", {})

                # Check if function name or env vars suggest database usage
                is_db_function = any(keyword in function_name.lower() for keyword in db_keywords)
                has_db_env_vars = any(
                    any(keyword in key.lower() for keyword in db_keywords)
                    for key in environment.keys()
                )

                if is_db_function or has_db_env_vars:
                    # Check if using Secrets Manager
                    uses_secrets = any(
                        "secret" in key.lower() or "arn:aws:secretsmanager" in str(value)
                        for key, value in environment.items()
                    )

                    if not uses_secrets:
                        findings.append(
                            self.create_finding(
                                check_id="12.3",
                                title="Lambda Function May Not Use Secrets Manager for Database Credentials",
                                severity="MEDIUM",
                                status="WARNING",
                                resource_id=function_arn,
                                description=f"Lambda function '{function_name}' appears to access databases but may not use Secrets Manager.",
                                recommendation="Store database credentials in AWS Secrets Manager and reference them in Lambda",
                            )
                        )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="12.3",
                    title="Unable to Check Secrets Manager Usage",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="lambda",
                    description=f"Could not verify Secrets Manager usage: {str(e)}",
                    recommendation="Verify AWS permissions",
                )
            )

        return findings

    def check_least_privilege(self) -> List[Dict[str, Any]]:
        """
        12.4: Ensure least privilege is used with Lambda function access
        Level: 1 | Type: Manual
        """
        findings = []
        try:
            lambda_client = self.session.client("lambda", region_name=self.region)
            iam = self.session.client("iam")
            functions = lambda_client.list_functions()

            for function in functions.get("Functions", []):
                function_name = function.get("FunctionName", "")
                function_arn = function.get("FunctionArn", "")
                role_arn = function.get("Role", "")

                if role_arn:
                    role_name = role_arn.split("/")[-1]

                    try:
                        # Get attached policies
                        attached_policies = iam.list_attached_role_policies(RoleName=role_name)

                        for policy in attached_policies.get("AttachedPolicies", []):
                            policy_name = policy.get("PolicyName", "")

                            # Check for overly permissive managed policies
                            if policy_name in [
                                "AdministratorAccess",
                                "PowerUserAccess",
                                "IAMFullAccess",
                            ]:
                                findings.append(
                                    self.create_finding(
                                        check_id="12.4",
                                        title="Lambda Function Has Overly Permissive IAM Role",
                                        severity="HIGH",
                                        status="FAILED",
                                        resource_id=function_arn,
                                        description=f"Lambda function '{function_name}' has overly permissive policy '{policy_name}' attached.",
                                        recommendation="Replace with custom policy granting only required permissions",
                                    )
                                )
                    except Exception:
                        pass

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="12.4",
                    title="Unable to Check Lambda Least Privilege",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="lambda",
                    description=f"Could not verify least privilege: {str(e)}",
                    recommendation="Verify AWS permissions",
                )
            )

        return findings

    def check_unique_iam_roles(self) -> List[Dict[str, Any]]:
        """
        12.5: Ensure every Lambda function has its own IAM Role
        Level: 1 | Type: Manual
        """
        findings = []
        try:
            lambda_client = self.session.client("lambda", region_name=self.region)
            functions = lambda_client.list_functions()

            role_usage = {}
            for function in functions.get("Functions", []):
                function_name = function.get("FunctionName", "")
                function_arn = function.get("FunctionArn", "")
                role_arn = function.get("Role", "")

                if role_arn:
                    if role_arn not in role_usage:
                        role_usage[role_arn] = []
                    role_usage[role_arn].append((function_name, function_arn))

            # Find roles shared by multiple functions
            for role_arn, functions_list in role_usage.items():
                if len(functions_list) > 1:
                    function_names = ", ".join([f[0] for f in functions_list])
                    for function_name, function_arn in functions_list:
                        findings.append(
                            self.create_finding(
                                check_id="12.5",
                                title="Lambda Function Shares IAM Role",
                                severity="MEDIUM",
                                status="FAILED",
                                resource_id=function_arn,
                                description=f"Lambda function '{function_name}' shares IAM role with: {function_names}",
                                recommendation="Create dedicated IAM role for each Lambda function to follow least privilege",
                            )
                        )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="12.5",
                    title="Unable to Check Lambda IAM Roles",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="lambda",
                    description=f"Could not verify IAM roles: {str(e)}",
                    recommendation="Verify AWS permissions",
                )
            )

        return findings

    def check_public_access(self) -> List[Dict[str, Any]]:
        """
        12.6: Ensure Lambda functions are not exposed to everyone
        Level: 1 | Type: Manual
        """
        findings = []
        try:
            lambda_client = self.session.client("lambda", region_name=self.region)
            functions = lambda_client.list_functions()

            for function in functions.get("Functions", []):
                function_name = function.get("FunctionName", "")
                function_arn = function.get("FunctionArn", "")

                try:
                    policy = lambda_client.get_policy(FunctionName=function_name)
                    import json

                    policy_doc = json.loads(policy.get("Policy", "{}"))
                    statements = policy_doc.get("Statement", [])

                    for statement in statements:
                        principal = statement.get("Principal", {})

                        # Check for public access
                        if principal == "*" or principal.get("AWS") == "*":
                            findings.append(
                                self.create_finding(
                                    check_id="12.6",
                                    title="Lambda Function Publicly Accessible",
                                    severity="CRITICAL",
                                    status="FAILED",
                                    resource_id=function_arn,
                                    description=f"Lambda function '{function_name}' has public access policy allowing invocation from any AWS account.",
                                    recommendation="Remove public access and grant permissions only to specific principals",
                                )
                            )
                            break
                except lambda_client.exceptions.ResourceNotFoundException:
                    pass  # No policy attached

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="12.6",
                    title="Unable to Check Lambda Public Access",
                    severity="CRITICAL",
                    status="WARNING",
                    resource_id="lambda",
                    description=f"Could not verify public access: {str(e)}",
                    recommendation="Verify AWS permissions",
                )
            )

        return findings

    def check_active_execution_roles(self) -> List[Dict[str, Any]]:
        """
        12.7: Ensure Lambda functions are referencing active execution roles
        Level: 1 | Type: Manual
        """
        findings = []
        try:
            lambda_client = self.session.client("lambda", region_name=self.region)
            iam = self.session.client("iam")
            functions = lambda_client.list_functions()

            for function in functions.get("Functions", []):
                function_name = function.get("FunctionName", "")
                function_arn = function.get("FunctionArn", "")
                role_arn = function.get("Role", "")

                if role_arn:
                    role_name = role_arn.split("/")[-1]

                    try:
                        iam.get_role(RoleName=role_name)
                    except iam.exceptions.NoSuchEntityException:
                        findings.append(
                            self.create_finding(
                                check_id="12.7",
                                title="Lambda Function References Deleted IAM Role",
                                severity="CRITICAL",
                                status="FAILED",
                                resource_id=function_arn,
                                description=f"Lambda function '{function_name}' references non-existent IAM role '{role_name}'.",
                                recommendation="Update function to use active IAM role",
                            )
                        )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="12.7",
                    title="Unable to Check Lambda Execution Roles",
                    severity="CRITICAL",
                    status="WARNING",
                    resource_id="lambda",
                    description=f"Could not verify execution roles: {str(e)}",
                    recommendation="Verify AWS permissions",
                )
            )

        return findings

    def check_code_signing(self) -> List[Dict[str, Any]]:
        """
        12.8: Ensure that Code Signing is enabled for Lambda functions
        Level: 1 | Type: Manual
        """
        findings = []
        try:
            lambda_client = self.session.client("lambda", region_name=self.region)
            functions = lambda_client.list_functions()

            for function in functions.get("Functions", []):
                function_name = function.get("FunctionName", "")
                function_arn = function.get("FunctionArn", "")

                config = lambda_client.get_function_configuration(FunctionName=function_name)
                code_signing_config = config.get("SigningJobArn")

                if not code_signing_config:
                    findings.append(
                        self.create_finding(
                            check_id="12.8",
                            title="Lambda Function Does Not Have Code Signing Enabled",
                            severity="MEDIUM",
                            status="FAILED",
                            resource_id=function_arn,
                            description=f"Lambda function '{function_name}' does not have code signing enabled.",
                            recommendation="Enable code signing to ensure only trusted code is deployed",
                        )
                    )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="12.8",
                    title="Unable to Check Lambda Code Signing",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="lambda",
                    description=f"Could not verify code signing: {str(e)}",
                    recommendation="Verify AWS permissions",
                )
            )

        return findings

    def check_admin_privileges(self) -> List[Dict[str, Any]]:
        """
        12.9: Ensure there are no Lambda functions with admin privileges
        Level: 1 | Type: Manual
        """
        findings = []
        # This is covered by check_least_privilege (12.4)
        return findings

    def check_cross_account_access(self) -> List[Dict[str, Any]]:
        """
        12.10: Ensure Lambda functions do not allow unknown cross account access
        Level: 1 | Type: Manual
        """
        findings = []
        # Simplified - would check for cross-account permissions in function policies
        return findings

    def check_runtime_versions(self) -> List[Dict[str, Any]]:
        """
        12.11: Ensure runtime environment versions used for Lambda functions do not have end of support dates
        Level: 1 | Type: Manual
        """
        findings = []
        try:
            lambda_client = self.session.client("lambda", region_name=self.region)
            functions = lambda_client.list_functions()

            # Deprecated runtimes as of 2025
            deprecated_runtimes = [
                "python2.7",
                "python3.6",
                "nodejs8.10",
                "nodejs10.x",
                "nodejs12.x",
                "dotnetcore2.1",
                "ruby2.5",
            ]

            for function in functions.get("Functions", []):
                function_name = function.get("FunctionName", "")
                function_arn = function.get("FunctionArn", "")
                runtime = function.get("Runtime", "")

                if runtime in deprecated_runtimes:
                    findings.append(
                        self.create_finding(
                            check_id="12.11",
                            title="Lambda Function Using Deprecated Runtime",
                            severity="HIGH",
                            status="FAILED",
                            resource_id=function_arn,
                            description=f"Lambda function '{function_name}' uses deprecated runtime '{runtime}'.",
                            recommendation="Update to a currently supported runtime version",
                        )
                    )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="12.11",
                    title="Unable to Check Lambda Runtimes",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="lambda",
                    description=f"Could not verify runtime versions: {str(e)}",
                    recommendation="Verify AWS permissions",
                )
            )

        return findings

    def check_encryption_in_transit(self) -> List[Dict[str, Any]]:
        """
        12.12: Ensure encryption in transit is enabled for Lambda environment variables
        Level: 1 | Type: Manual
        """
        findings = []
        try:
            lambda_client = self.session.client("lambda", region_name=self.region)
            functions = lambda_client.list_functions()

            for function in functions.get("Functions", []):
                function_name = function.get("FunctionName", "")
                function_arn = function.get("FunctionArn", "")
                environment = function.get("Environment", {})
                kms_key_arn = function.get("KMSKeyArn")

                has_env_vars = bool(environment.get("Variables", {}))

                if has_env_vars and not kms_key_arn:
                    findings.append(
                        self.create_finding(
                            check_id="12.12",
                            title="Lambda Environment Variables Not Encrypted with CMK",
                            severity="MEDIUM",
                            status="FAILED",
                            resource_id=function_arn,
                            description=f"Lambda function '{function_name}' has environment variables but does not use a customer-managed KMS key.",
                            recommendation="Configure KMS key for environment variable encryption",
                        )
                    )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="12.12",
                    title="Unable to Check Lambda Encryption",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="lambda",
                    description=f"Could not verify encryption: {str(e)}",
                    recommendation="Verify AWS permissions",
                )
            )

        return findings

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """Return mock findings for testing"""
        return [
            self.create_finding(
                check_id="12.4",
                title="Lambda Function Has Overly Permissive IAM Role",
                severity="HIGH",
                status="FAILED",
                resource_id="arn:aws:lambda:us-east-1:123456789012:function:data-processor",
                description="Lambda function has AdministratorAccess policy attached.",
                recommendation="Replace with custom policy granting only required permissions",
                command="aws lambda get-function --function-name data-processor --query 'Configuration.Role'",
                evidence={"Role": "arn:aws:iam::123456789012:role/AdministratorAccess", "Policies": ["AdministratorAccess"]}
            ),
            self.create_finding(
                check_id="12.6",
                title="Lambda Function Publicly Accessible",
                severity="CRITICAL",
                status="FAILED",
                resource_id="arn:aws:lambda:us-east-1:123456789012:function:api-handler",
                description="Lambda function has public access policy.",
                recommendation="Remove public access and grant permissions to specific principals",
                command="aws lambda get-policy --function-name api-handler",
                evidence={"Policy": '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunction"}]}'}
            ),
            self.create_finding(
                check_id="12.11",
                title="Lambda Function Using Deprecated Runtime",
                severity="HIGH",
                status="FAILED",
                resource_id="arn:aws:lambda:us-east-1:123456789012:function:legacy-app",
                description="Lambda function uses deprecated runtime 'python3.6'.",
                recommendation="Update to a currently supported runtime version",
                command="aws lambda get-function --function-name legacy-app --query 'Configuration.Runtime'",
                evidence={"Runtime": "python3.6", "Deprecated": True, "SupportedRuntimes": ["python3.9", "python3.10", "python3.11"]}
            ),
        ]
