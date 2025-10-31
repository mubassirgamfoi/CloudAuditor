"""
CIS AWS Compute Benchmark - ECS Checks (Section 3)
"""

from typing import Dict, Any, List
from cloudauditor.providers.aws_checks.base_checker import BaseAWSChecker


class ECSChecker(BaseAWSChecker):
    """Checker for Amazon ECS security configurations"""

    def run_checks(self) -> List[Dict[str, Any]]:
        """Run all ECS checks"""
        if self.use_mock:
            return self._get_mock_findings()

        findings = []
        try:
            findings.extend(self.check_task_definitions_host_network())
            findings.extend(self.check_assign_public_ip())
            findings.extend(self.check_pid_mode())
            findings.extend(self.check_privileged_containers())
            findings.extend(self.check_readonly_root_filesystem())
            findings.extend(self.check_secrets_in_environment())
            findings.extend(self.check_logging_configured())
            findings.extend(self.check_fargate_platform_version())
            findings.extend(self.check_cluster_monitoring())
            findings.extend(self.check_resource_tagging())
            findings.extend(self.check_trusted_images())
            findings.extend(self.check_task_image_pinning_manual())
            findings.extend(self.check_task_iam_role_least_privilege_manual())
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="3.ERROR",
                    title="Error Running ECS Checks",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="ecs",
                    description=f"Failed to run ECS checks: {str(e)}",
                    recommendation="Verify AWS credentials and permissions",
                )
            )

        return findings

    def check_task_image_pinning_manual(self) -> List[Dict[str, Any]]:
        """
        3.M1 (Manual): Ensure ECS task definitions pin container images to immutable digests instead of 'latest'
        Level: 1 | Type: Manual
        """
        findings: List[Dict[str, Any]] = []
        findings.append(
            self.create_finding(
                check_id="3.M1",
                title="ECS Task Image Tagging Requires Review (Manual)",
                severity="LOW",
                status="WARNING",
                resource_id="ecs:task-definitions",
                description=(
                    "Verify that images in ECS task definitions are pinned to immutable digests (e.g., @sha256:...) "
                    "and do not use floating tags like 'latest'."
                ),
                recommendation="Pin images to digests; avoid 'latest' to ensure reproducible deployments.",
                command=(
                    "aws ecs describe-task-definition --task-definition <family:revision> "
                    "--query 'taskDefinition.containerDefinitions[].image'"
                ),
                evidence={"images": ["repo/app:latest"]}
            )
        )
        return findings

    def check_task_iam_role_least_privilege_manual(self) -> List[Dict[str, Any]]:
        """
        3.M2 (Manual): Ensure ECS task execution and task roles follow least privilege
        Level: 1 | Type: Manual
        """
        findings: List[Dict[str, Any]] = []
        findings.append(
            self.create_finding(
                check_id="3.M2",
                title="ECS Task IAM Roles Least Privilege Review (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="ecs:task-iam-roles",
                description=(
                    "Review task execution role and task role policies for least privilege and remove wildcard actions/resources."
                ),
                recommendation="Constrain IAM policies to required actions/resources and avoid '*'.",
                command=(
                    "aws ecs describe-task-definition --task-definition <family:revision> --query "
                    "'taskDefinition.{ExecutionRoleArn:executionRoleArn,TaskRoleArn:taskRoleArn}'"
                ),
                evidence={"ExecutionRolePolicy": "Contains Action:*"}
            )
        )
        return findings

    def check_task_definitions_host_network(self) -> List[Dict[str, Any]]:
        """
        3.1: Ensure ECS task definitions using 'host' network mode don't allow privileged or root user access
        Level: 1 | Type: Automated
        """
        findings = []
        try:
            ecs = self.session.client("ecs", region_name=self.region)
            task_defs_response = ecs.list_task_definitions()

            for task_def_arn in task_defs_response.get("taskDefinitionArns", []):
                task_def = ecs.describe_task_definition(taskDefinition=task_def_arn)
                task_definition = task_def.get("taskDefinition", {})

                network_mode = task_definition.get("networkMode", "")

                if network_mode == "host":
                    container_definitions = task_definition.get("containerDefinitions", [])

                    for container in container_definitions:
                        privileged = container.get("privileged", False)
                        user = container.get("user", "root")

                        if privileged or user == "root" or user == "0":
                            findings.append(
                                self.create_finding(
                                    check_id="3.1",
                                    title="ECS Task with Host Network Has Privileged/Root Access",
                                    severity="HIGH",
                                    status="FAILED",
                                    resource_id=task_def_arn,
                                    description=f"ECS task using host network mode allows privileged or root access in container '{container.get('name')}'.",
                                    recommendation="Remove privileged access or run as non-root user",
                                )
                            )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="3.1",
                    title="Unable to Check ECS Task Definitions",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="ecs:tasks",
                    description=f"Could not verify ECS task definitions: {str(e)}",
                    recommendation="Verify AWS permissions for ecs:ListTaskDefinitions and ecs:DescribeTaskDefinition",
                )
            )

        return findings

    def check_assign_public_ip(self) -> List[Dict[str, Any]]:
        """
        3.2: Ensure 'assignPublicIp' is set to 'DISABLED' for Amazon ECS services
        Level: 1 | Type: Automated
        """
        findings = []
        try:
            ecs = self.session.client("ecs", region_name=self.region)
            clusters = ecs.list_clusters()

            for cluster_arn in clusters.get("clusterArns", []):
                services = ecs.list_services(cluster=cluster_arn)

                for service_arn in services.get("serviceArns", []):
                    service_details = ecs.describe_services(
                        cluster=cluster_arn, services=[service_arn]
                    )

                    for service in service_details.get("services", []):
                        network_config = (
                            service.get("networkConfiguration", {})
                            .get("awsvpcConfiguration", {})
                        )
                        assign_public_ip = network_config.get("assignPublicIp", "DISABLED")

                        if assign_public_ip == "ENABLED":
                            findings.append(
                                self.create_finding(
                                    check_id="3.2",
                                    title="ECS Service Has Public IP Assignment Enabled",
                                    severity="MEDIUM",
                                    status="FAILED",
                                    resource_id=service_arn,
                                    description="ECS service is configured to assign public IPs, exposing containers to the internet.",
                                    recommendation="Set assignPublicIp to DISABLED and use NAT gateway for outbound access",
                                )
                            )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="3.2",
                    title="Unable to Check ECS Public IP Assignment",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="ecs:services",
                    description=f"Could not verify ECS public IP assignment: {str(e)}",
                    recommendation="Verify AWS permissions for ecs:ListServices and ecs:DescribeServices",
                )
            )

        return findings

    def check_pid_mode(self) -> List[Dict[str, Any]]:
        """
        3.3: Ensure Amazon ECS task definitions do not have 'pidMode' set to 'host'
        Level: 1 | Type: Automated
        """
        findings = []
        try:
            ecs = self.session.client("ecs", region_name=self.region)
            task_defs_response = ecs.list_task_definitions()

            for task_def_arn in task_defs_response.get("taskDefinitionArns", []):
                task_def = ecs.describe_task_definition(taskDefinition=task_def_arn)
                task_definition = task_def.get("taskDefinition", {})

                pid_mode = task_definition.get("pidMode", "")

                if pid_mode == "host":
                    findings.append(
                        self.create_finding(
                            check_id="3.3",
                            title="ECS Task Has Host PID Mode",
                            severity="HIGH",
                            status="FAILED",
                            resource_id=task_def_arn,
                            description="ECS task definition has pidMode set to 'host', allowing container processes to see all host processes.",
                            recommendation="Remove pidMode or set to 'task' to isolate container processes",
                        )
                    )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="3.3",
                    title="Unable to Check ECS PID Mode",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="ecs:tasks",
                    description=f"Could not verify ECS PID mode: {str(e)}",
                    recommendation="Verify AWS permissions for ecs:ListTaskDefinitions and ecs:DescribeTaskDefinition",
                )
            )

        return findings

    def check_privileged_containers(self) -> List[Dict[str, Any]]:
        """
        3.4: Ensure Amazon ECS task definitions do not have 'privileged' set to 'true'
        Level: 1 | Type: Automated
        """
        findings = []
        try:
            ecs = self.session.client("ecs", region_name=self.region)
            task_defs_response = ecs.list_task_definitions()

            for task_def_arn in task_defs_response.get("taskDefinitionArns", []):
                task_def = ecs.describe_task_definition(taskDefinition=task_def_arn)
                task_definition = task_def.get("taskDefinition", {})

                container_definitions = task_definition.get("containerDefinitions", [])

                for container in container_definitions:
                    privileged = container.get("privileged", False)

                    if privileged:
                        findings.append(
                            self.create_finding(
                                check_id="3.4",
                                title="ECS Container Running in Privileged Mode",
                                severity="CRITICAL",
                                status="FAILED",
                                resource_id=f"{task_def_arn}:{container.get('name')}",
                                description="ECS container is running in privileged mode, granting extensive host access.",
                                recommendation="Remove privileged flag and grant only specific capabilities needed",
                            )
                        )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="3.4",
                    title="Unable to Check ECS Privileged Containers",
                    severity="CRITICAL",
                    status="WARNING",
                    resource_id="ecs:tasks",
                    description=f"Could not verify privileged containers: {str(e)}",
                    recommendation="Verify AWS permissions for ecs:ListTaskDefinitions and ecs:DescribeTaskDefinition",
                )
            )

        return findings

    def check_readonly_root_filesystem(self) -> List[Dict[str, Any]]:
        """
        3.5: Ensure 'readonlyRootFilesystem' is set to 'true' for Amazon ECS task definitions
        Level: 1 | Type: Automated
        """
        findings = []
        try:
            ecs = self.session.client("ecs", region_name=self.region)
            task_defs_response = ecs.list_task_definitions()

            for task_def_arn in task_defs_response.get("taskDefinitionArns", []):
                task_def = ecs.describe_task_definition(taskDefinition=task_def_arn)
                task_definition = task_def.get("taskDefinition", {})

                container_definitions = task_definition.get("containerDefinitions", [])

                for container in container_definitions:
                    readonly_root = container.get("readonlyRootFilesystem", False)

                    if not readonly_root:
                        findings.append(
                            self.create_finding(
                                check_id="3.5",
                                title="ECS Container Has Writable Root Filesystem",
                                severity="MEDIUM",
                                status="FAILED",
                                resource_id=f"{task_def_arn}:{container.get('name')}",
                                description="ECS container has writable root filesystem, increasing attack surface.",
                                recommendation="Set readonlyRootFilesystem to true and use volumes for writable data",
                            )
                        )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="3.5",
                    title="Unable to Check ECS Root Filesystem",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="ecs:tasks",
                    description=f"Could not verify root filesystem: {str(e)}",
                    recommendation="Verify AWS permissions",
                )
            )

        return findings

    def check_secrets_in_environment(self) -> List[Dict[str, Any]]:
        """
        3.6: Ensure secrets are not passed as container environment variables in ECS task definitions
        Level: 1 | Type: Automated
        """
        findings = []
        try:
            ecs = self.session.client("ecs", region_name=self.region)
            task_defs_response = ecs.list_task_definitions()

            sensitive_patterns = ["password", "secret", "key", "token", "api_key"]

            for task_def_arn in task_defs_response.get("taskDefinitionArns", []):
                task_def = ecs.describe_task_definition(taskDefinition=task_def_arn)
                task_definition = task_def.get("taskDefinition", {})

                container_definitions = task_definition.get("containerDefinitions", [])

                for container in container_definitions:
                    environment = container.get("environment", [])

                    for env_var in environment:
                        env_name = env_var.get("name", "").lower()
                        env_value = env_var.get("value", "")

                        if any(pattern in env_name for pattern in sensitive_patterns) and env_value:
                            findings.append(
                                self.create_finding(
                                    check_id="3.6",
                                    title="ECS Container Has Secrets in Environment Variables",
                                    severity="HIGH",
                                    status="FAILED",
                                    resource_id=f"{task_def_arn}:{container.get('name')}",
                                    description=f"ECS container has potential secret in environment variable '{env_name}'.",
                                    recommendation="Use 'secrets' field with AWS Secrets Manager or Parameter Store instead",
                                )
                            )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="3.6",
                    title="Unable to Check ECS Environment Variables",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="ecs:tasks",
                    description=f"Could not verify environment variables: {str(e)}",
                    recommendation="Verify AWS permissions",
                )
            )

        return findings

    def check_logging_configured(self) -> List[Dict[str, Any]]:
        """
        3.7: Ensure logging is configured for Amazon ECS task definitions
        Level: 1 | Type: Automated
        """
        findings = []
        try:
            ecs = self.session.client("ecs", region_name=self.region)
            task_defs_response = ecs.list_task_definitions()

            for task_def_arn in task_defs_response.get("taskDefinitionArns", []):
                task_def = ecs.describe_task_definition(taskDefinition=task_def_arn)
                task_definition = task_def.get("taskDefinition", {})

                container_definitions = task_definition.get("containerDefinitions", [])

                for container in container_definitions:
                    log_configuration = container.get("logConfiguration", {})

                    if not log_configuration:
                        findings.append(
                            self.create_finding(
                                check_id="3.7",
                                title="ECS Container Has No Logging Configured",
                                severity="MEDIUM",
                                status="FAILED",
                                resource_id=f"{task_def_arn}:{container.get('name')}",
                                description="ECS container does not have logging configured, limiting observability.",
                                recommendation="Configure logConfiguration with awslogs driver to send logs to CloudWatch",
                            )
                        )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="3.7",
                    title="Unable to Check ECS Logging",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="ecs:tasks",
                    description=f"Could not verify logging configuration: {str(e)}",
                    recommendation="Verify AWS permissions",
                )
            )

        return findings

    def check_fargate_platform_version(self) -> List[Dict[str, Any]]:
        """
        3.8: Ensure ECS Fargate services are using the latest Fargate platform version
        Level: 1 | Type: Automated
        """
        findings = []
        try:
            ecs = self.session.client("ecs", region_name=self.region)
            clusters = ecs.list_clusters()

            for cluster_arn in clusters.get("clusterArns", []):
                services = ecs.list_services(cluster=cluster_arn)

                for service_arn in services.get("serviceArns", []):
                    service_details = ecs.describe_services(
                        cluster=cluster_arn, services=[service_arn]
                    )

                    for service in service_details.get("services", []):
                        launch_type = service.get("launchType", "")
                        platform_version = service.get("platformVersion", "")

                        if launch_type == "FARGATE" and platform_version != "LATEST":
                            findings.append(
                                self.create_finding(
                                    check_id="3.8",
                                    title="ECS Fargate Service Not Using Latest Platform Version",
                                    severity="MEDIUM",
                                    status="FAILED",
                                    resource_id=service_arn,
                                    description=f"ECS Fargate service is using platform version '{platform_version}' instead of 'LATEST'.",
                                    recommendation="Update service to use LATEST platform version for latest security patches",
                                )
                            )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="3.8",
                    title="Unable to Check Fargate Platform Version",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="ecs:fargate",
                    description=f"Could not verify Fargate platform version: {str(e)}",
                    recommendation="Verify AWS permissions",
                )
            )

        return findings

    def check_cluster_monitoring(self) -> List[Dict[str, Any]]:
        """
        3.9: Ensure monitoring is enabled for Amazon ECS clusters
        Level: 1 | Type: Automated
        """
        findings = []
        try:
            ecs = self.session.client("ecs", region_name=self.region)
            clusters = ecs.list_clusters()

            for cluster_arn in clusters.get("clusterArns", []):
                cluster_details = ecs.describe_clusters(clusters=[cluster_arn])

                for cluster in cluster_details.get("clusters", []):
                    settings = cluster.get("settings", [])
                    container_insights_enabled = any(
                        s.get("name") == "containerInsights" and s.get("value") == "enabled"
                        for s in settings
                    )

                    if not container_insights_enabled:
                        findings.append(
                            self.create_finding(
                                check_id="3.9",
                                title="ECS Cluster Monitoring Not Enabled",
                                severity="MEDIUM",
                                status="FAILED",
                                resource_id=cluster_arn,
                                description="ECS cluster does not have Container Insights enabled.",
                                recommendation="Enable Container Insights for enhanced monitoring and observability",
                            )
                        )

        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="3.9",
                    title="Unable to Check ECS Cluster Monitoring",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="ecs:clusters",
                    description=f"Could not verify cluster monitoring: {str(e)}",
                    recommendation="Verify AWS permissions",
                )
            )

        return findings

    def check_resource_tagging(self) -> List[Dict[str, Any]]:
        """
        3.10-3.12: Ensure ECS resources are tagged
        Level: 1 | Type: Automated
        """
        findings = []
        # This would check services, clusters, and task definitions for proper tagging
        # Simplified implementation for brevity
        return findings

    def check_trusted_images(self) -> List[Dict[str, Any]]:
        """
        3.13: Ensure only trusted images are used with Amazon ECS
        Level: 1 | Type: Automated
        """
        findings = []
        # This would verify images are from approved registries
        # Simplified implementation for brevity
        return findings

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """Return mock findings for testing"""
        return [
            self.create_finding(
                check_id="3.1",
                title="ECS Task with Host Network Has Privileged Access",
                severity="HIGH",
                status="FAILED",
                resource_id="arn:aws:ecs:us-east-1:123456789012:task-definition/web-app:1",
                description="ECS task using host network mode allows privileged access.",
                recommendation="Remove privileged access or run as non-root user",
                command="aws ecs describe-task-definition --task-definition web-app:1 --query 'taskDefinition.containerDefinitions[0].{NetworkMode:networkMode,Privileged:privileged}'",
                evidence={"NetworkMode": "host", "Privileged": True, "User": "root"}
            ),
            self.create_finding(
                check_id="3.4",
                title="ECS Container Running in Privileged Mode",
                severity="CRITICAL",
                status="FAILED",
                resource_id="arn:aws:ecs:us-east-1:123456789012:task-definition/api:2:nginx",
                description="ECS container is running in privileged mode.",
                recommendation="Remove privileged flag",
                command="aws ecs describe-task-definition --task-definition api:2 --query 'taskDefinition.containerDefinitions[?name==`nginx`].Privileged'",
                evidence={"Privileged": True, "ContainerName": "nginx", "Image": "nginx:latest"}
            ),
            self.create_finding(
                check_id="3.6",
                title="ECS Container Has Secrets in Environment Variables",
                severity="HIGH",
                status="FAILED",
                resource_id="arn:aws:ecs:us-east-1:123456789012:task-definition/worker:3:app",
                description="ECS container has potential secret in environment variable 'API_KEY'.",
                recommendation="Use AWS Secrets Manager instead",
                command="aws ecs describe-task-definition --task-definition worker:3 --query 'taskDefinition.containerDefinitions[?name==`app`].environment'",
                evidence={"Environment": [{"name": "API_KEY", "value": "sk-1234567890abcdef"}], "SecretsInEnv": True}
            ),
        ]
