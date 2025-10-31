import boto3
from typing import Dict, List, Any, Optional
from ..aws_checks.base_checker import BaseAWSChecker


class EDRChecker(BaseAWSChecker):
    """
    Elastic Disaster Recovery security checker implementation

    Implements EDR specific checks from CIS AWS Storage
    Services Benchmark v1.0.0
    """

    def __init__(self, session: boto3.Session, region: str = 'us-east-1', use_mock: bool = True):
        """Initialize EDR checker"""
        super().__init__(session, region, use_mock)
        self.service_name = "Elastic Disaster Recovery"

        # Initialize service clients
        if session:
            self.drs_client = session.client('drs', region_name=region)
            self.iam_client = session.client('iam', region_name=region)
            self.cloudwatch_client = session.client('cloudwatch', region_name=region)

    def check_edr_configuration(self) -> Dict[str, Any]:
        """
        Check Elastic Disaster Recovery configuration
        
        Returns:
            Check result dictionary
        """
        try:
            if self.use_mock:
                return self.create_finding(
                    check_id="edr_6.1",
                    title="Ensure Elastic Disaster Recovery is Configured (Manual)",
                    severity="HIGH",
                    status="FAILED",
                    resource_id="aws:edr:disaster-recovery",
                    description="Elastic Disaster Recovery is not properly configured",
                    recommendation="Configure AWS Elastic Disaster Recovery for high resiliency",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            # Check EDR source servers
            try:
                source_servers = self.drs_client.describe_source_servers()
                total_servers = len(source_servers['items'])

                if total_servers == 0:
                    return self.create_finding(
                        check_id="edr_6.1",
                        title="Ensure Elastic Disaster Recovery is Configured (Manual)",
                        severity="HIGH",
                        status="FAILED",
                        resource_id="aws:edr:disaster-recovery",
                        description="No source servers found in EDR",
                        recommendation="Configure source servers for disaster recovery",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

            except Exception as e:
                return self.create_finding(
                    check_id="edr_6.1",
                    title="Ensure Elastic Disaster Recovery is Configured (Manual)",
                    severity="HIGH",
                    status="FAILED",
                    resource_id="aws:edr:disaster-recovery",
                    description=f"Error checking EDR configuration: {str(e)}",
                    recommendation="Configure AWS Elastic Disaster Recovery for high resiliency",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            return self.create_finding(
                check_id="edr_6.1",
                title="Ensure Elastic Disaster Recovery is Configured (Manual)",
                severity="HIGH",
                status="PASSED",
                resource_id="aws:edr:disaster-recovery",
                description=f"Found {total_servers} source servers in EDR",
                recommendation="Continue monitoring EDR configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

        except Exception as e:
            return self.create_finding(
                check_id="edr_6.1",
                title="Ensure Elastic Disaster Recovery is Configured (Manual)",
                severity="HIGH",
                status="ERROR",
                resource_id="aws:edr:disaster-recovery",
                description=f"Error checking EDR configuration: {str(e)}",
                recommendation="Review EDR configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

    def check_edr_disaster_recovery_config(self) -> Dict[str, Any]:
        """
        Check AWS Disaster Recovery configuration
        
        Returns:
            Check result dictionary
        """
        try:
            if self.use_mock:
                return self.create_finding(
                    check_id="edr_6.2",
                    title="Ensure AWS Disaster Recovery Configuration (Manual)",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="aws:edr:configuration",
                    description="AWS Disaster Recovery configuration needs review",
                    recommendation="Review and update AWS Disaster Recovery configuration",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            # Check EDR replication configuration
            try:
                replication_configs = self.drs_client.describe_replication_configuration_templates()
                total_configs = len(replication_configs['items'])

                if total_configs == 0:
                    return self.create_finding(
                        check_id="edr_6.2",
                        title="Ensure AWS Disaster Recovery Configuration (Manual)",
                        severity="HIGH",
                        status="WARNING",
                        resource_id="aws:edr:configuration",
                        description="No replication configuration templates found",
                        recommendation="Create replication configuration templates for disaster recovery",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

            except Exception as e:
                return self.create_finding(
                    check_id="edr_6.2",
                    title="Ensure AWS Disaster Recovery Configuration (Manual)",
                    severity="HIGH",
                    status="WARNING",
                    resource_id="aws:edr:configuration",
                    description=f"Error checking EDR replication configuration: {str(e)}",
                    recommendation="Review EDR replication configuration",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            return self.create_finding(
                check_id="edr_6.2",
                title="Ensure AWS Disaster Recovery Configuration (Manual)",
                severity="HIGH",
                status="PASSED",
                resource_id="aws:edr:configuration",
                description=f"Found {total_configs} replication configuration templates",
                recommendation="Continue monitoring EDR configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

        except Exception as e:
            return self.create_finding(
                check_id="edr_6.2",
                title="Ensure AWS Disaster Recovery Configuration (Manual)",
                severity="HIGH",
                status="ERROR",
                resource_id="aws:edr:configuration",
                description=f"Error checking EDR disaster recovery configuration: {str(e)}",
                recommendation="Review EDR configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

    def check_edr_endpoint_detection(self) -> Dict[str, Any]:
        """
        Check EDR endpoint detection functionality
        
        Returns:
            Check result dictionary
        """
        try:
            if self.use_mock:
                return self.create_finding(
                    check_id="edr_6.3",
                    title="Ensure functionality of Endpoint Detection and Response (EDR) (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:edr:endpoint-detection",
                    description="Endpoint Detection and Response functionality needs review",
                    recommendation="Ensure EDR functionality is properly configured",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            # Check EDR job status
            try:
                jobs = self.drs_client.describe_jobs()
                active_jobs = 0
                total_jobs = len(jobs['items'])

                for job in jobs['items']:
                    if job['status'] in ['PENDING', 'STARTED', 'IN_PROGRESS']:
                        active_jobs += 1

                if total_jobs == 0:
                    return self.create_finding(
                        check_id="edr_6.3",
                        title="Ensure functionality of Endpoint Detection and Response (EDR) (Manual)",
                        severity="MEDIUM",
                        status="WARNING",
                        resource_id="aws:edr:endpoint-detection",
                        description="No EDR jobs found",
                        recommendation="Ensure EDR jobs are running for endpoint detection",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

            except Exception as e:
                return self.create_finding(
                    check_id="edr_6.3",
                    title="Ensure functionality of Endpoint Detection and Response (EDR) (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:edr:endpoint-detection",
                    description=f"Error checking EDR jobs: {str(e)}",
                    recommendation="Review EDR job configuration",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            return self.create_finding(
                check_id="edr_6.3",
                title="Ensure functionality of Endpoint Detection and Response (EDR) (Manual)",
                severity="MEDIUM",
                status="PASSED",
                resource_id="aws:edr:endpoint-detection",
                description=f"Found {active_jobs} active EDR jobs",
                recommendation="Continue monitoring EDR functionality",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

        except Exception as e:
            return self.create_finding(
                check_id="edr_6.3",
                title="Ensure functionality of Endpoint Detection and Response (EDR) (Manual)",
                severity="HIGH",
                status="ERROR",
                resource_id="aws:edr:endpoint-detection",
                description=f"Error checking EDR endpoint detection: {str(e)}",
                recommendation="Review EDR endpoint detection configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

    def check_edr_replication_settings(self) -> Dict[str, Any]:
        """
        Check EDR replication settings
        
        Returns:
            Check result dictionary
        """
        try:
            if self.use_mock:
                return self.create_finding(
                    check_id="edr_6.4",
                    title="Ensure configuration of replication settings (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:edr:replication-settings",
                    description="Replication settings need configuration",
                    recommendation="Configure proper replication settings for disaster recovery",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            # Check EDR replication configuration templates
            try:
                templates = self.drs_client.describe_replication_configuration_templates()
                total_templates = len(templates['items'])

                if total_templates == 0:
                    return self.create_finding(
                        check_id="edr_6.4",
                        title="Ensure configuration of replication settings (Manual)",
                        severity="MEDIUM",
                        status="WARNING",
                        resource_id="aws:edr:replication-settings",
                        description="No replication configuration templates found",
                        recommendation="Create replication configuration templates",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

            except Exception as e:
                return self.create_finding(
                    check_id="edr_6.4",
                    title="Ensure configuration of replication settings (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:edr:replication-settings",
                    description=f"Error checking replication settings: {str(e)}",
                    recommendation="Review replication settings configuration",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            return self.create_finding(
                check_id="edr_6.4",
                title="Ensure configuration of replication settings (Manual)",
                severity="MEDIUM",
                status="PASSED",
                resource_id="aws:edr:replication-settings",
                description=f"Found {total_templates} replication configuration templates",
                recommendation="Continue monitoring replication settings",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

        except Exception as e:
            return self.create_finding(
                check_id="edr_6.4",
                title="Ensure configuration of replication settings (Manual)",
                severity="HIGH",
                status="ERROR",
                resource_id="aws:edr:replication-settings",
                description=f"Error checking EDR replication settings: {str(e)}",
                recommendation="Review EDR replication settings configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

    def check_edr_iam_configuration(self) -> Dict[str, Any]:
        """
        Check EDR IAM configuration
        
        Returns:
            Check result dictionary
        """
        try:
            if self.use_mock:
                return self.create_finding(
                    check_id="edr_6.5",
                    title="Ensure proper IAM configuration for AWS Elastic Disaster Recovery (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:edr:iam-configuration",
                    description="IAM configuration for EDR needs review",
                    recommendation="Configure proper IAM policies and roles for EDR",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            # Check for EDR-related IAM roles
            try:
                roles = self.iam_client.list_roles()
                edr_roles = [r for r in roles['Roles'] if 'drs' in r['RoleName'].lower() or 'disaster' in r['RoleName'].lower()]

                if not edr_roles:
                    return self.create_finding(
                        check_id="edr_6.5",
                        title="Ensure proper IAM configuration for AWS Elastic Disaster Recovery (Manual)",
                        severity="MEDIUM",
                        status="WARNING",
                        resource_id="aws:edr:iam-configuration",
                        description="No EDR-specific IAM roles found",
                        recommendation="Create IAM roles specifically for EDR operations",
                        compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                    )

            except Exception as e:
                return self.create_finding(
                    check_id="edr_6.5",
                    title="Ensure proper IAM configuration for AWS Elastic Disaster Recovery (Manual)",
                    severity="MEDIUM",
                    status="WARNING",
                    resource_id="aws:edr:iam-configuration",
                    description=f"Error checking IAM roles: {str(e)}",
                    recommendation="Review IAM roles for EDR",
                    compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
                )

            return self.create_finding(
                check_id="edr_6.5",
                title="Ensure proper IAM configuration for AWS Elastic Disaster Recovery (Manual)",
                severity="MEDIUM",
                status="PASSED",
                resource_id="aws:edr:iam-configuration",
                description=f"Found {len(edr_roles)} EDR-specific IAM roles",
                recommendation="Continue monitoring EDR IAM configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

        except Exception as e:
            return self.create_finding(
                check_id="edr_6.5",
                title="Ensure proper IAM configuration for AWS Elastic Disaster Recovery (Manual)",
                severity="HIGH",
                status="ERROR",
                resource_id="aws:edr:iam-configuration",
                description=f"Error checking EDR IAM configuration: {str(e)}",
                recommendation="Review EDR IAM configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )

    def run_checks(self) -> List[Dict[str, Any]]:
        """
        Run all EDR security checks

        Returns:
            List of check results
        """
        if self.use_mock:
            return self._get_mock_findings()

        checks = [
            self.check_edr_configuration(),
            self.check_edr_disaster_recovery_config(),
            self.check_edr_endpoint_detection(),
            self.check_edr_replication_settings(),
            self.check_edr_iam_configuration()
        ]

        return checks

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """
        Get mock findings for EDR

        Returns:
            List of mock findings
        """
        return [
            self.create_finding(
                check_id="edr_6.1",
                title="Ensure Elastic Disaster Recovery is Configured (Manual)",
                severity="HIGH",
                status="FAILED",
                resource_id="aws:edr:disaster-recovery",
                description="Elastic Disaster Recovery is not properly configured",
                recommendation="Configure AWS Elastic Disaster Recovery for high resiliency",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="edr_6.2",
                title="Ensure AWS Disaster Recovery Configuration (Manual)",
                severity="HIGH",
                status="WARNING",
                resource_id="aws:edr:configuration",
                description="AWS Disaster Recovery configuration needs review",
                recommendation="Review and update AWS Disaster Recovery configuration",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="edr_6.3",
                title="Ensure functionality of Endpoint Detection and Response (EDR) (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:edr:endpoint-detection",
                description="Endpoint Detection and Response functionality needs review",
                recommendation="Ensure EDR functionality is properly configured",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="edr_6.4",
                title="Ensure configuration of replication settings (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:edr:replication-settings",
                description="Replication settings need configuration",
                recommendation="Configure proper replication settings for disaster recovery",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            ),
            self.create_finding(
                check_id="edr_6.5",
                title="Ensure proper IAM configuration for AWS Elastic Disaster Recovery (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:edr:iam-configuration",
                description="IAM configuration for EDR needs review",
                recommendation="Configure proper IAM policies and roles for EDR",
                compliance_standard="CIS AWS Storage Services Benchmark v1.0.0"
            )
        ]
