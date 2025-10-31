"""
Base checker for AWS End User Compute Services

This module provides the base class for implementing CIS AWS End User Compute
Services Benchmark v1.2.0 checks.
"""

import boto3
from typing import Dict, List, Any, Optional
from ..aws_checks.base_checker import BaseAWSChecker


class EndUserComputeChecker(BaseAWSChecker):
    """
    Base class for AWS End User Compute Services security checks
    
    Implements CIS AWS End User Compute Services Benchmark v1.2.0
    covering WorkSpaces, WorkSpaces Web, WorkDocs, and AppStream 2.0
    """
    
    def __init__(self, session: boto3.Session, region: str = 'us-east-1'):
        """
        Initialize the End User Compute checker
        
        Args:
            session: Boto3 session
            region: AWS region
        """
        super().__init__(session, region)
        self.benchmark_name = "CIS AWS End User Compute Services Benchmark v1.2.0"
        self.benchmark_version = "1.2.0"
        
        # Initialize service clients
        self.workspaces_client = self.session.client('workspaces', region_name=region)
        self.workspaces_web_client = self.session.client('workspaces-web', region_name=region)
        self.workdocs_client = self.session.client('workdocs', region_name=region)
        self.appstream_client = self.session.client('appstream', region_name=region)
        self.iam_client = self.session.client('iam', region_name=region)
        self.ds_client = self.session.client('ds', region_name=region)
        self.kms_client = self.session.client('kms', region_name=region)
        
    def run_checks(self) -> List[Dict[str, Any]]:
        """
        Run all End User Compute security checks
        
        Returns:
            List of check results
        """
        if self.use_mock:
            return self._get_mock_findings()
        
        checks = []
        
        # WorkSpaces checks
        checks.extend(self.get_workspaces_checks())
        
        # WorkSpaces Web checks  
        checks.extend(self.get_workspaces_web_checks())
        
        # WorkDocs checks
        checks.extend(self.get_workdocs_checks())
        
        # AppStream 2.0 checks
        checks.extend(self.get_appstream_checks())
        
        return checks
    
    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """
        Get mock findings for End User Compute services
        
        Returns:
            List of mock findings
        """
        return [
            self.create_finding(
                check_id="workspaces_2.1",
                title="Ensure Administration of WorkSpaces is defined using IAM",
                severity="MEDIUM",
                status="FAILED",
                resource_id="aws:workspaces:administration",
                description="WorkSpaces administration IAM policies not properly configured",
                recommendation="Configure proper IAM policies for WorkSpaces administration",
                compliance_standard="CIS AWS End User Compute Services Benchmark v1.2.0"
            ),
            self.create_finding(
                check_id="workspaces_2.3",
                title="Ensure WorkSpace volumes are encrypted",
                severity="HIGH",
                status="PASSED",
                resource_id="aws:workspaces:volumes",
                description="WorkSpaces volumes are properly encrypted",
                recommendation="Continue monitoring encryption settings",
                compliance_standard="CIS AWS End User Compute Services Benchmark v1.2.0"
            ),
            self.create_finding(
                check_id="appstream_5.1",
                title="Ensure AppStream 2.0 stacks have proper security groups configured",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:appstream:security-groups",
                description="AppStream security groups need review for overly permissive rules",
                recommendation="Review and tighten security group rules",
                compliance_standard="CIS AWS End User Compute Services Benchmark v1.2.0"
            )
        ]
    
    def get_workspaces_checks(self) -> List[Dict[str, Any]]:
        """Get WorkSpaces specific checks"""
        return [
            {
                'id': 'workspaces_2.1',
                'title': 'Ensure Administration of WorkSpaces is defined using IAM',
                'description': 'To allow users to administer Amazon WorkSpaces, IAM policies must be created and attached with the required permissions to an IAM Principal used for administration of Amazon WorkSpaces.',
                'rationale': 'Creating and managing Workspaces specific users is not done in AWS IAM. Creating and managing Workspaces specific users is done within the Workspace service console. In order to properly administer Workspaces specific users, an IAM Principal with proper permissions must be created.',
                'profile': 'Level 1',
                'assessment_status': 'Manual',
                'service': 'WorkSpaces',
                'category': 'Access Control'
            },
            {
                'id': 'workspaces_2.2', 
                'title': 'Ensure MFA is enabled for WorkSpaces users',
                'description': 'Multi-Factor Authentication (MFA) adds an extra layer of authentication assurance beyond traditional username and password.',
                'rationale': 'Enabling MFA provides increased security to a username and password as it requires the user to have a virtual or physical hardware solution that displays a time-sensitive code.',
                'profile': 'Level 2',
                'assessment_status': 'Manual',
                'service': 'WorkSpaces',
                'category': 'Authentication'
            },
            {
                'id': 'workspaces_2.3',
                'title': 'Ensure WorkSpace volumes are encrypted',
                'description': 'Encrypt WorkSpaces root volume (C:drive for Windows and root for Amazon Linux) and user volume (D:drive for Windows and /home for Amazon Linux).',
                'rationale': 'When you launch a WorkSpace, you can encrypt the root volume and the user volume. This ensures that the data stored at rest for WorkSpaces is encrypted.',
                'profile': 'Level 1',
                'assessment_status': 'Automated',
                'service': 'WorkSpaces',
                'category': 'Encryption'
            }
        ]
    
    def get_workspaces_web_checks(self) -> List[Dict[str, Any]]:
        """Get WorkSpaces Web specific checks"""
        return [
            {
                'id': 'workspaces_web_3.1',
                'title': 'Ensure WorkSpaces Web portal is configured with proper authentication',
                'description': 'WorkSpaces Web portals should be configured with appropriate identity providers and authentication methods.',
                'rationale': 'Proper authentication configuration ensures only authorized users can access WorkSpaces Web portals.',
                'profile': 'Level 1',
                'assessment_status': 'Automated',
                'service': 'WorkSpaces Web',
                'category': 'Authentication'
            },
            {
                'id': 'workspaces_web_3.2',
                'title': 'Ensure WorkSpaces Web portal has network restrictions configured',
                'description': 'WorkSpaces Web portals should have appropriate network access controls and IP restrictions.',
                'rationale': 'Network restrictions help prevent unauthorized access to WorkSpaces Web portals from untrusted networks.',
                'profile': 'Level 1',
                'assessment_status': 'Automated',
                'service': 'WorkSpaces Web',
                'category': 'Network Security'
            }
        ]
    
    def get_workdocs_checks(self) -> List[Dict[str, Any]]:
        """Get WorkDocs specific checks"""
        return [
            {
                'id': 'workdocs_4.1',
                'title': 'Ensure WorkDocs sites have proper access controls',
                'description': 'WorkDocs sites should be configured with appropriate user access controls and permissions.',
                'rationale': 'Proper access controls ensure that only authorized users can access WorkDocs content and that data is protected according to the principle of least privilege.',
                'profile': 'Level 1',
                'assessment_status': 'Manual',
                'service': 'WorkDocs',
                'category': 'Access Control'
            },
            {
                'id': 'workdocs_4.2',
                'title': 'Ensure WorkDocs data is encrypted at rest',
                'description': 'WorkDocs data should be encrypted at rest using AWS KMS.',
                'rationale': 'Encryption at rest protects WorkDocs data from unauthorized access even if the underlying storage is compromised.',
                'profile': 'Level 1',
                'assessment_status': 'Automated',
                'service': 'WorkDocs',
                'category': 'Encryption'
            }
        ]
    
    def get_appstream_checks(self) -> List[Dict[str, Any]]:
        """Get AppStream 2.0 specific checks"""
        return [
            {
                'id': 'appstream_5.1',
                'title': 'Ensure AppStream 2.0 stacks have proper security groups configured',
                'description': 'AppStream 2.0 stacks should be configured with security groups that follow the principle of least privilege.',
                'rationale': 'Properly configured security groups help control network access to AppStream 2.0 resources and prevent unauthorized access.',
                'profile': 'Level 1',
                'assessment_status': 'Automated',
                'service': 'AppStream 2.0',
                'category': 'Network Security'
            },
            {
                'id': 'appstream_5.2',
                'title': 'Ensure AppStream 2.0 fleets have encryption enabled',
                'description': 'AppStream 2.0 fleets should have encryption enabled for data at rest and in transit.',
                'rationale': 'Encryption helps protect sensitive data processed by AppStream 2.0 applications from unauthorized access.',
                'profile': 'Level 1',
                'assessment_status': 'Automated',
                'service': 'AppStream 2.0',
                'category': 'Encryption'
            },
            {
                'id': 'appstream_5.3',
                'title': 'Ensure AppStream 2.0 user access is properly configured',
                'description': 'AppStream 2.0 user access should be configured with appropriate authentication and authorization controls.',
                'rationale': 'Proper user access configuration ensures that only authorized users can access AppStream 2.0 applications and resources.',
                'profile': 'Level 1',
                'assessment_status': 'Manual',
                'service': 'AppStream 2.0',
                'category': 'Access Control'
            }
        ]
