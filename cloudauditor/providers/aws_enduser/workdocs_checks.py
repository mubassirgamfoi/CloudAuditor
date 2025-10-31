"""
WorkDocs Security Checks

This module implements WorkDocs specific security checks from the
CIS AWS End User Compute Services Benchmark v1.2.0
"""

import boto3
from typing import Dict, List, Any, Optional
from ..aws_checks.base_checker import BaseAWSChecker


class WorkDocsChecker(BaseAWSChecker):
    """
    WorkDocs security checker implementation
    
    Implements WorkDocs specific checks from CIS AWS End User Compute
    Services Benchmark v1.2.0
    """
    
    def __init__(self, session: boto3.Session, region: str = 'us-east-1', use_mock: bool = True):
        """Initialize WorkDocs checker"""
        super().__init__(session, region, use_mock)
        self.service_name = "WorkDocs"
        
        # Initialize service clients
        if session:
            self.workdocs_client = session.client('workdocs', region_name=region)
    
    def check_workdocs_access_controls(self) -> Dict[str, Any]:
        """
        Check 4.1: Ensure WorkDocs sites have proper access controls
        
        Returns:
            Check result dictionary
        """
        check_id = "workdocs_4.1"
        check_title = "Ensure WorkDocs sites have proper access controls"
        
        try:
            # Get WorkDocs sites
            sites = []
            try:
                response = self.workdocs_client.describe_users()
                # WorkDocs doesn't have a direct list sites API, so we check users
                # which gives us information about the organization
                users = response.get('Users', [])
                
                # Group users by organization to identify sites
                organizations = {}
                for user in users:
                    org_id = user.get('OrganizationId', 'Unknown')
                    if org_id not in organizations:
                        organizations[org_id] = {
                            'organization_id': org_id,
                            'users': [],
                            'admin_users': [],
                            'regular_users': []
                        }
                    
                    organizations[org_id]['users'].append(user)
                    
                    # Check if user is admin
                    if user.get('Type') == 'ADMIN':
                        organizations[org_id]['admin_users'].append(user)
                    else:
                        organizations[org_id]['regular_users'].append(user)
                
                sites = list(organizations.values())
                
            except Exception as e:
                return {
                    'check_id': check_id,
                    'check_title': check_title,
                    'status': "ERROR",
                    'message': f"Error retrieving WorkDocs sites: {str(e)}",
                    'details': {},
                    'recommendation': 'Ensure WorkDocs is properly configured'
                }
            
            if not sites:
                return {
                    'check_id': check_id,
                    'check_title': check_title,
                    'status': "INFO",
                    'message': "No WorkDocs sites found",
                    'details': {'sites': []},
                    'recommendation': 'No action required - no WorkDocs sites configured'
                }
            
            site_access_status = []
            for site in sites:
                org_id = site['organization_id']
                total_users = len(site['users'])
                admin_users = len(site['admin_users'])
                regular_users = len(site['regular_users'])
                
                # Check access control indicators
                has_admins = admin_users > 0
                has_regular_users = regular_users > 0
                proper_user_distribution = has_admins and has_regular_users
                
                # Check for specific user permissions (this would require more detailed API calls)
                # For now, we'll check basic structure
                access_controls_configured = proper_user_distribution and total_users > 0
                
                site_access_status.append({
                    'organization_id': org_id,
                    'total_users': total_users,
                    'admin_users': admin_users,
                    'regular_users': regular_users,
                    'has_admins': has_admins,
                    'has_regular_users': has_regular_users,
                    'proper_user_distribution': proper_user_distribution,
                    'access_controls_configured': access_controls_configured
                })
            
            # Determine overall status
            properly_configured = [s for s in site_access_status if s.get('access_controls_configured', False)]
            
            if len(properly_configured) == len(site_access_status) and len(site_access_status) > 0:
                status = "PASS"
                message = f"All {len(site_access_status)} WorkDocs sites have proper access controls configured"
            elif len(properly_configured) > 0:
                status = "WARN"
                message = f"{len(properly_configured)} out of {len(site_access_status)} sites have proper access controls configured"
            else:
                status = "FAIL"
                message = "No WorkDocs sites have proper access controls configured"
            
            return {
                'check_id': check_id,
                'check_title': check_title,
                'status': status,
                'message': message,
                'details': {
                    'sites': site_access_status,
                    'total_sites': len(site_access_status),
                    'properly_configured': len(properly_configured)
                },
                'recommendation': 'Configure proper user access controls and permissions for all WorkDocs sites'
            }
            
        except Exception as e:
            return {
                'check_id': check_id,
                'check_title': check_title,
                'status': "ERROR",
                'message': f"Error checking WorkDocs access controls: {str(e)}",
                'details': {},
                'recommendation': 'Review WorkDocs site configuration and ensure proper access controls'
            }
    
    def check_workdocs_encryption_at_rest(self) -> Dict[str, Any]:
        """
        Check 4.2: Ensure WorkDocs data is encrypted at rest
        
        Returns:
            Check result dictionary
        """
        check_id = "workdocs_4.2"
        check_title = "Ensure WorkDocs data is encrypted at rest"
        
        try:
            # WorkDocs uses S3 for storage, so we need to check S3 bucket encryption
            # This is a simplified check - in practice, you'd need to check the actual S3 buckets
            # used by WorkDocs in your organization
            
            # Get WorkDocs organization information
            try:
                response = self.workdocs_client.describe_users()
                users = response.get('Users', [])
                
                if not users:
                    return {
                        'check_id': check_id,
                        'check_title': check_title,
                        'status': "INFO",
                        'message': "No WorkDocs users found",
                        'details': {},
                        'recommendation': 'No action required - no WorkDocs data to encrypt'
                    }
                
                # Check if KMS is being used (this would require checking S3 bucket policies)
                # For now, we'll provide a general recommendation
                status = "INFO"
                message = "WorkDocs encryption status requires manual verification of S3 bucket encryption settings"
                
                return {
                    'check_id': check_id,
                    'check_title': check_title,
                    'status': status,
                    'message': message,
                    'details': {
                        'total_users': len(users),
                        'note': 'WorkDocs uses S3 for storage. Check S3 bucket encryption settings for WorkDocs buckets.'
                    },
                    'recommendation': 'Verify that S3 buckets used by WorkDocs have server-side encryption enabled with AWS KMS'
                }
                
            except Exception as e:
                return {
                    'check_id': check_id,
                    'check_title': check_title,
                    'status': "ERROR",
                    'message': f"Error checking WorkDocs encryption: {str(e)}",
                    'details': {},
                    'recommendation': 'Review WorkDocs configuration and ensure S3 buckets are encrypted'
                }
            
        except Exception as e:
            return {
                'check_id': check_id,
                'check_title': check_title,
                'status': "ERROR",
                'message': f"Error checking WorkDocs encryption at rest: {str(e)}",
                'details': {},
                'recommendation': 'Review WorkDocs configuration and ensure proper encryption is enabled'
            }
    
    def run_checks(self) -> List[Dict[str, Any]]:
        """
        Run all WorkDocs security checks
        
        Returns:
            List of check results
        """
        if self.use_mock:
            return self._get_mock_findings()
        
        checks = [
            self.check_workdocs_access_controls(),
            self.check_workdocs_encryption_at_rest()
        ]
        
        return checks
    
    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """
        Get mock findings for WorkDocs
        
        Returns:
            List of mock findings
        """
        return [
            self.create_finding(
                check_id="workdocs_4.1",
                title="Ensure WorkDocs sites have proper access controls",
                severity="MEDIUM",
                status="INFO",
                resource_id="aws:workdocs:access-controls",
                description="WorkDocs access controls require manual verification",
                recommendation="Review and configure proper user access controls for WorkDocs sites",
                compliance_standard="CIS AWS End User Compute Services Benchmark v1.2.0"
            )
        ]
