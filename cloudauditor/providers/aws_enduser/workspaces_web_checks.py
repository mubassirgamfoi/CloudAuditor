"""
WorkSpaces Web Security Checks

This module implements WorkSpaces Web specific security checks from the
CIS AWS End User Compute Services Benchmark v1.2.0
"""

import boto3
from typing import Dict, List, Any, Optional
from ..aws_checks.base_checker import BaseAWSChecker


class WorkSpacesWebChecker(BaseAWSChecker):
    """
    WorkSpaces Web security checker implementation
    
    Implements WorkSpaces Web specific checks from CIS AWS End User Compute
    Services Benchmark v1.2.0
    """
    
    def __init__(self, session: boto3.Session, region: str = 'us-east-1', use_mock: bool = True):
        """Initialize WorkSpaces Web checker"""
        super().__init__(session, region, use_mock)
        self.service_name = "WorkSpaces Web"
        
        # Initialize service clients
        if session:
            self.workspaces_web_client = session.client('workspaces-web', region_name=region)
            self.ec2_client = session.client('ec2', region_name=region)
    
    def check_workspaces_web_authentication(self) -> Dict[str, Any]:
        """
        Check 3.1: Ensure WorkSpaces Web portal is configured with proper authentication
        
        Returns:
            Check result dictionary
        """
        check_id = "workspaces_web_3.1"
        check_title = "Ensure WorkSpaces Web portal is configured with proper authentication"
        
        try:
            # Get WorkSpaces Web portals
            portals = []
            try:
                response = self.workspaces_web_client.list_portals()
                portals = response.get('portals', [])
            except Exception as e:
                return {
                    'check_id': check_id,
                    'check_title': check_title,
                    'status': "ERROR",
                    'message': f"Error retrieving WorkSpaces Web portals: {str(e)}",
                    'details': {},
                    'recommendation': 'Ensure WorkSpaces Web is properly configured'
                }
            
            if not portals:
                return {
                    'check_id': check_id,
                    'check_title': check_title,
                    'status': "INFO",
                    'message': "No WorkSpaces Web portals found",
                    'details': {'portals': []},
                    'recommendation': 'No action required - no WorkSpaces Web portals configured'
                }
            
            portal_auth_status = []
            for portal in portals:
                portal_id = portal['portalArn'].split('/')[-1]
                
                # Get portal details
                try:
                    portal_details = self.workspaces_web_client.get_portal(
                        portalArn=portal['portalArn']
                    )
                    
                    # Check authentication configuration
                    auth_config = portal_details.get('portal', {})
                    identity_provider = auth_config.get('identityProvider', {})
                    
                    # Get identity provider details
                    idp_type = identity_provider.get('identityProviderType', 'Unknown')
                    idp_arn = identity_provider.get('identityProviderArn', '')
                    
                    # Check if SAML is configured
                    saml_configured = idp_type == 'SAML' and idp_arn
                    
                    portal_auth_status.append({
                        'portal_id': portal_id,
                        'portal_arn': portal['portalArn'],
                        'identity_provider_type': idp_type,
                        'identity_provider_arn': idp_arn,
                        'saml_configured': saml_configured,
                        'authentication_configured': bool(idp_arn)
                    })
                    
                except Exception as e:
                    portal_auth_status.append({
                        'portal_id': portal_id,
                        'portal_arn': portal['portalArn'],
                        'error': str(e),
                        'authentication_configured': False
                    })
            
            # Determine overall status
            properly_configured = [p for p in portal_auth_status if p.get('authentication_configured', False)]
            saml_configured = [p for p in portal_auth_status if p.get('saml_configured', False)]
            
            if len(properly_configured) == len(portal_auth_status) and len(portal_auth_status) > 0:
                status = "PASS"
                message = f"All {len(portal_auth_status)} WorkSpaces Web portals have authentication configured"
            elif len(properly_configured) > 0:
                status = "WARN"
                message = f"{len(properly_configured)} out of {len(portal_auth_status)} portals have authentication configured"
            else:
                status = "FAIL"
                message = "No WorkSpaces Web portals have authentication configured"
            
            return {
                'check_id': check_id,
                'check_title': check_title,
                'status': status,
                'message': message,
                'details': {
                    'portals': portal_auth_status,
                    'total_portals': len(portal_auth_status),
                    'properly_configured': len(properly_configured),
                    'saml_configured': len(saml_configured)
                },
                'recommendation': 'Configure proper identity providers (SAML recommended) for all WorkSpaces Web portals'
            }
            
        except Exception as e:
            return {
                'check_id': check_id,
                'check_title': check_title,
                'status': "ERROR",
                'message': f"Error checking WorkSpaces Web authentication: {str(e)}",
                'details': {},
                'recommendation': 'Review WorkSpaces Web portal configuration and enable proper authentication'
            }
    
    def check_workspaces_web_network_restrictions(self) -> Dict[str, Any]:
        """
        Check 3.2: Ensure WorkSpaces Web portal has network restrictions configured
        
        Returns:
            Check result dictionary
        """
        check_id = "workspaces_web_3.2"
        check_title = "Ensure WorkSpaces Web portal has network restrictions configured"
        
        try:
            # Get WorkSpaces Web portals
            portals = []
            try:
                response = self.workspaces_web_client.list_portals()
                portals = response.get('portals', [])
            except Exception as e:
                return {
                    'check_id': check_id,
                    'check_title': check_title,
                    'status': "ERROR",
                    'message': f"Error retrieving WorkSpaces Web portals: {str(e)}",
                    'details': {},
                    'recommendation': 'Ensure WorkSpaces Web is properly configured'
                }
            
            if not portals:
                return {
                    'check_id': check_id,
                    'check_title': check_title,
                    'status': "INFO",
                    'message': "No WorkSpaces Web portals found",
                    'details': {'portals': []},
                    'recommendation': 'No action required - no WorkSpaces Web portals configured'
                }
            
            portal_network_status = []
            for portal in portals:
                portal_id = portal['portalArn'].split('/')[-1]
                
                try:
                    # Get network settings for the portal
                    network_settings = self.workspaces_web_client.get_network_settings(
                        networkSettingsArn=portal['networkSettingsArn']
                    )
                    
                    # Get IP access settings
                    ip_access_settings = self.workspaces_web_client.get_ip_access_settings(
                        ipAccessSettingsArn=portal['ipAccessSettingsArn']
                    )
                    
                    network_config = network_settings.get('networkSettings', {})
                    ip_config = ip_access_settings.get('ipAccessSettings', {})
                    
                    # Check for VPC configuration
                    vpc_id = network_config.get('vpcId', '')
                    subnet_ids = network_config.get('subnetIds', [])
                    security_group_ids = network_config.get('securityGroupIds', [])
                    
                    # Check for IP restrictions
                    ip_rules = ip_config.get('ipRules', [])
                    ip_restrictions_enabled = len(ip_rules) > 0
                    
                    # Check if portal is in a VPC (more secure than public)
                    vpc_configured = bool(vpc_id and subnet_ids)
                    
                    portal_network_status.append({
                        'portal_id': portal_id,
                        'portal_arn': portal['portalArn'],
                        'vpc_id': vpc_id,
                        'subnet_ids': subnet_ids,
                        'security_group_ids': security_group_ids,
                        'vpc_configured': vpc_configured,
                        'ip_rules': ip_rules,
                        'ip_restrictions_enabled': ip_restrictions_enabled,
                        'network_restrictions_configured': vpc_configured or ip_restrictions_enabled
                    })
                    
                except Exception as e:
                    portal_network_status.append({
                        'portal_id': portal_id,
                        'portal_arn': portal['portalArn'],
                        'error': str(e),
                        'network_restrictions_configured': False
                    })
            
            # Determine overall status
            properly_configured = [p for p in portal_network_status if p.get('network_restrictions_configured', False)]
            vpc_configured = [p for p in portal_network_status if p.get('vpc_configured', False)]
            ip_restricted = [p for p in portal_network_status if p.get('ip_restrictions_enabled', False)]
            
            if len(properly_configured) == len(portal_network_status) and len(portal_network_status) > 0:
                status = "PASS"
                message = f"All {len(portal_network_status)} WorkSpaces Web portals have network restrictions configured"
            elif len(properly_configured) > 0:
                status = "WARN"
                message = f"{len(properly_configured)} out of {len(portal_network_status)} portals have network restrictions configured"
            else:
                status = "FAIL"
                message = "No WorkSpaces Web portals have network restrictions configured"
            
            return {
                'check_id': check_id,
                'check_title': check_title,
                'status': status,
                'message': message,
                'details': {
                    'portals': portal_network_status,
                    'total_portals': len(portal_network_status),
                    'properly_configured': len(properly_configured),
                    'vpc_configured': len(vpc_configured),
                    'ip_restricted': len(ip_restricted)
                },
                'recommendation': 'Configure VPC and/or IP access restrictions for all WorkSpaces Web portals'
            }
            
        except Exception as e:
            return {
                'check_id': check_id,
                'check_title': check_title,
                'status': "ERROR",
                'message': f"Error checking WorkSpaces Web network restrictions: {str(e)}",
                'details': {},
                'recommendation': 'Review WorkSpaces Web network configuration and enable proper restrictions'
            }
    
    def run_checks(self) -> List[Dict[str, Any]]:
        """
        Run all WorkSpaces Web security checks
        
        Returns:
            List of check results
        """
        if self.use_mock:
            return self._get_mock_findings()
        
        checks = [
            self.check_workspaces_web_authentication(),
            self.check_workspaces_web_network_restrictions()
        ]
        
        return checks
    
    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """
        Get mock findings for WorkSpaces Web
        
        Returns:
            List of mock findings
        """
        return [
            self.create_finding(
                check_id="workspaces_web_3.1",
                title="Ensure WorkSpaces Web portal is configured with proper authentication",
                severity="MEDIUM",
                status="WARNING",
                resource_id="aws:workspaces-web:authentication",
                description="WorkSpaces Web authentication configuration needs review",
                recommendation="Configure proper identity providers for WorkSpaces Web portals",
                compliance_standard="CIS AWS End User Compute Services Benchmark v1.2.0"
            )
        ]
