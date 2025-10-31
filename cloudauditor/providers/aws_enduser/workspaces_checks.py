"""
WorkSpaces Security Checks

This module implements WorkSpaces specific security checks from the
CIS AWS End User Compute Services Benchmark v1.2.0
"""

import boto3
from typing import Dict, List, Any, Optional
from ..aws_checks.base_checker import BaseAWSChecker


class WorkSpacesChecker(BaseAWSChecker):
    """
    WorkSpaces security checker implementation
    
    Implements WorkSpaces specific checks from CIS AWS End User Compute
    Services Benchmark v1.2.0
    """
    
    def __init__(self, session: boto3.Session, region: str = 'us-east-1', use_mock: bool = True):
        """Initialize WorkSpaces checker"""
        super().__init__(session, region, use_mock)
        self.service_name = "WorkSpaces"
        
        # Initialize service clients
        if session:
            self.workspaces_client = session.client('workspaces', region_name=region)
            self.iam_client = session.client('iam', region_name=region)
            self.ds_client = session.client('ds', region_name=region)
            self.kms_client = session.client('kms', region_name=region)
    
    def check_workspaces_administration_iam(self) -> Dict[str, Any]:
        """
        Check 2.1: Ensure Administration of WorkSpaces is defined using IAM
        
        Returns:
            Check result dictionary
        """
        check_id = "workspaces_2.1"
        check_title = "Ensure Administration of WorkSpaces is defined using IAM"
        
        try:
            # Check for IAM policies that grant WorkSpaces administration permissions
            workspaces_admin_policies = []
            
            # Check for AWS managed policy
            try:
                response = self.iam_client.get_policy(
                    PolicyArn='arn:aws:iam::aws:policy/AmazonWorkSpacesAdmin'
                )
                workspaces_admin_policies.append({
                    'policy_arn': response['Policy']['Arn'],
                    'policy_name': response['Policy']['PolicyName'],
                    'type': 'AWS Managed'
                })
            except self.iam_client.exceptions.NoSuchEntityException:
                pass
            
            # Check for custom policies with WorkSpaces permissions
            paginator = self.iam_client.get_paginator('list_policies')
            for page in paginator.paginate(Scope='Local'):
                for policy in page['Policies']:
                    try:
                        policy_version = self.iam_client.get_policy_version(
                            PolicyArn=policy['Arn'],
                            VersionId=policy['DefaultVersionId']
                        )
                        policy_doc = policy_version['PolicyVersion']['Document']
                        
                        # Check if policy contains WorkSpaces permissions
                        if self._policy_contains_workspaces_permissions(policy_doc):
                            workspaces_admin_policies.append({
                                'policy_arn': policy['Arn'],
                                'policy_name': policy['PolicyName'],
                                'type': 'Custom'
                            })
                    except Exception:
                        continue
            
            # Check which roles/users/groups have these policies attached
            attached_entities = []
            for policy in workspaces_admin_policies:
                # Check roles
                try:
                    roles = self.iam_client.list_entities_for_policy(
                        PolicyArn=policy['policy_arn'],
                        EntityFilter='Role'
                    )
                    for role in roles['PolicyRoles']:
                        attached_entities.append({
                            'entity_type': 'Role',
                            'entity_name': role['RoleName'],
                            'policy_name': policy['policy_name']
                        })
                except Exception:
                    pass
                
                # Check users
                try:
                    users = self.iam_client.list_entities_for_policy(
                        PolicyArn=policy['policy_arn'],
                        EntityFilter='User'
                    )
                    for user in users['PolicyUsers']:
                        attached_entities.append({
                            'entity_type': 'User',
                            'entity_name': user['UserName'],
                            'policy_name': policy['policy_name']
                        })
                except Exception:
                    pass
                
                # Check groups
                try:
                    groups = self.iam_client.list_entities_for_policy(
                        PolicyArn=policy['policy_arn'],
                        EntityFilter='Group'
                    )
                    for group in groups['PolicyGroups']:
                        attached_entities.append({
                            'entity_type': 'Group',
                            'entity_name': group['GroupName'],
                            'policy_name': policy['policy_name']
                        })
                except Exception:
                    pass
            
            if attached_entities:
                status = "PASS"
                message = f"Found {len(attached_entities)} IAM entities with WorkSpaces administration permissions"
            else:
                status = "FAIL"
                message = "No IAM entities found with WorkSpaces administration permissions"
            
            return {
                'check_id': check_id,
                'check_title': check_title,
                'status': status,
                'message': message,
                'details': {
                    'workspaces_policies': workspaces_admin_policies,
                    'attached_entities': attached_entities
                },
                'recommendation': 'Ensure IAM principals (users, roles, groups) have appropriate WorkSpaces administration policies attached'
            }
            
        except Exception as e:
            return {
                'check_id': check_id,
                'check_title': check_title,
                'status': "ERROR",
                'message': f"Error checking WorkSpaces IAM administration: {str(e)}",
                'details': {},
                'recommendation': 'Review IAM configuration and ensure proper WorkSpaces permissions are granted'
            }
    
    def check_workspaces_mfa_enabled(self) -> Dict[str, Any]:
        """
        Check 2.2: Ensure MFA is enabled for WorkSpaces users
        
        Returns:
            Check result dictionary
        """
        check_id = "workspaces_2.2"
        check_title = "Ensure MFA is enabled for WorkSpaces users"
        
        try:
            # Get WorkSpaces directories
            directories = []
            try:
                response = self.workspaces_client.describe_workspace_directories()
                directories = response.get('Directories', [])
            except Exception as e:
                return {
                    'check_id': check_id,
                    'check_title': check_title,
                    'status': "ERROR",
                    'message': f"Error retrieving WorkSpaces directories: {str(e)}",
                    'details': {},
                    'recommendation': 'Ensure WorkSpaces directories are properly configured'
                }
            
            mfa_status = []
            for directory in directories:
                directory_id = directory['DirectoryId']
                directory_type = directory.get('DirectoryType', 'Unknown')
                
                # Check MFA configuration for different directory types
                if directory_type == 'AD_CONNECTOR':
                    # For AD Connector, check Directory Service
                    try:
                        ds_response = self.ds_client.describe_directories(
                            DirectoryIds=[directory_id]
                        )
                        if ds_response['DirectoryDescriptions']:
                            ds_directory = ds_response['DirectoryDescriptions'][0]
                            mfa_enabled = ds_directory.get('RadiusSettings', {}).get('RadiusStatus') == 'Enabled'
                            mfa_status.append({
                                'directory_id': directory_id,
                                'directory_type': directory_type,
                                'mfa_enabled': mfa_enabled,
                                'radius_status': ds_directory.get('RadiusSettings', {}).get('RadiusStatus', 'Not Configured')
                            })
                    except Exception as e:
                        mfa_status.append({
                            'directory_id': directory_id,
                            'directory_type': directory_type,
                            'mfa_enabled': False,
                            'error': str(e)
                        })
                elif directory_type == 'SIMPLE_AD':
                    # Simple AD doesn't support MFA
                    mfa_status.append({
                        'directory_id': directory_id,
                        'directory_type': directory_type,
                        'mfa_enabled': False,
                        'note': 'Simple AD does not support MFA'
                    })
                else:
                    # For other directory types, check if MFA is configured
                    mfa_status.append({
                        'directory_id': directory_id,
                        'directory_type': directory_type,
                        'mfa_enabled': False,
                        'note': 'MFA configuration not available for this directory type'
                    })
            
            # Determine overall status
            directories_with_mfa = [d for d in mfa_status if d.get('mfa_enabled', False)]
            
            if directories_with_mfa:
                status = "PASS"
                message = f"MFA is enabled for {len(directories_with_mfa)} out of {len(mfa_status)} WorkSpaces directories"
            else:
                status = "FAIL"
                message = "MFA is not enabled for any WorkSpaces directories"
            
            return {
                'check_id': check_id,
                'check_title': check_title,
                'status': status,
                'message': message,
                'details': {
                    'directories': mfa_status,
                    'total_directories': len(mfa_status),
                    'directories_with_mfa': len(directories_with_mfa)
                },
                'recommendation': 'Enable MFA for WorkSpaces directories using RADIUS server configuration'
            }
            
        except Exception as e:
            return {
                'check_id': check_id,
                'check_title': check_title,
                'status': "ERROR",
                'message': f"Error checking WorkSpaces MFA configuration: {str(e)}",
                'details': {},
                'recommendation': 'Review WorkSpaces directory configuration and enable MFA'
            }
    
    def check_workspaces_volumes_encrypted(self) -> Dict[str, Any]:
        """
        Check 2.3: Ensure WorkSpace volumes are encrypted
        
        Returns:
            Check result dictionary
        """
        check_id = "workspaces_2.3"
        check_title = "Ensure WorkSpace volumes are encrypted"
        
        try:
            # Get all WorkSpaces
            workspaces = []
            try:
                response = self.workspaces_client.describe_workspaces()
                workspaces = response.get('Workspaces', [])
            except Exception as e:
                return {
                    'check_id': check_id,
                    'check_title': check_title,
                    'status': "ERROR",
                    'message': f"Error retrieving WorkSpaces: {str(e)}",
                    'details': {},
                    'recommendation': 'Ensure WorkSpaces are properly configured'
                }
            
            encryption_status = []
            for workspace in workspaces:
                workspace_id = workspace['WorkspaceId']
                user_name = workspace.get('UserName', 'Unknown')
                bundle_id = workspace.get('BundleId', 'Unknown')
                
                # Check volume encryption status
                root_encrypted = workspace.get('RootVolumeEncryptionEnabled', False)
                user_encrypted = workspace.get('UserVolumeEncryptionEnabled', False)
                
                encryption_status.append({
                    'workspace_id': workspace_id,
                    'user_name': user_name,
                    'bundle_id': bundle_id,
                    'root_volume_encrypted': root_encrypted,
                    'user_volume_encrypted': user_encrypted,
                    'both_volumes_encrypted': root_encrypted and user_encrypted
                })
            
            # Determine overall status
            fully_encrypted = [w for w in encryption_status if w['both_volumes_encrypted']]
            partially_encrypted = [w for w in encryption_status if w['root_volume_encrypted'] or w['user_volume_encrypted']]
            unencrypted = [w for w in encryption_status if not w['root_volume_encrypted'] and not w['user_volume_encrypted']]
            
            if len(fully_encrypted) == len(encryption_status) and len(encryption_status) > 0:
                status = "PASS"
                message = f"All {len(encryption_status)} WorkSpaces have both root and user volumes encrypted"
            elif len(fully_encrypted) > 0:
                status = "WARN"
                message = f"{len(fully_encrypted)} WorkSpaces fully encrypted, {len(partially_encrypted)} partially encrypted, {len(unencrypted)} unencrypted"
            else:
                status = "FAIL"
                message = f"No WorkSpaces have both volumes encrypted. {len(partially_encrypted)} partially encrypted, {len(unencrypted)} unencrypted"
            
            return {
                'check_id': check_id,
                'check_title': check_title,
                'status': status,
                'message': message,
                'details': {
                    'workspaces': encryption_status,
                    'total_workspaces': len(encryption_status),
                    'fully_encrypted': len(fully_encrypted),
                    'partially_encrypted': len(partially_encrypted),
                    'unencrypted': len(unencrypted)
                },
                'recommendation': 'Enable encryption for both root and user volumes on all WorkSpaces'
            }
            
        except Exception as e:
            return {
                'check_id': check_id,
                'check_title': check_title,
                'status': "ERROR",
                'message': f"Error checking WorkSpaces volume encryption: {str(e)}",
                'details': {},
                'recommendation': 'Review WorkSpaces configuration and enable volume encryption'
            }
    
    def _policy_contains_workspaces_permissions(self, policy_doc: Dict[str, Any]) -> bool:
        """
        Check if a policy document contains WorkSpaces permissions
        
        Args:
            policy_doc: IAM policy document
            
        Returns:
            True if policy contains WorkSpaces permissions
        """
        workspaces_actions = [
            'workspaces:',
            'wam:',
            'thinclient:',
            'workspaces-web:'
        ]
        
        if 'Statement' in policy_doc:
            statements = policy_doc['Statement']
            if not isinstance(statements, list):
                statements = [statements]
            
            for statement in statements:
                actions = statement.get('Action', [])
                if not isinstance(actions, list):
                    actions = [actions]
                
                for action in actions:
                    for workspaces_action in workspaces_actions:
                        if workspaces_action in action:
                            return True
        
        return False
    
    def run_checks(self) -> List[Dict[str, Any]]:
        """
        Run all WorkSpaces security checks
        
        Returns:
            List of check results
        """
        if self.use_mock:
            return self._get_mock_findings()
        
        checks = [
            self.check_workspaces_administration_iam(),
            self.check_workspaces_mfa_enabled(),
            self.check_workspaces_volumes_encrypted()
        ]
        
        return checks
    
    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        """
        Get mock findings for WorkSpaces
        
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
            )
        ]
