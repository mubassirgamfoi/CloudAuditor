"""
AWS End User Compute Services Benchmark Implementation

This module implements the CIS AWS End User Compute Services Benchmark v1.2.0
covering WorkSpaces, WorkSpaces Web, WorkDocs, and AppStream 2.0.
"""

from .base_checker import EndUserComputeChecker
from .workspaces_checks import WorkSpacesChecker
from .workspaces_web_checks import WorkSpacesWebChecker
from .workdocs_checks import WorkDocsChecker
from .appstream_checks import AppStreamChecker

__all__ = [
    'EndUserComputeChecker',
    'WorkSpacesChecker', 
    'WorkSpacesWebChecker',
    'WorkDocsChecker',
    'AppStreamChecker'
]
