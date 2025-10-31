from typing import Dict, List, Any
from cloudauditor.providers.digitalocean.base_checker import BaseDOChecker


class SpacesChecker(BaseDOChecker):
    def run_checks(self) -> List[Dict[str, Any]]:
        if self.use_mock:
            return self._get_mock_findings()
        return []

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        cs = "CIS DigitalOcean Services Benchmark v1.0.0"
        return [
            self.create_finding(
                check_id="do_svc_5.1",
                title="Ensure Access Control to Spaces are Set (Manual)",
                severity="HIGH",
                status="WARNING",
                resource_id="digitalocean:spaces:access-control",
                description="Spaces access controls require review for least privilege.",
                recommendation="Use Limited access keys and Teams appropriately; review bucket permissions.",
                command="(UI) Spaces → Access Keys; review bucket permissions",
                evidence={"accessKeys": [{"name": "full-access-key", "scope": "full"}]},
                compliance_standard=cs,
            ),
            self.create_finding(
                check_id="do_svc_5.2",
                title="Ensure Access and Secret Keys are Created (Manual)",
                severity="LOW",
                status="WARNING",
                resource_id="digitalocean:spaces:keys",
                description="Spaces access keys not provisioned for required automation.",
                recommendation="Create appropriately scoped access/secret keys and store securely.",
                command="(UI) Spaces → Access Keys → Create Access Key",
                evidence={"keysPresent": False},
                compliance_standard=cs,
            ),
            self.create_finding(
                check_id="do_svc_5.3",
                title="Ensure Spaces Bucket Lifecycle Policy is Set (Automated)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="digitalocean:spaces:lifecycle",
                description="No lifecycle policy configured for Spaces bucket.",
                recommendation="Configure lifecycle to expire objects and remove incomplete multipart uploads.",
                command="s3cmd getlifecycle s3://<space>; s3cmd expire --expiry-days=30 s3://<space>",
                evidence={"lifecycleConfigured": False},
                compliance_standard=cs,
            ),
            self.create_finding(
                check_id="do_svc_5.4",
                title="Ensure File Listing Permissions are Set (Manual)",
                severity="HIGH",
                status="FAILED",
                resource_id="digitalocean:spaces:file-listing",
                description="Bucket file listing is Public.",
                recommendation="Set file listing to Private in bucket settings.",
                command="(UI) Spaces → Bucket → Settings → File Listing",
                evidence={"fileListing": "Public"},
                compliance_standard=cs,
            ),
            self.create_finding(
                check_id="do_svc_5.5",
                title="Ensure Spaces CDN is Enabled (Manual)",
                severity="LOW",
                status="WARNING",
                resource_id="digitalocean:spaces:cdn",
                description="Spaces CDN is not enabled for performance and resilience.",
                recommendation="Enable CDN and configure appropriate Edge Cache TTL.",
                command="(UI) Spaces → Bucket → Settings → CDN → Enable",
                evidence={"cdnEnabled": False},
                compliance_standard=cs,
            ),
            self.create_finding(
                check_id="do_svc_5.6",
                title="Ensure CORS is Enabled (Manual)",
                severity="LOW",
                status="WARNING",
                resource_id="digitalocean:spaces:cors",
                description="CORS not configured for required cross-origin access.",
                recommendation="Configure CORS rules via UI or s3cmd setcors with appropriate origins/methods.",
                command="s3cmd setcors /path/to/config.xml s3://BUCKET_NAME",
                evidence={"corsConfigured": False},
                compliance_standard=cs,
            ),
            self.create_finding(
                check_id="do_svc_5.7",
                title="Ensure Unneeded Spaces Bucket are Destroyed (Manual)",
                severity="LOW",
                status="WARNING",
                resource_id="digitalocean:spaces:bucket-destruction",
                description="Stale Spaces bucket found that is no longer needed.",
                recommendation="Schedule bucket for destruction or cancel if needed.",
                command="(UI) Spaces → Bucket → Settings → Destroy this Space",
                evidence={"bucketStatus": "active", "lastAccessedDays": 240},
                compliance_standard=cs,
            ),
        ]


