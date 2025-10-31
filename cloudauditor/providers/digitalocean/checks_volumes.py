from typing import Dict, List, Any
from cloudauditor.providers.digitalocean.base_checker import BaseDOChecker


class VolumesChecker(BaseDOChecker):
    def run_checks(self) -> List[Dict[str, Any]]:
        if self.use_mock:
            return self._get_mock_findings()
        return []

    def _get_mock_findings(self) -> List[Dict[str, Any]]:
        cs = "CIS DigitalOcean Services Benchmark v1.0.0"
        return [
            self.create_finding(
                check_id="do_svc_6.1",
                title="Ensure Drive is Encrypted with LUKS on Top of Volume (Manual)",
                severity="MEDIUM",
                status="WARNING",
                resource_id="digitalocean:volume:luks",
                description="Attached block volume is not encrypted with LUKS at the filesystem layer.",
                recommendation="Configure LUKS on the block device and mount via crypttab/fstab.",
                command="cryptsetup status secure-volume; lsblk -f",
                evidence={"luks": False},
                compliance_standard=cs,
            ),
        ]


