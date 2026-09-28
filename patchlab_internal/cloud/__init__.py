"""Cloud providers: test patches on clones of real AWS, Azure, GCP and OCI assets."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import CLI, CloudError, CloudSandbox

if TYPE_CHECKING:
    from ..config import Config
    from ..runner import TargetRun

CLOUD_PROVIDERS = ("aws", "azure", "gcp", "oci")


def provider_class(name: str):
    if name == "aws":
        from .aws import AWSProvider
        return AWSProvider
    if name == "azure":
        from .azure import AzureProvider
        return AzureProvider
    if name == "gcp":
        from .gcp import GCPProvider
        return GCPProvider
    if name == "oci":
        from .oci import OCIProvider
        return OCIProvider
    raise ValueError(f"unknown cloud provider {name}")


class CloudOps:
    """Cloud lifecycle shared by the Linux and Windows platforms."""

    def __init__(self, cfg: "Config", cli_factory=CLI):
        self.cfg = cfg
        self.name = cfg.sandbox.provider
        self.cli_factory = cli_factory

    def provider(self, log_path=None):
        return provider_class(self.name)(self.cfg.sandbox.provider_options, self.cli_factory(log_path))

    def available(self) -> str | None:
        return self.provider().check()

    def provision(self, tr: "TargetRun", expected_os: str) -> None:
        sb = self.cfg.sandbox
        with tr.stage("clone") as st:
            prov = self.provider(tr.logdir / f"{self.name}-cli.log")
            name = tr.sandbox_name(60)
            tr.box = CloudSandbox(prov, tr.image, name, tr.run_id, expected_os,
                                  clone_timeout=float(sb.provider_options.get("clone_timeout", 3600)))
            tr.box.start(cancel=tr.cancel)
            st.detail = f"{name}: clone of {tr.image} ({self.name} {tr.box.clone.instance})"
        with tr.stage("boot") as st:
            secs = tr.box.wait_ready(sb.boot_timeout, cancel=tr.cancel)
            st.detail = f"clone answering commands after {secs:.0f}s"

    def leftovers(self, run_id: str) -> list[str]:
        return self.provider().list_clones(run_id)

    def remove(self, names: list[str]) -> None:
        prov = self.provider()
        for n in names:
            prov.destroy_named(n)

    def gc(self, run_id: str | None = None, include_cache: bool = False) -> str:
        names = self.provider().list_clones(run_id)
        self.remove(names)
        return f"removed {len(names)} {self.name} clone(s)" + (f": {', '.join(names)}" if names else "")

    def debug_hint(self, name: str) -> str:
        return {
            "aws": f"aws ssm start-session --target <instance id tagged Name={name}>",
            "azure": f"az vm run-command invoke / Bastion in resource group {name}",
            "gcp": f"gcloud compute ssh {name} --tunnel-through-iap",
            "oci": f"OCI console > Compute > Instances > {name} (Run Command / console connection)",
        }[self.name]


__all__ = ["CLI", "CLOUD_PROVIDERS", "CloudError", "CloudOps", "CloudSandbox", "provider_class"]
