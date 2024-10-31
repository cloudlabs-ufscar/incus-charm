#!/usr/bin/env python3
# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.

"""Charm the application."""

import logging
from typing import List, Optional, Union

import charms.data_platform_libs.v0.data_models as data_models
import charms.operator_libs_linux.v0.apt as apt
import ops
import requests
import yaml
from pydantic import ValidationError, field_validator

import incus

logger = logging.getLogger(__name__)


class IncusConfig(data_models.BaseConfigModel):
    """The Incus charm configuration."""

    server_port: int


class AddTrustedCertificateActionParams(data_models.BaseConfigModel):
    """Parameters for the add-trusted-certificate action."""

    cert: str
    name: Optional[str] = None
    projects: Optional[List[str]] = None

    @field_validator("projects", mode="before")
    @classmethod
    def split_projects(cls, value):
        """Split a comma separated string of projects into a list."""
        if isinstance(value, str):
            return [project.strip() for project in value.split(",")]
        return value

    @field_validator("cert")
    @classmethod
    def validate_cert(cls, cert: str):
        """Validate that `cert` is a valid PEM encoded x509 certificate."""
        cert = cert.strip()
        begin_mark = "-----BEGIN CERTIFICATE-----"
        end_mark = "-----END CERTIFICATE-----"
        if not cert.startswith(begin_mark) or not cert.endswith(end_mark):
            raise ValueError("value is not a valid x509 certificate")

        # NOTE: the certificate from the action parameters contains spaces
        # instead of newlines, so we need to reconstruct the certificate in
        # the appropriate format
        return "\n".join(cert.replace(" CERTIFICATE-", "CERTIFICATE-").split()).replace(
            "CERTIFICATE-", " CERTIFICATE-"
        )


class IncusCharm(data_models.TypedCharmBase[IncusConfig]):
    """Charm the Incus application."""

    package_name = "incus"
    config_type = IncusConfig

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)

        # Events
        framework.observe(self.on.collect_unit_status, self.on_collect_unit_status)
        framework.observe(self.on.install, self.on_install)
        framework.observe(self.on.config_changed, self.on_config_changed)
        framework.observe(self.on.start, self.on_start)

        # Actions
        framework.observe(
            self.on.add_trusted_certificate_action, self.add_trusted_certificate_action
        )

    def on_collect_unit_status(self, event: ops.CollectStatusEvent):
        """Handle collect unit status event."""
        if not self._package_installed:
            event.add_status(ops.BlockedStatus(f"Package '{self.package_name}' not installed"))
        event.add_status(ops.ActiveStatus("Unit is ready"))

    def on_install(self, event: ops.InstallEvent):
        """Handle install event."""
        self.unit.status = ops.MaintenanceStatus("Installing packages")
        # TODO: make the repository and gpg key configurable
        self._add_apt_repository(
            repository_line="deb https://pkgs.zabbly.com/incus/stable jammy main",
            gpg_key_url="https://pkgs.zabbly.com/key.asc",
        )
        self._install_package()
        self.unit.set_workload_version(self._package_version)

    def on_config_changed(self, event: ops.ConfigChangedEvent):
        """Handle config changed event."""
        self.unit.status = ops.MaintenanceStatus("Changing config")
        port = self.config.server_port
        public_address = ""
        public_binding = self.model.get_binding("public")
        if public_binding and public_binding.network.bind_address:
            public_address = str(public_binding.network.bind_address)
        incus.set_config("core.https_address", f"{public_address}:{port}")
        self.unit.set_ports(ops.Port("tcp", port))

    def on_start(self, event: ops.StartEvent):
        """Handle start event."""
        self.unit.status = ops.MaintenanceStatus("Bootstrapping Incus")
        self._bootstrap_incus()
        self.unit.status = ops.ActiveStatus("Unit is ready")

    @data_models.validate_params(AddTrustedCertificateActionParams)
    def add_trusted_certificate_action(
        self: ops.CharmBase,
        event: ops.ActionEvent,
        params: Union[AddTrustedCertificateActionParams, ValidationError],
    ):
        """Handle the add-trusted-certificate action."""
        if isinstance(params, ValidationError):
            return event.fail(str(params))
        self.unit.status = ops.MaintenanceStatus("Adding trusted certificate")
        logger.debug(
            "Adding trusted certificate. cert=%s projects=%s name=%s",
            params.cert,
            params.projects,
            params.name,
        )
        try:
            incus.add_trusted_certificate(
                cert=params.cert,
                type="client",
                projects=params.projects,
                name=params.name,
            )
            event.set_results({"result": "Certificate added to Incus truststore"})
        except incus.IncusProcessError as e:
            event.fail(str(e))

    @property
    def _package_installed(self) -> bool:
        package = apt.DebianPackage.from_system(self.package_name)
        return package.present

    @property
    def _package_version(self) -> str:
        package = apt.DebianPackage.from_system(self.package_name)
        if not package.present:
            return ""
        package_version = package.version.number
        # NOTE: deb packages usually are composed of the upstream version with the debian
        # revision appended after an "-" (e.g. 6.6-ubuntu22.04-202410031532). We choose to
        # only display the upstream version to the operator.
        if "-" in package_version:
            return package_version.split("-")[0]
        return package_version

    def _install_package(self):
        """Installs the `incus` package on the system."""
        logging.info("Installing package. package_name=%s", self.package_name)
        try:
            apt.update()
            package = apt.DebianPackage.from_system(self.package_name)
            package.ensure(apt.PackageState.Present)
            package_version = package.version.number
            logger.info(
                "Installed package. package_name=%s package_version=%s",
                self.package_name,
                package_version,
            )
        except apt.PackageNotFoundError:
            logger.warning("Package not found in repositories. package_name=%s", self.package_name)
        except apt.PackageError as e:
            logger.error(
                "Error when installing package. package_name=%s error=%s",
                self.package_name,
                e,
            )
            raise e

    def _add_apt_repository(self, repository_line: str, gpg_key_url: Optional[str] = None):
        """Add the apt repository defined by `repository_line` and optionally retrieve its GPG key from `gpg_key_url`."""
        logger.info(
            "Adding apt repository. repository_line=%s gpg_key_url=%s",
            repository_line,
            gpg_key_url,
        )
        repositories = apt.RepositoryMapping()
        key = None
        if gpg_key_url:
            logger.debug("Downloading repository GPG key. gpg_key_url=%s", gpg_key_url)
            key = requests.get(gpg_key_url).content.decode()
            logger.debug("Downloaded repository GPG key. key=%s", key)

        repository = apt.DebianRepository.from_repo_line(repository_line)
        if key:
            repository.import_key(key)
        logger.debug("Created apt repository.")
        repositories.add(repository)
        logger.info(
            "Repository added. repository_line=%s gpg_key_url=%s",
            repository_line,
            gpg_key_url,
        )

    def _bootstrap_incus(self):
        """Bootstraps the Incus server via `incus admin init`."""
        logger.info("Bootstrapping Incus")

        preseed = {
            # TODO: make the creation of networks configurable
            "networks": [
                {
                    "name": "incusbr0",
                    "description": "Default network",
                    "type": "",
                    "project": "default",
                    "config": {
                        "ipv4.address": "auto",
                        "ipv6.address": "auto",
                    },
                },
            ],
            # TODO: make the creation of storage pools configurable
            "storage_pools": [
                {
                    "name": "default",
                    "description": "Default storage pool",
                    "driver": "btrfs",
                    "config": {"size": "5GiB"},
                },
            ],
            "profiles": [
                {
                    "name": "default",
                    "description": "Default profile",
                    "config": {},
                    "devices": {
                        "eth0": {
                            "name": "eth0",
                            "network": "incusbr0",
                            "type": "nic",
                        },
                        "root": {
                            "path": "/",
                            "pool": "default",
                            "type": "disk",
                        },
                    },
                },
            ],
            "projects": [],
            "cluster": None,
        }
        incus.run_command("admin", "init", "--preseed", input=yaml.dump(preseed))
        logger.info("Incus server bootstrapped")


if __name__ == "__main__":  # pragma: nocover
    ops.main(IncusCharm)  # type: ignore
