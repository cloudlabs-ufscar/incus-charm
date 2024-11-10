#!/usr/bin/env python3
# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.

"""Charm the application."""

import json
import logging
import socket
from typing import Dict, List, Optional, Union, cast

import charms.data_platform_libs.v0.data_models as data_models
import charms.operator_libs_linux.v0.apt as apt
import ops
import requests
from pydantic import ValidationError, validator

import incus

logger = logging.getLogger(__name__)


class ClusterAppData(data_models.BaseConfigModel):
    """The application data in the cluster relation."""

    tokens: Dict[str, str]


class ClusterUnitData(data_models.BaseConfigModel):
    """The unit data in the cluster relation."""

    node_name: str


class IncusConfig(data_models.BaseConfigModel):
    """The Incus charm configuration."""

    server_port: int
    cluster_port: int

    @validator("server_port", "cluster_port")
    @classmethod
    def validate_port(cls, port: int) -> int:
        """Validate that the given `port` is within a valid range."""
        max_port_number = 65535
        if not (0 <= port <= max_port_number):
            raise ValueError("A port value should be an integer between 0 and 65535")
        return port


class ClusterListActionParams(data_models.BaseConfigModel):
    """Parameters for the cluster-list action."""

    format: incus.CLIFormats


class AddTrustedCertificateActionParams(data_models.BaseConfigModel):
    """Parameters for the add-trusted-certificate action."""

    cert: str
    name: Optional[str] = None
    projects: Optional[List[str]] = None

    @validator("projects", pre=True)
    @classmethod
    def split_projects(cls, value):
        """Split a comma separated string of projects into a list."""
        if isinstance(value, str):
            return [project.strip() for project in value.split(",")]
        return value

    @validator("cert")
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
        framework.observe(self.on.stop, self.on_stop)
        framework.observe(self.on.cluster_relation_created, self.on_cluster_relation_created)
        framework.observe(self.on.cluster_relation_changed, self.on_cluster_relation_changed)

        # Actions
        framework.observe(
            self.on.add_trusted_certificate_action, self.add_trusted_certificate_action
        )
        framework.observe(self.on.cluster_list_action, self.cluster_list_action)

    def on_collect_unit_status(self, event: ops.CollectStatusEvent):
        """Handle collect unit status event."""
        if not self._package_installed:
            event.add_status(ops.BlockedStatus(f"Package '{self.package_name}' not installed"))
            return

        is_clustered = incus.is_clustered()
        if not self.unit.is_leader() and not is_clustered:
            event.add_status(ops.WaitingStatus("Waiting for cluster token"))
            return
        if not is_clustered:
            event.add_status(ops.ActiveStatus("Unit is ready"))
            return

        info = incus.get_cluster_member_info(self._node_name)
        if info.status == incus.ClusterMemberStatus.EVACUATED:
            event.add_status(ops.MaintenanceStatus(f"Evacuated: {info.message}"))
            return
        if info.status == incus.ClusterMemberStatus.ONLINE:
            event.add_status(ops.ActiveStatus(f"Online: {info.message}"))
            return
        event.add_status(ops.BlockedStatus(f"{info.status.value}: {info.message}"))

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

        public_address = ""
        server_port = self.config.server_port
        public_binding = self.model.get_binding("public")
        if public_binding and public_binding.network.bind_address:
            public_address = str(public_binding.network.bind_address)
        incus.set_config("core.https_address", f"{public_address}:{server_port}")
        self.unit.set_ports(ops.Port("tcp", server_port))

        # NOTE: Incus does not support changing the cluster.https_address if the
        # server is already part of a cluster.
        if not incus.is_clustered():
            incus.set_config("cluster.https_address", self._cluster_address)

    def on_start(self, event: ops.StartEvent):
        """Handle start event."""
        if self.unit.is_leader():
            self._bootstrap_incus()

    def on_stop(self, event: ops.StopEvent):
        """Handle stop event."""
        if incus.is_clustered():
            self.unit.status = ops.MaintenanceStatus("Evacuating node")
            logger.info("Evacuating cluster member. node_name=%s", self._node_name)
            incus.evacuate_node(self._node_name)

            self.unit.status = ops.MaintenanceStatus("Leaving cluster")
            logger.info("Leaving cluster. node_name=%s", self._node_name)
            incus.remove_cluster_member(self._node_name)

        self.unit.status = ops.MaintenanceStatus("Uninstalling packages")
        self._uninstall_package()

    def on_cluster_relation_created(self, event: ops.RelationCreatedEvent):
        """Handle cluster relation created event."""
        event.relation.data[self.unit]["node-name"] = self._node_name
        if self.unit.is_leader():
            event.relation.data[event.app]["tokens"] = json.dumps({})

    @data_models.parse_relation_data(app_model=ClusterAppData, unit_model=ClusterUnitData)
    def on_cluster_relation_changed(
        self: ops.CharmBase,
        event: ops.RelationEvent,
        app_data: Optional[Union[ClusterAppData, ValidationError]] = None,
        unit_data: Optional[Union[ClusterUnitData, ValidationError]] = None,
    ):
        """Handle cluster relation changed event."""
        # HACK: the typings for the `data_models` library are a bit broken, so we have
        # to declare `self` as `ops.CharmBase` and then cast it back to `IncusCharm`.
        self = cast(IncusCharm, self)
        if app_data is None:
            logger.warning("No app data available. event=%s", event)
            return
        if isinstance(app_data, ValidationError):
            logger.warning("Invalid app data. event=%s validation_error=%s", event, str(app_data))
            return

        if self.unit.is_leader():
            if unit_data is None:
                logger.warning("No unit data available. event=%s", event)
                return
            if isinstance(unit_data, ValidationError):
                logger.warning(
                    "Invalid unit data. event=%s validation_error=%s", event, str(unit_data)
                )
                return
            if not incus.is_clustered():
                self.unit.status = ops.MaintenanceStatus("Enabling clustering")
                logger.info("Node has not enabled clustering. Will enable it.")
                incus.enable_clustering(self._node_name)

            node_name = unit_data.node_name
            if node_name in app_data.tokens:
                logger.debug("Token already generated for node. node_name=%s", node_name)
                return

            self.unit.status = ops.MaintenanceStatus(f"Creating join token for {node_name}")
            logger.info(
                "Creating join token for unit. unit=%s node_name=%s",
                event.unit,
                node_name,
            )
            join_token = incus.create_join_token(node_name)
            secret = self.app.add_secret({"token": join_token}, label=f"{node_name}-join-token")
            assert secret.id, f"Generated secret does not have a valid ID. secret={secret}"
            app_data.tokens[node_name] = secret.id
            event.relation.data[event.app]["tokens"] = json.dumps(app_data.tokens)
            logger.info("Join token created.")
        else:
            if incus.is_clustered():
                return
            node_name = self._node_name
            logger.debug(
                "Checking if secret ID for join token is available in application data. node_name=%s app_data=%s",
                node_name,
                app_data,
            )
            secret_id = app_data.tokens.get(node_name)
            if not secret_id:
                logger.debug("Secret ID not found in app data.")
                return

            logger.info(
                "Secret ID found in app data. Will fetch token from it and join the cluster. secret_id=%s",
                secret_id,
            )
            secret = self.model.get_secret(id=secret_id)
            logger.debug("Got secret with join token from model.")
            token = secret.get_content().get("token")
            assert token, "Join token secret has an invalid content."
            self._bootstrap_incus(token)

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

    @data_models.validate_params(ClusterListActionParams)
    def cluster_list_action(
        self: ops.CharmBase,
        event: ops.ActionEvent,
        params: Union[ClusterListActionParams, ValidationError],
    ):
        """Handle the cluster-list action."""
        try:
            if not incus.is_clustered():
                return event.fail("Unit is not clustered")

            if isinstance(params, ValidationError):
                return event.fail(str(params))

            result = incus.cluster_list(format=params.format)
            event.set_results({"result": result})
        except incus.IncusProcessError as e:
            event.fail(str(e))

    @property
    def _cluster_address(self) -> str:
        cluster_address = ""
        cluster_port = self.config.cluster_port
        cluster_binding = self.model.get_binding("cluster")
        if cluster_binding and cluster_binding.network.bind_address:
            cluster_address = str(cluster_binding.network.bind_address)
        return f"{cluster_address}:{cluster_port}"

    @property
    def _node_name(self) -> str:
        return socket.gethostname()

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
        """Install the `incus` package on the system."""
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

    def _uninstall_package(self):
        """Uninstall the `incus` package on the system."""
        logging.info("Uninstalling package. package_name=%s", self.package_name)
        try:
            apt.update()
            package = apt.DebianPackage.from_system(self.package_name)
            package.ensure(apt.PackageState.Absent)
            logger.info("Uninstalled package. package_name=%s", self.package_name)
        except apt.PackageNotFoundError:
            logger.warning("Package not found in repositories. package_name=%s", self.package_name)
        except apt.PackageError as e:
            logger.error(
                "Error when uninstalling package. package_name=%s error=%s",
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

    def _bootstrap_incus(self, join_token: Optional[str] = None):
        """Bootstraps the Incus server via `incus admin init`.

        If `join_token` is provided, joins an existing cluster.
        """
        self.unit.status = ops.MaintenanceStatus("Bootstrapping Incus")
        logger.info("Bootstrapping Incus")
        cluster_info = (
            None
            if join_token is None
            else {
                "enabled": True,
                "cluster_token": join_token,
                "server_address": self._cluster_address,
            }
        )
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
            "cluster": cluster_info,
        }
        incus.bootstrap_node(preseed)
        logger.info("Incus server bootstrapped")


if __name__ == "__main__":  # pragma: nocover
    ops.main(IncusCharm)  # type: ignore
