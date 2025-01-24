#!/usr/bin/env python3
# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.

"""Charm the application."""

import datetime
import json
import logging
import os
import socket
from typing import Any, Dict, List, Optional, Set, Union, cast

import charmhelpers.contrib.storage.linux.ceph as ceph_client
import charms.data_platform_libs.v0.data_models as data_models
import charms.operator_libs_linux.v0.apt as apt
import charms.operator_libs_linux.v1.systemd as systemd
import charms.tls_certificates_interface.v0.tls_certificates as tls_certificates
import ops
import requests
from pydantic import ValidationError, validator

import ceph
import incus

logger = logging.getLogger(__name__)


class ClusterAppData(data_models.RelationDataModel):
    """The application data in the cluster relation."""

    tokens: Dict[str, str]
    cluster_certificate: str
    created_storage: Set[incus.IncusStorageDriver]
    created_network: Set[incus.IncusNetworkDriver]


class ClusterUnitData(data_models.RelationDataModel):
    """The unit data in the cluster relation."""

    node_name: str
    joined_cluster_at: Optional[str]


class CephUnitData(data_models.RelationDataModel, extra="ignore"):
    """The unit data in the ceph relation."""

    key: str
    auth: str
    ceph_public_address: str


class OvnCentralUnitData(data_models.RelationDataModel, extra="ignore"):
    """The unit data in the ovn-central relation."""

    bound_address: str


class IncusConfig(data_models.BaseConfigModel):
    """The Incus charm configuration."""

    server_port: int
    cluster_port: int
    metrics_port: int
    ceph_rbd_features: str
    package_repository: str
    package_repository_gpg_key: str
    set_failure_domain: bool

    @validator("server_port", "cluster_port", "metrics_port")
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
    service_name = "incus"
    ceph_package_name = "ceph-common"

    config_type = IncusConfig

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)

        # Certificate request
        sans = []
        for binding_name in ("public", "cluster"):
            binding = self.model.get_binding(binding_name)
            if binding and binding.network.bind_address:
                sans.append(str(binding.network.bind_address))
        self.tls_certificates = tls_certificates.TLSCertificatesRequires(
            self, common_name=socket.getfqdn(), sans=sans
        )

        # Events
        framework.observe(self.on.collect_unit_status, self.on_collect_unit_status)
        framework.observe(self.on.install, self.on_install)
        framework.observe(self.on.config_changed, self.on_config_changed)
        framework.observe(self.on.start, self.on_start)
        framework.observe(self.on.stop, self.on_stop)
        framework.observe(self.on.cluster_relation_created, self.on_cluster_relation_created)
        framework.observe(self.on.cluster_relation_changed, self.on_cluster_relation_changed)
        framework.observe(
            self.tls_certificates.on.certificate_changed, self.on_certificate_changed
        )
        framework.observe(self.on.ceph_relation_created, self.on_ceph_relation_created)
        framework.observe(self.on.ceph_relation_changed, self.on_ceph_relation_changed)
        framework.observe(self.on.ovsdb_cms_relation_created, self.on_ovsdb_cms_relation_created)
        framework.observe(self.on.ovsdb_cms_relation_changed, self.on_ovsdb_cms_relation_changed)

        # Actions
        framework.observe(
            self.on.add_trusted_certificate_action, self.add_trusted_certificate_action
        )
        framework.observe(self.on.cluster_list_action, self.cluster_list_action)

    def on_collect_unit_status(self, event: ops.CollectStatusEvent):
        """Handle collect-unit-status event.

        Collects the status of the current Incus deployment to present it
        on `juju status` output.
        """
        if not self._package_installed:
            event.add_status(ops.BlockedStatus(f"Package '{self.package_name}' not installed"))
            return

        if self.model.get_relation("certificates") and not self.tls_certificates.certificate:
            event.add_status(ops.WaitingStatus("Waiting for certificate"))

        cluster_relation = self.model.get_relation("cluster")
        if cluster_relation:
            try:
                cluster_data = cast(
                    ClusterAppData, ClusterAppData.read(cluster_relation.data[self.app])
                )
            except ValidationError as error:
                logger.debug(
                    "Could not validate cluster application data when collecting unit status. error=%s",
                    error,
                )
            else:
                if self.model.get_relation("ceph"):
                    if not ceph.is_configured(self._ceph_user):
                        event.add_status(
                            ops.WaitingStatus("Waiting for Ceph configuration on unit")
                        )
                    else:
                        if "ceph" not in cluster_data.created_storage:
                            event.add_status(
                                ops.WaitingStatus("Waiting for Ceph storage pool creation")
                            )

                if not self._is_ovn_ready(cluster_data):
                    event.add_status(
                        ops.WaitingStatus("Waiting for OVN northbound connection configuration")
                    )

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
        """Handle install event.

        Adds the Zabbly APT repository and installs the incus package. If a relation
        to Ceph is present, also installs packages for communicating with Ceph.
        """
        self.unit.status = ops.MaintenanceStatus("Installing packages")
        self._add_apt_repository(
            repository_line=self.config.package_repository,
            gpg_key_url=self.config.package_repository_gpg_key,
        )

        packages = [self.package_name]
        if self.model.get_relation("ceph"):
            packages.append(self.ceph_package_name)

        self._install_packages(*packages)
        self.unit.set_workload_version(self._package_version)

    def on_config_changed(self, event: ops.ConfigChangedEvent):
        """Handle config-changed event.

        Applies the given configuration to the Incus instance.
        """
        self.unit.status = ops.MaintenanceStatus("Changing config")

        public_address = ""
        server_port = self.config.server_port
        public_binding = self.model.get_binding("public")
        if public_binding and public_binding.network.bind_address:
            public_address = str(public_binding.network.bind_address)
        incus.set_config("core.https_address", f"{public_address}:{server_port}")

        # NOTE: Incus does not support changing the cluster.https_address if the
        # server is already part of a cluster.
        if not incus.is_clustered():
            incus.set_config("cluster.https_address", self._cluster_address)

        metrics_address = ""
        metrics_port = self.config.metrics_port
        monitoring_binding = self.model.get_binding("monitoring")
        if monitoring_binding and monitoring_binding.network.bind_address:
            metrics_address = str(monitoring_binding.network.bind_address)
        if metrics_address != public_address:
            incus.set_config("core.metrics_address", f"{metrics_address}:{metrics_port}")
        self.unit.set_ports(ops.Port("tcp", metrics_port), ops.Port("tcp", server_port))

        if incus.is_clustered() and self.config.set_failure_domain:
            self._set_failure_domain()

        if not self.unit.is_leader():
            return

        cluster_relation = self.model.get_relation("cluster")
        assert cluster_relation, "Cluster peer relation does not exist."
        try:
            data = cast(ClusterAppData, ClusterAppData.read(cluster_relation.data[self.app]))
            created_storage = data.created_storage
        except ValidationError as error:
            logger.debug(
                "Could not validate application data when configuring Ceph storage pool. error=%s",
                error,
            )
        else:
            if "ceph" in created_storage and ceph.is_configured(self._ceph_user):
                logger.debug(
                    "Ceph storage pool is created. Will update its configuration values. ceph_rbd_features=%s",
                    self.config.ceph_rbd_features,
                )
                incus.configure_storage(
                    "ceph", {"ceph.rbd.features": self.config.ceph_rbd_features}
                )

    def on_start(self, event: ops.StartEvent):
        """Handle start event.

        Bootstraps the Incus instance if the current unit is leader. Non leader
        units are bootstrapped by receiving join tokens via the cluster relation.
        """
        # NOTE: to handle restarts, we should ensure that we only try to
        # bootstrap if the current node is not already part of a cluster
        if self.unit.is_leader() and not incus.is_clustered():
            self._bootstrap_incus()

    def on_stop(self, event: ops.StopEvent):
        """Handle stop event.

        Removes the current Incus instance from the cluster and uninstalls the
        incus package.
        """
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
        """Handle cluster-relation-created event.

        The leader unit initializes the application data bag by creating the
        dictionary for the join tokens and the cluster certificate, if one is
        available.
        """
        if not self.unit.is_leader():
            return

        # NOTE: if there's a certificates relation, the certificate should
        # be put in the relation data in response to a certificate-changed
        # event. Otherwise, the cluster certificate will be the self-signed
        # certificate of the leader unit.
        if not self.model.get_relation("certificates"):
            event.relation.data[event.app]["cluster-certificate"] = incus.get_server_certificate()
        event.relation.data[event.app]["tokens"] = json.dumps({})
        event.relation.data[event.app]["created-storage"] = json.dumps([])
        event.relation.data[event.app]["created-network"] = json.dumps([])

    @data_models.parse_relation_data(app_model=ClusterAppData, unit_model=ClusterUnitData)
    def on_cluster_relation_changed(
        self: ops.CharmBase,
        event: ops.RelationEvent,
        app_data: Optional[Union[ClusterAppData, ValidationError]] = None,
        unit_data: Optional[Union[ClusterUnitData, ValidationError]] = None,
    ):
        """Handle cluster-relation-changed event.

        The leader unit enables clustering in the Incus instance if it is not
        already enabled. It also generates a join token for the remote unit that
        triggered the event if one does not already exist.

        Non leader units get the token from the relation data and use it to join
        the Incus cluster.
        """
        # HACK: the typings for the `data_models` library are a bit broken, so we have
        # to declare `self` as `ops.CharmBase` and then cast it back to `IncusCharm`.
        self = cast(IncusCharm, self)
        if app_data is None:
            logger.debug("No app data available. event=%s", event)
            return
        if isinstance(app_data, ValidationError):
            logger.debug("Invalid app data. event=%s validation_error=%s", event, str(app_data))
            return

        event.relation.data[self.unit]["node-name"] = self._node_name

        if self.unit.is_leader():
            if unit_data is None:
                logger.debug("No unit data available. event=%s", event)
                return
            if isinstance(unit_data, ValidationError):
                logger.debug(
                    "Invalid unit data. event=%s validation_error=%s", event, str(unit_data)
                )
                return

            if not incus.is_clustered():
                self._enable_clustering()
                event.relation.data[self.unit]["joined-cluster-at"] = datetime.datetime.now(
                    datetime.timezone.utc
                ).isoformat()

            # TODO: check if unit already joined cluster and delete token secret
            node_name = unit_data.node_name
            if node_name in app_data.tokens:
                logger.debug("Token already generated for node. node_name=%s", node_name)
                return

            secret_id = self._create_join_token(node_name)
            app_data.tokens[node_name] = secret_id
            event.relation.data[event.app]["tokens"] = json.dumps(app_data.tokens)
        else:
            node_name = self._node_name
            if incus.is_clustered() or self._joined_cluster:
                return

            logger.debug(
                "Checking if secret ID for join token is available in application data. node_name=%s app_data=%s",
                node_name,
                app_data,
            )
            secret_id = app_data.tokens.get(node_name)
            if not secret_id:
                logger.debug("Secret ID not found in application data.")
                return

            if not self._is_ceph_ready(app_data):
                logger.info(
                    "Ceph storage is not ready. Deferring the event. node_name=%s", node_name
                )
                return event.defer()

            if not self._is_certificate_ready():
                logger.info(
                    "Certificate is not ready. Deferring event. node_name=%s",
                    node_name,
                )
                return event.defer()

            if not self._is_ovn_ready(app_data):
                logger.info(
                    "OVN network is not ready. Deferring event. node_name=%s",
                    node_name,
                )
                return event.defer()

            logger.info(
                "Secret ID found in app data. Will fetch token from it and join the cluster. secret_id=%s",
                secret_id,
            )
            secret = self.model.get_secret(id=secret_id)
            logger.debug("Got secret with join token from model.")
            token = secret.get_content().get("token")
            assert token, "Join token secret has an invalid content."
            cluster_certificate = app_data.cluster_certificate
            self._bootstrap_incus(join_token=token, cluster_certificate=cluster_certificate)
            logger.info("Joined cluster. node_name=%s", self._node_name)
            event.relation.data[self.unit]["joined-cluster-at"] = datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat()

    @property
    def _joined_cluster(self) -> bool:
        """Whether the current unit already joined the cluster."""
        cluster_relation = self.model.get_relation("cluster")
        if not cluster_relation:
            return False
        return cluster_relation.data[self.unit].get("joined-cluster-at") is not None

    def on_certificate_changed(self, event: tls_certificates.CertificateChangedEvent):
        """Handle certificate-changed event.

        Updates the certificate on all cluster members.
        """
        certificate = event.certificate
        logger.debug("Handling certificate changed event. certificate=%s", certificate)

        self.unit.status = ops.MaintenanceStatus("Applying certificate")
        logger.info("Applying certificate")
        incus.update_server_certificate(
            cert=certificate.cert, key=certificate.key, ca=certificate.ca
        )
        if not incus.is_clustered():
            logger.info("Unit is standalone. Will restart service to apply new certificate.")
            self._restart_service(self.service_name)
        elif self.unit.is_leader():
            logger.debug(
                "Unit is the cluster leader. Will apply certificate to all cluster members."
            )
            incus.update_cluster_certificate(cert=certificate.cert, key=certificate.key)

        # NOTE: put the certificate in the relation data so other units can
        # join the cluster using this certificate
        if self.unit.is_leader():
            cluster_relation = self.model.get_relation("cluster")
            assert cluster_relation, "Cluster peer relation does not exist."
            cluster_relation.data[self.app]["cluster-certificate"] = certificate.cert

        # NOTE: set OVN configuration only on the leader unit, as OVN options
        # are global for all cluster members
        if self.unit.is_leader() and self.model.get_relation("ovsdb-cms"):
            connection_options = self._get_ovn_connection_options()
            if connection_options:
                logger.debug("OVN connection options available. Will configure OVN connection.")
                self._configure_ovn_connection(event, connection_options)

        logger.info("Certificate applied")

    def on_ceph_relation_created(self, event: ops.RelationCreatedEvent):
        """Handle ceph-relation-created event.

        Ensures that the local incus service supports the Ceph storage driver, and
        installs the required packages if needed.
        """
        supported_storage_drivers = incus.get_supported_storage_drivers()
        if "ceph" not in supported_storage_drivers:
            logger.debug(
                "Ceph storage driver not currently supported by Incus. Will install needed packages. supported_storage_drivers=%s",
                supported_storage_drivers,
            )
            self.unit.status = ops.MaintenanceStatus(
                f"Installing {self.ceph_package_name} package"
            )
            self._install_packages(self.ceph_package_name)
            # NOTE: Since Incus checks for supported storage drivers at startup,
            # we need to restart the service to update the supported storage drivers
            self.unit.status = ops.MaintenanceStatus(f"Restarting {self.service_name} service")
            self._restart_service(self.service_name)
            logger.info(
                "Installed required Ceph packages. package_name=%s", self.ceph_package_name
            )

        supported_storage_drivers = incus.get_supported_storage_drivers()
        assert "ceph" in supported_storage_drivers, "Failed to enable Ceph support on Incus"

    @data_models.parse_relation_data(unit_model=CephUnitData)
    def on_ceph_relation_changed(
        self: ops.CharmBase,
        event: ops.RelationEvent,
        app_data: Optional[Union[Any, ValidationError]] = None,
        unit_data: Optional[Union[CephUnitData, ValidationError]] = None,
    ):
        """Handle ceph-relation-changed event.

        Gets the endpoints and authentication key from the relation data and
        writes them to the Ceph configuration files on the system.
        """
        self = cast(IncusCharm, self)
        if unit_data is None:
            logger.debug("No unit data available. event=%s", event)
            return
        if isinstance(unit_data, ValidationError):
            logger.debug("Invalid unit data. event=%s validation_error=%s", event, str(unit_data))
            return

        logger.debug(
            "Handling ceph relation changed event. event=%s unit_data=%s", event, unit_data
        )
        ceph_addresses = {
            address
            for address in (
                event.relation.data[unit].get("ceph-public-address")
                for unit in event.relation.units
            )
            if address is not None
        }
        logger.debug(
            "Collected Ceph addresses from relation data. ceph_addresses=%s relation_data=%s",
            ceph_addresses,
            event.relation.data,
        )

        self.unit.status = ops.MaintenanceStatus("Updating Ceph configuration files")
        logger.info(
            "Writing data from relation into ceph config files. ceph_addresses=%s ceph_user=%s",
            ceph_addresses,
            self._ceph_user,
        )
        ceph.write_keyring_file(ceph_user=self._ceph_user, key=unit_data.key)
        ceph.write_ceph_conf_file(ceph_addresses)

        if not self.unit.is_leader():
            return

        # TODO: make Ceph storage pool parameters configurable
        ceph_pool_name = "incus"
        request = ceph_client.CephBrokerRq()
        request.add_op_create_replicated_pool(
            name=ceph_pool_name, replica_count=3, app_name=self._ceph_user
        )
        if ceph_client.is_request_complete(request):
            cluster_relation = self.model.get_relation("cluster")
            assert cluster_relation, "Cluster peer relation does not exist."
            created_storage: Set[incus.IncusStorageDriver] = set()
            try:
                data = cast(ClusterAppData, ClusterAppData.read(cluster_relation.data[self.app]))
                created_storage = data.created_storage
            except ValidationError as error:
                logger.debug(
                    "Could not validate application data when creating Ceph storage pool. Deferring the event. error=%s",
                    error,
                )
                return event.defer()

            if "ceph" in created_storage:
                logger.info(
                    "A Ceph storage pool is already present in the Incus cluster. Skipping storage pool creation."
                )
                return

            self.unit.status = ops.MaintenanceStatus("Creating Ceph storage pool on Incus")
            self._create_ceph_storage_pool(ceph_pool_name, self._ceph_user)
            created_storage.add("ceph")
            cluster_relation.data[self.app]["created-storage"] = json.dumps(list(created_storage))
        else:
            self.unit.status = ops.MaintenanceStatus("Requesting Ceph pool creation")
            logger.info("Will request ceph-mon to create a Ceph OSD pool for Incus")
            ceph_client.send_request_if_needed(request)

    def _create_ceph_storage_pool(self, ceph_pool_name: str, ceph_user: str):
        """Create a Ceph storage pool in the Incus cluster."""
        logger.info(
            "Creating Ceph storage pool. ceph_pool_name=%s ceph_user=%s", ceph_pool_name, ceph_user
        )
        pool_config = {
            "ceph.user.name": ceph_user,
            "ceph.rbd.features": self.config.ceph_rbd_features,
        }
        if not incus.is_clustered():
            incus.create_storage(
                pool_name="ceph",
                storage_driver="ceph",
                source=ceph_pool_name,
                pool_config=pool_config,
            )
            logger.info("Ceph storage pool created.")
            return

        logger.info("Will create pending storage pool on all cluster nodes.")
        cluster_relation = self.model.get_relation("cluster")
        assert cluster_relation, "Cluster peer relation does not exist."
        for unit in [*cluster_relation.units, self.unit]:
            try:
                data = cast(ClusterUnitData, ClusterUnitData.read(cluster_relation.data[unit]))
            except ValidationError as error:
                logger.debug(
                    "Could not validate unit data when creating Ceph storage pool. unit=%s error=%s",
                    unit,
                    error,
                )
                continue

            node_name = data.node_name
            if not data.joined_cluster_at:
                logger.info(
                    "Unit has not yet joined the cluster. Skipping ceph storage pool creation on node. node_name=%s",
                    data.node_name,
                )
                continue

            logger.info("Creating Ceph storage pool on Incus node. node_name=%s", node_name)
            incus.create_storage(
                pool_name="ceph",
                storage_driver="ceph",
                source=ceph_pool_name,
                target=node_name,
            )
            logger.info("Ceph storage pool created on node. node_name=%s", node_name)
        logger.info("Instantiating Ceph storage pool across the cluster.")
        incus.create_storage(
            pool_name="ceph",
            storage_driver="ceph",
            pool_config=pool_config,
        )
        logger.info("Ceph storage pool created.")

    def on_ovsdb_cms_relation_created(self, event: ops.RelationCreatedEvent):
        """Handle ovsdb-cms-relation-created event.

        Sets the unit's IP address on the relation data for ovn-central to
        create firewall rules allowing access to the ovn northbound database.
        """
        ovsdb_cms_binding = self.model.get_binding("ovsdb-cms")
        if ovsdb_cms_binding and ovsdb_cms_binding.network.bind_address:
            ovsdb_cms_address = str(ovsdb_cms_binding.network.bind_address)
            logger.debug(
                "Setting cms-client-bound-address on ovsdb-cms relation data. ovsdb_cms_address=%s",
                ovsdb_cms_address,
            )
            event.relation.data[self.unit]["cms-client-bound-address"] = ovsdb_cms_address
        else:
            logger.warning(
                "Could not set cms-client-bound-address on ovsdb-cms relation. No IP address available for ovsdb-cms binding."
            )

    @data_models.parse_relation_data(unit_model=OvnCentralUnitData)
    def on_ovsdb_cms_relation_changed(
        self: ops.CharmBase,
        event: ops.RelationEvent,
        app_data: Optional[Union[Any, ValidationError]] = None,
        unit_data: Optional[Union[OvnCentralUnitData, ValidationError]] = None,
    ):
        """Handle ovsdb-cms-relation-changed event.

        Fetches the OVN northbound database endpoints from the relation data and
        sets them on Incus.
        """
        self = cast(IncusCharm, self)
        if unit_data is None:
            logger.debug("No unit data available. event=%s", event)
            return
        if isinstance(unit_data, ValidationError):
            logger.debug("Invalid unit data. event=%s validation_error=%s", event, str(unit_data))
            return

        if not self.unit.is_leader():
            logger.debug("Unit is not leader. Skipping event. event=%s", event)
            return

        logger.debug(
            "Handling ovsdb-cms relation changed event. event=%s unit_data=%s", event, unit_data
        )
        connection_options = self._get_ovn_connection_options()
        if not connection_options:
            logger.debug("OVN connection options not available. Skipping event. event=%s", event)
            return
        self._configure_ovn_connection(event, connection_options)

    @data_models.validate_params(AddTrustedCertificateActionParams)
    def add_trusted_certificate_action(
        self: ops.CharmBase,
        event: ops.ActionEvent,
        params: Union[AddTrustedCertificateActionParams, ValidationError],
    ):
        """Handle the add-trusted-certificate action.

        Adds the received certificate to the Incus truststore.
        """
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
        """Handle the cluster-list action.

        Lists the cluster state and return its output.
        """
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

    @property
    def _ceph_user(self) -> str:
        return self.app.name

    @property
    def _availability_zone(self) -> Optional[str]:
        return os.environ.get("JUJU_AVAILABILITY_ZONE")

    def _install_packages(self, *packages: str):
        """Install the specified `packages` on the system."""
        logging.info("Installing packages. packages=%s", packages)
        package = ""
        try:
            apt.update()
            for package in packages:
                package = apt.DebianPackage.from_system(package)
                package.ensure(apt.PackageState.Present)
                package_version = package.version.number
                logger.info(
                    "Installed package. package=%s version=%s",
                    package,
                    package_version,
                )
        except apt.PackageNotFoundError:
            logger.warning("Package not found in repositories. package=%s", package)
        except apt.PackageError as e:
            logger.error(
                "Error when installing package. name=%s error=%s",
                package,
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

    def _restart_service(self, service: str):
        """Restart the given `service`."""
        try:
            systemd.service_restart(service)
        except systemd.SystemdError as e:
            logger.error("Error when restarting systemd service. error=%s", e)
            raise e

    def _bootstrap_incus(
        self, join_token: Optional[str] = None, cluster_certificate: Optional[str] = None
    ):
        """Bootstraps the Incus server via `incus admin init`.

        If `join_token` is provided, joins an existing cluster using `cluster_certificate` to
        authenticate with the existing members.
        """
        self.unit.status = ops.MaintenanceStatus("Bootstrapping Incus")
        logger.info("Bootstrapping Incus")
        cluster_info = (
            None
            if join_token is None
            else {
                "enabled": True,
                "cluster_token": join_token,
                "cluster_certificate": cluster_certificate,
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
        try:
            incus.bootstrap_node(preseed)
        except incus.IncusProcessError as error:
            if not error.is_retryable:
                raise error
            logger.warning(
                "A retryable error occurred while bootstrapping Incus. Despite that, the server should have been correctly bootstrapped. error=%s",
                error,
            )
        logger.info("Incus server bootstrapped")
        self._set_failure_domain()

    def _set_failure_domain(self):
        """Set the current node failure domain."""
        if not self.config.set_failure_domain:
            return

        if not self._availability_zone:
            logger.warning(
                "No availability zone available from Juju. Node will use the default failure domain."
            )
            return

        if self._availability_zone:
            incus.set_cluster_member_failure_domain(self._node_name, self._availability_zone)
            logger.info(
                "Set node failure domain according to Juju availability zone. failure_domain=%s",
                self._availability_zone,
            )

    def _enable_clustering(self):
        """Enable clustering on the local Incus daemon.

        This should be used by the leader unit to enable clustering
        before creating join tokens for new units.
        """
        self.unit.status = ops.MaintenanceStatus("Enabling clustering")
        logger.info("Node has not enabled clustering. Will enable it.")
        incus.enable_clustering(self._node_name)
        certificate = self.tls_certificates.certificate
        if certificate:
            logger.info("Updating cluster certificate.")
            incus.update_cluster_certificate(cert=certificate.cert, key=certificate.key)
        logger.info("Enabled clustering. node_name=%s", self._node_name)
        self._set_failure_domain()

    def _create_join_token(self, node_name: str) -> str:
        """Create a Incus cluster join token for `node_name` and returns its secret ID.

        The token allows new units to join the Incus cluster. Since the token
        contains sensitive data, it is stored as a Juju secret in the model.
        """
        self.unit.status = ops.MaintenanceStatus(f"Creating join token for {node_name}")
        logger.info(
            "Creating join token for node. node_name=%s",
            node_name,
        )
        join_token = incus.create_join_token(node_name)
        secret = self.app.add_secret({"token": join_token}, label=f"{node_name}-join-token")
        assert secret.id, f"Generated secret does not have a valid ID. secret={secret}"
        logger.info("Join token created.")
        return secret.id

    def _is_ceph_ready(self, app_data: ClusterAppData) -> bool:
        """Check if all Ceph prerequisites are met to join the cluster.

        If requirements are not met, the unit should defer the event that
        it is currently handling. This avoids race conditions and ensures
        that all members will be able to join the cluster and configure
        the Ceph storage pool.
        """
        # NOTE: if a ceph relation exists, we expect that eventually a Ceph
        # storage pool will be created on the cluster. If either ceph is not
        # configured on the unit or the leader unit has not yet created the
        # ceph pool and signaled it via the application data, we consider ceph
        # as not ready.
        if self.model.get_relation("ceph"):
            if not ceph.is_configured(self._ceph_user):
                logger.info("Ceph is not configured on unit. app_data=%s", app_data)
                return False
            if "ceph" not in app_data.created_storage:
                logger.debug(
                    "Ceph storage pool is not created on the cluster. app_data=%s", app_data
                )
                return False
        return True

    def _is_certificate_ready(self) -> bool:
        """Check if all certificates prerequisites are met to join the cluster.

        If requirements are not met, the unit should defer the event that
        it is currently handling. This avoids race conditions and ensures
        that all members will have the certificate applied before joining
        the cluster.
        """
        # NOTE: if a certificate relation exists, we expect that eventually a
        # certificate will be issued and applied to the unit. If the certificate
        # either is not issued or not applied yet, we consider it not ready.
        if self.model.get_relation("certificates"):
            certificate = self.tls_certificates.certificate
            if not certificate:
                logger.debug(
                    "Certificate not yet emitted for this unit. unit=%s",
                    self.unit,
                )
                return False

            if certificate.cert != incus.get_server_certificate():
                logger.debug("Certificate not yet applied to unit. unit=%s", self.unit)
                return False
        return True

    def _is_ovn_ready(self, app_data: ClusterAppData) -> bool:
        """Check if all OVN prerequisites are met to join the cluster.

        If requirements are not met, the unit should defer the event that
        it is currently handling. This avoids race conditions and ensures
        that all members will be able to join the cluster and configure
        the OVN northbound connection.
        """
        # NOTE: if a ovsdb-cms relation exists, we expect that eventually the
        # configuration for the OVN northbound connection will be performed an
        # signaled in the cluster data.
        if self.model.get_relation("ovsdb-cms"):
            if "ovn" not in app_data.created_network:
                logger.debug(
                    "OVN northbound connection is not configured on the cluster. app_data=%s",
                    app_data,
                )
                return False
        return True

    def _get_ovn_connection_options(self) -> Optional[incus.OvnConnectionOptions]:
        """Get the OVN connection options from the environment.

        Returns None if any of the option values are not available.

        We need to check if all requirements are met before configuring the
        connection because any change in a OVN related config option in Incus
        triggers a connection check. This means that we must only configure
        OVN related options when we can ensure a working connection.
        """
        logger.debug("Checking requirements for OVN configuration")
        relation = self.model.get_relation("ovsdb-cms")
        if not relation:
            logger.debug("Relation ovsdb-cms not present. Skipping OVN configuration.")
            return

        # If any endpoints from ovn-central are missing, we're not ready
        ovn_endpoints = [self._get_ovn_endpoint(relation.data[unit]) for unit in relation.units]
        if not ovn_endpoints or not all(ovn_endpoints):
            logger.debug(
                "Endpoints missing from ovsdb-cms relation. Skipping OVN configuration. relation_data=%s",
                relation.data,
            )
            return
        ovn_endpoints = cast(List[str], ovn_endpoints)

        # If no certificate is issues, we're not ready
        certificate = self.tls_certificates.certificate
        if not certificate:
            logger.debug("No certificate available. Skipping OVN configuration.")
            return

        # If all requirements are met, setup the OVN connection options
        ovn_northbound_connection = ",".join(sorted(ovn_endpoints))
        logger.info(
            "Gathered all OVN northbound connection options. ovn_northbound_connection=%s",
            ovn_northbound_connection,
        )
        return incus.OvnConnectionOptions(
            client_cert=certificate.cert,
            client_key=certificate.key,
            client_ca=certificate.ca,
            northbound_connection=ovn_northbound_connection,
        )

    def _get_ovn_endpoint(self, relation_data: ops.RelationDataContent) -> Optional[str]:
        """Get an OVN endpoint from the unit's `relation_data`.

        Returns `None` if no endpoint is available.
        """
        ip = relation_data.get("bound-address")
        if not ip:
            return None
        ip = ip.strip('"')
        return f"ssl:{ip}:6641"

    def _configure_ovn_connection(
        self, event: ops.EventBase, connection_options: incus.OvnConnectionOptions
    ):
        """Configure the OVN connection in Incus.

        If a retryable error occurs, `event` is deferred.
        """
        try:
            self.unit.status = ops.MaintenanceStatus("Configuring OVN northbound connection")
            logger.info("Configuring OVN northbound connection")
            incus.set_ovn_northbound_connection(connection_options)
        except incus.IncusProcessError as error:
            if error.is_retryable:
                logger.warning("Error is retryable. Will defer event. event=%s", event)
                return event.defer()
        else:
            cluster_relation = self.model.get_relation("cluster")
            assert cluster_relation, "Cluster peer relation does not exist."
            data = cast(ClusterAppData, ClusterAppData.read(cluster_relation.data[self.app]))
            created_network = data.created_network
            created_network.add("ovn")
            cluster_relation.data[self.app]["created-network"] = json.dumps(list(created_network))


if __name__ == "__main__":  # pragma: nocover
    ops.main(IncusCharm)  # type: ignore
