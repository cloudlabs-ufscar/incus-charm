# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing


from unittest.mock import call, patch

import pytest
import scenario
from scenario.errors import UncaughtCharmError

from charm import IncusCharm


@pytest.mark.parametrize("server_port,cluster_port", [(8443, 8443), (1234, 1235), (9999, 2000)])
def test_config_changed_not_clustered(server_port, cluster_port):
    """Test the config-changed event on units that are not clustered.

    Both the server and cluster ports should be applied to the Incus instance.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._install_packages"),
        patch("charm.IncusCharm._uninstall_packages"),
        patch("charm.incus.set_config") as set_config,
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            config={"server-port": server_port, "cluster-port": cluster_port},
            networks=[
                scenario.Network(
                    binding_name="public",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.1")])],
                ),
                scenario.Network(
                    binding_name="cluster",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.2")])],
                ),
            ],
        )

        ctx.run(ctx.on.config_changed(), state)

        set_config.assert_has_calls(
            [
                call({"core.https_address": f"10.0.0.1:{server_port}"}),
                call({"cluster.https_address": f"10.0.0.2:{cluster_port}"}),
            ]
        )


@pytest.mark.parametrize(
    "metrics_port",
    [(8445), (4321), (1166)],
)
def test_config_changed_not_clustered_expose_metrics_endpoints(metrics_port):
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._install_packages"),
        patch("charm.IncusCharm._uninstall_packages"),
        patch("charm.incus.set_config") as set_config,
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            config={"server-port": 8443, "cluster-port": 8444, "metrics-port": metrics_port},
            networks=[
                scenario.Network(
                    binding_name="public",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.1")])],
                ),
                scenario.Network(
                    binding_name="cluster",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.2")])],
                ),
                scenario.Network(
                    binding_name="monitoring",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.3")])],
                ),
            ],
        )

        ctx.run(ctx.on.config_changed(), state)

        set_config.assert_has_calls(
            [
                call({"core.metrics_address": f"10.0.0.3:{metrics_port}"}),
            ]
        )


@pytest.mark.parametrize("server_port,cluster_port", [(8443, 8443), (1234, 1235), (9999, 2000)])
def test_config_changed_clustered(server_port, cluster_port):
    """Test the config-changed event on units that are clustered.

    The cluster port should not be modified. Only the server port should be
    applied to the Incus instance.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._install_packages"),
        patch("charm.IncusCharm._uninstall_packages"),
        patch("charm.incus.set_config") as set_config,
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            config={"server-port": server_port, "cluster-port": cluster_port},
            networks=[
                scenario.Network(
                    binding_name="public",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.1")])],
                ),
            ],
        )

        ctx.run(ctx.on.config_changed(), state)

        set_config.assert_has_calls(
            [
                call({"core.https_address": f"10.0.0.1:{server_port}"}),
            ]
        )


@pytest.mark.parametrize("metrics_port", [(8445), (4321), (1166)])
def test_config_changed_clustered_expose_metrics_endpoints(metrics_port):
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._install_packages"),
        patch("charm.IncusCharm._uninstall_packages"),
        patch("charm.incus.set_config") as set_config,
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            config={"server-port": 8443, "cluster-port": 8444, "metrics-port": metrics_port},
            networks=[
                scenario.Network(
                    binding_name="public",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.1")])],
                ),
                scenario.Network(
                    binding_name="monitoring",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.3")])],
                ),
            ],
        )

        ctx.run(ctx.on.config_changed(), state)

        set_config.assert_has_calls(
            [
                call({"core.metrics_address": f"10.0.0.3:{metrics_port}"}),
            ]
        )


@pytest.mark.parametrize(
    "server_port,cluster_port",
    [(-1, 8443), (1234, -1), (99999999, 8843), (8843, 99999999)],
)
def test_config_changed_invalid_port(server_port, cluster_port):
    """Test the config-changed event with invalid ports.

    The charm should enter in an error state and not apply any configuration
    to the Incus instance.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._install_packages"),
        patch("charm.IncusCharm._uninstall_packages"),
        patch("charm.incus.set_config") as set_config,
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            config={"server-port": server_port, "cluster-port": cluster_port},
            networks=[
                scenario.Network(
                    binding_name="public",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.1")])],
                ),
                scenario.Network(
                    binding_name="cluster",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.2")])],
                ),
            ],
        )

        with pytest.raises(UncaughtCharmError):
            ctx.run(ctx.on.config_changed(), state)

        assert ctx.unit_status_history == [scenario.UnknownStatus()]
        set_config.assert_not_called()


@pytest.mark.parametrize("metrics_port", [(-1), (99999999)])
def test_config_changed_invalid_port_expose_metrics_endpoints(metrics_port):
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._install_packages"),
        patch("charm.IncusCharm._uninstall_packages"),
        patch("charm.incus.set_config") as set_config,
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            config={"server-port": 8443, "cluster-port": 8444, "metrics-port": metrics_port},
            networks=[
                scenario.Network(
                    binding_name="public",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.1")])],
                ),
                scenario.Network(
                    binding_name="cluster",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.2")])],
                ),
                scenario.Network(
                    binding_name="monitoring",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.3")])],
                ),
            ],
        )

        with pytest.raises(UncaughtCharmError):
            ctx.run(ctx.on.config_changed(), state)

        assert ctx.unit_status_history == [scenario.UnknownStatus()]
        set_config.assert_not_called()


@pytest.mark.parametrize("is_clustered", [True, False])
def test_config_changed_ceph_rbd_features_non_leader(is_clustered: bool):
    """Test the config-changed event for the ceph-rbd-features config option on non leader units.

    Non leader units should not try to set this config option on the Incus
    cluster.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._install_packages"),
        patch("charm.IncusCharm._uninstall_packages"),
        patch("charm.incus.set_config"),
        patch("charm.incus.is_clustered", return_value=is_clustered),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.incus.configure_storage") as configure_storage,
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            leader=False,
            config={"ceph-rbd-features": "any-feature,another-feature"},
        )

        ctx.run(ctx.on.config_changed(), state)

        configure_storage.assert_not_called()


@pytest.mark.parametrize("is_clustered", [True, False])
def test_config_changed_ceph_rbd_features_leader(is_clustered: bool):
    """Test the config-changed event for the ceph-rbd-features config option on leader units.

    The leader unit should set this config option on the Incus cluster.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._install_packages"),
        patch("charm.IncusCharm._uninstall_packages"),
        patch("charm.incus.set_config"),
        patch("charm.incus.is_clustered", return_value=is_clustered),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.incus.configure_storage") as configure_storage,
        patch("charm.ceph.is_configured", return_value=True),
    ):
        cluster_relation = scenario.PeerRelation(
            endpoint="cluster",
            local_app_data={
                "tokens": "{}",
                "created-storage": '["ceph"]',
                "created-network": "[]",
                "cluster-certificate": "any-cluster-certificate",
            },
        )
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            leader=True,
            config={"ceph-rbd-features": "any-feature,another-feature"},
            relations={cluster_relation},
        )

        ctx.run(ctx.on.config_changed(), state)

        configure_storage.assert_called_once_with(
            "ceph", {"ceph.rbd.features": "any-feature,another-feature"}
        )


def test_config_changed_ceph_rbd_features_ceph_storage_not_configured():
    """Test the config-changed event for the ceph-rbd-features when the storage is not configured.

    The leader unit should not try to set this config option on the Incus cluster.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._install_packages"),
        patch("charm.IncusCharm._uninstall_packages"),
        patch("charm.incus.set_config"),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.incus.configure_storage") as configure_storage,
        patch("charm.ceph.is_configured", return_value=False),
    ):
        cluster_relation = scenario.PeerRelation(
            endpoint="cluster",
            local_app_data={
                "tokens": "{}",
                "created-storage": '["ceph"]',
                "cluster-certificate": "any-cluster-certificate",
            },
        )
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            leader=True,
            config={"ceph-rbd-features": "any-feature,another-feature"},
            relations={cluster_relation},
        )

        ctx.run(ctx.on.config_changed(), state)

        configure_storage.assert_not_called()


def test_config_changed_ceph_rbd_features_ceph_storage_not_created():
    """Test the config-changed event for the ceph-rbd-features when the storage is not created.

    The leader unit should not try to set this config option on the Incus cluster.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._install_packages"),
        patch("charm.IncusCharm._uninstall_packages"),
        patch("charm.incus.set_config"),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.incus.configure_storage") as configure_storage,
        patch("charm.ceph.is_configured", return_value=True),
    ):
        cluster_relation = scenario.PeerRelation(
            endpoint="cluster",
            local_app_data={
                "tokens": "{}",
                "created-storage": "[]",
                "cluster-certificate": "any-cluster-certificate",
            },
        )
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            leader=True,
            config={"ceph-rbd-features": "any-feature,another-feature"},
            relations={cluster_relation},
        )

        ctx.run(ctx.on.config_changed(), state)

        configure_storage.assert_not_called()


def test_config_changed_ceph_rbd_features_invalid_application_data():
    """Test the config-changed event for the ceph-rbd-features when the application data is invalid.

    The leader unit should not try to set this config option on the Incus cluster.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._install_packages"),
        patch("charm.IncusCharm._uninstall_packages"),
        patch("charm.incus.set_config"),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.incus.configure_storage") as configure_storage,
        patch("charm.ceph.is_configured", return_value=True),
    ):
        cluster_relation = scenario.PeerRelation(
            endpoint="cluster",
            local_app_data={
                "tokens": "{}",
                "cluster-certificate": "any-cluster-certificate",
            },
        )
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            leader=True,
            config={"ceph-rbd-features": "any-feature,another-feature"},
            relations={cluster_relation},
        )

        ctx.run(ctx.on.config_changed(), state)

        configure_storage.assert_not_called()


@pytest.mark.parametrize("leader", [True, False])
def test_config_changed_set_failure_domain_not_clustered(leader: bool):
    """Test the config-changed event for the set-failure-domain config option on non clustered units.

    If the unit is not part of a cluster, it should not set any failure domain.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._install_packages"),
        patch("charm.IncusCharm._uninstall_packages"),
        patch("charm.incus.set_config"),
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch(
            "charm.incus.set_cluster_member_failure_domain"
        ) as set_cluster_member_failure_domain,
    ):
        cluster_relation = scenario.PeerRelation(
            endpoint="cluster",
            local_app_data={
                "tokens": "{}",
                "cluster-certificate": "any-cluster-certificate",
            },
        )
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            leader=leader,
            config={"set-failure-domain": True},
            relations={cluster_relation},
        )

        ctx.run(ctx.on.config_changed(), state)

        set_cluster_member_failure_domain.assert_not_called()


@pytest.mark.parametrize("leader", [True, False])
def test_config_changed_set_failure_domain_clustered(leader: bool):
    """Test the config-changed event for the set-failure-domain config option on clustered units.

    If the unit is part of a cluster, it should set its failure domain using
    the JUJU_AVAILABILITY_ZONE environment variable.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._install_packages"),
        patch("charm.IncusCharm._uninstall_packages"),
        patch("charm.incus.set_config"),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch(
            "charm.incus.set_cluster_member_failure_domain"
        ) as set_cluster_member_failure_domain,
        patch.dict("charm.os.environ", {"JUJU_AVAILABILITY_ZONE": "any-availability-zone"}),
    ):
        cluster_relation = scenario.PeerRelation(
            endpoint="cluster",
            local_app_data={
                "tokens": "{}",
                "cluster-certificate": "any-cluster-certificate",
            },
        )
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            leader=leader, config={"set-failure-domain": True}, relations={cluster_relation}
        )

        ctx.run(ctx.on.config_changed(), state)

        set_cluster_member_failure_domain.assert_called_once_with(
            "any-node-name", "any-availability-zone"
        )


@pytest.mark.parametrize("leader", [True, False])
def test_config_changed_set_failure_domain_clustered_az_not_available(leader: bool):
    """Test the config-changed event for the set-failure-domain config option on clustered units that do not have the Juju availability zone.

    If the unit is part of a cluster, but it does not have the JUJU_AVAILABILITY_ZONE
    environment variable set, it should not set any failure domain.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._install_packages"),
        patch("charm.IncusCharm._uninstall_packages"),
        patch("charm.incus.set_config"),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch(
            "charm.incus.set_cluster_member_failure_domain"
        ) as set_cluster_member_failure_domain,
    ):
        cluster_relation = scenario.PeerRelation(
            endpoint="cluster",
            local_app_data={
                "tokens": "{}",
                "cluster-certificate": "any-cluster-certificate",
            },
        )
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            leader=leader, config={"set-failure-domain": True}, relations={cluster_relation}
        )

        ctx.run(ctx.on.config_changed(), state)

        set_cluster_member_failure_domain.assert_not_called()


@pytest.mark.parametrize("package_installed", [True, False])
def test_config_changed_enable_web_ui(package_installed):
    """Test the config-changed event when the enable-web-ui config is true.

    The unit should install the incus-ui-canonical package if it is not already
    installed.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=package_installed),
        patch("charm.IncusCharm._install_packages") as install_packages,
        patch("charm.IncusCharm._uninstall_packages") as uninstall_packages,
        patch("charm.incus.set_config"),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            config={"enable-web-ui": True},
        )

        ctx.run(ctx.on.config_changed(), state)

        if not package_installed:
            assert ctx.unit_status_history == [
                scenario.UnknownStatus(),
                scenario.MaintenanceStatus("Changing config"),
                scenario.MaintenanceStatus("Enabling web UI"),
            ]
            install_packages.assert_called_once_with("incus-ui-canonical")
            uninstall_packages.assert_not_called()
        else:
            uninstall_packages.assert_not_called()
            install_packages.assert_not_called()


@pytest.mark.parametrize("package_installed", [True, False])
def test_config_changed_disable_web_ui(package_installed):
    """Test the config-changed event when the enable-web-ui config is false.

    The unit should uninstall the incus-ui-canonical package if it is installed.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=package_installed),
        patch("charm.IncusCharm._install_packages") as install_packages,
        patch("charm.IncusCharm._uninstall_packages") as uninstall_packages,
        patch("charm.incus.set_config"),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            config={"enable-web-ui": False},
        )

        ctx.run(ctx.on.config_changed(), state)

        if package_installed:
            assert ctx.unit_status_history == [
                scenario.UnknownStatus(),
                scenario.MaintenanceStatus("Changing config"),
                scenario.MaintenanceStatus("Disabling web UI"),
            ]
            uninstall_packages.assert_called_once_with("incus-ui-canonical")
            install_packages.assert_not_called()
        else:
            uninstall_packages.assert_not_called()
            install_packages.assert_not_called()


def test_config_changed_auth():
    """Test the config-changed event when auth related config options are set.

    The unit should set the config options in Incus.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=False),
        patch("charm.IncusCharm._install_packages"),
        patch("charm.IncusCharm._uninstall_packages"),
        patch("charm.incus.set_config") as set_config,
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
    ):
        cluster_relation = scenario.PeerRelation(
            endpoint="cluster",
            local_app_data={
                "tokens": "{}",
                "created-storage": "[]",
                "cluster-certificate": "any-cluster-certificate",
            },
        )
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            leader=True,
            relations={cluster_relation},
            config={
                "oidc-audience": "any-audience",
                "oidc-claim": "any-claim",
                "oidc-client-id": "any-client-id",
                "oidc-issuer": "any-issuer",
                "oidc-scopes": "any-scopes",
                "openfga-api-token": "any-token",
                "openfga-api-url": "any-url",
                "openfga-store-id": "any-store-id",
            },
        )

        ctx.run(ctx.on.config_changed(), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Changing config"),
        ]

        set_config.assert_has_calls(
            [
                call(
                    {
                        "oidc.audience": "any-audience",
                        "oidc.claim": "any-claim",
                        "oidc.client.id": "any-client-id",
                        "oidc.issuer": "any-issuer",
                        "oidc.scopes": "any-scopes",
                        "openfga.api.token": "any-token",
                        "openfga.api.url": "any-url",
                        "openfga.store.id": "any-store-id",
                    }
                )
            ]
        )
