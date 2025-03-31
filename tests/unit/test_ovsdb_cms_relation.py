from typing import List
from unittest.mock import call, patch

import pytest
import scenario

import incus
from charm import IncusCharm


@pytest.mark.parametrize("address", ["192.168.0.2", "10.0.2.84", "38.28.79.12"])
def test_ovsdb_cms_relation_created(address: str):
    """Test the ovsdb-cms-relation-created event.

    The unit should put the IP address for the binding associated with the
    relation in the relation data.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        ovsdb_cms_relation = scenario.Relation(endpoint="ovsdb-cms", interface="ovsdb-cms")
        cluster_relation = scenario.PeerRelation(
            endpoint="cluster",
            interface="incus-cluster",
            local_app_data={
                "tokens": "{}",
                "cluster-certificate": "any-cluster-certificate",
                "created-storage": "[]",
                "created-network": "[]",
            },
        )
        network = scenario.Network(
            binding_name="ovsdb-cms",
            bind_addresses=[scenario.BindAddress([scenario.Address(address)])],
        )
        state = scenario.State(
            leader=True, relations={ovsdb_cms_relation, cluster_relation}, networks={network}
        )

        ctx.run(ctx.on.relation_created(relation=ovsdb_cms_relation), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]
        assert ovsdb_cms_relation.local_unit_data.get("cms-client-bound-address") == address


def test_ovsdb_cms_relation_changed_non_leader():
    """Test the ovsdb-cms-relation-changed event on non leader units.

    The unit should skip the event.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.incus.set_ovn_northbound_connection") as set_ovn_northbound_connection,
    ):
        ctx = scenario.Context(IncusCharm)
        ovsdb_cms_relation = scenario.Relation(endpoint="ovsdb-cms", interface="ovsdb-cms")
        cluster_relation = scenario.PeerRelation(
            endpoint="cluster",
            interface="incus-cluster",
            local_app_data={
                "tokens": "{}",
                "cluster-certificate": "any-cluster-certificate",
                "created-storage": "[]",
                "created-network": "[]",
            },
        )

        state = scenario.State(leader=False, relations={ovsdb_cms_relation, cluster_relation})

        ctx.run(ctx.on.relation_changed(relation=ovsdb_cms_relation), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]
        set_ovn_northbound_connection.assert_not_called()


@pytest.mark.parametrize(
    "addresses,expected_connection",
    [
        (["10.0.0.1"], "ssl:10.0.0.1:6641"),
        (
            ["10.10.10.1", "10.10.10.2", "10.10.11.3"],
            "ssl:10.10.10.1:6641,ssl:10.10.10.2:6641,ssl:10.10.11.3:6641",
        ),
    ],
)
def test_ovsdb_cms_relation_changed_leader(addresses: List[str], expected_connection: str):
    """Test the ovsdb-cms-relation-changed event on leader units.

    The unit should collect the ovn northbound database endpoints from the
    relation data and set them in Incus.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.incus.set_ovn_northbound_connection") as set_ovn_northbound_connection,
        patch("charm.incus.create_network") as _create_network,
    ):
        ctx = scenario.Context(IncusCharm)
        ovsdb_cms_relation = scenario.Relation(
            endpoint="ovsdb-cms",
            interface="ovsdb-cms",
            remote_units_data={i: {"bound-address": f'"{v}"'} for i, v in enumerate(addresses)},
        )
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_units_data={
                0: {
                    "ca": "any-ca",
                    "client.cert": "any-client-cert",
                    "client.key": "any-client-key",
                    "incus_0.server.cert": "any-server-cert",
                    "incus_0.server.key": "any-server-key",
                },
            },
        )
        cluster_relation = scenario.PeerRelation(
            endpoint="cluster",
            interface="incus-cluster",
            local_app_data={
                "tokens": "{}",
                "cluster-certificate": "any-cluster-certificate",
                "created-storage": "[]",
                "created-network": "[]",
            },
        )
        state = scenario.State(
            leader=True,
            relations={ovsdb_cms_relation, certificates_relation, cluster_relation},
            config={
                "ovn-uplink-network-config": "any-key=any-value another-key=another-value",
                "ovn-uplink-network-type": "bridge",
            },
        )

        ctx.run(ctx.on.relation_changed(relation=ovsdb_cms_relation), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Configuring OVN northbound connection"),
            scenario.MaintenanceStatus("Creating OVN network"),
        ]
        set_ovn_northbound_connection.assert_called_once_with(
            incus.OvnConnectionOptions(
                client_cert="any-server-cert",
                client_key="any-server-key",
                client_ca="any-ca",
                northbound_connection=expected_connection,
            )
        )

        assert cluster_relation.local_app_data.get("ovn-nb-connection-ready") == "true"
        assert cluster_relation.local_app_data.get("created-network") == '["ovn"]'


def test_ovsdb_cms_relation_changed_leader_no_addresses():
    """Test the ovsdb-cms-relation-changed event on leader units when no addresses are present in the relation data.

    The unit skip the event.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.incus.set_ovn_northbound_connection") as set_ovn_northbound_connection,
    ):
        ctx = scenario.Context(IncusCharm)
        ovsdb_cms_relation = scenario.Relation(
            endpoint="ovsdb-cms",
            interface="ovsdb-cms",
            remote_units_data={0: {}},
        )
        cluster_relation = scenario.PeerRelation(
            endpoint="cluster",
            interface="incus-cluster",
            local_app_data={
                "tokens": "{}",
                "cluster-certificate": "any-cluster-certificate",
                "created-storage": "[]",
                "created-network": "[]",
            },
        )
        state = scenario.State(leader=True, relations={ovsdb_cms_relation, cluster_relation})

        ctx.run(ctx.on.relation_changed(relation=ovsdb_cms_relation), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]
        set_ovn_northbound_connection.assert_not_called()


def test_ovsdb_cms_relation_changed_leader_network_created():
    """Test the ovsdb-cms-relation-changed event on leader units when the OVN network is already created.

    The unit should collect the ovn northbound database endpoints from the
    relation data and set them in Incus. It should not try to create a new
    OVN network.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.incus.set_ovn_northbound_connection") as set_ovn_northbound_connection,
        patch("charm.incus.create_network") as create_network,
    ):
        ctx = scenario.Context(IncusCharm)
        ovsdb_cms_relation = scenario.Relation(
            endpoint="ovsdb-cms",
            interface="ovsdb-cms",
            remote_units_data={
                i: {"bound-address": f'"{v}"'}
                for i, v in enumerate(["10.10.10.1", "10.10.10.2", "10.10.11.3"])
            },
        )
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_units_data={
                0: {
                    "ca": "any-ca",
                    "client.cert": "any-client-cert",
                    "client.key": "any-client-key",
                    "incus_0.server.cert": "any-server-cert",
                    "incus_0.server.key": "any-server-key",
                },
            },
        )
        cluster_relation = scenario.PeerRelation(
            endpoint="cluster",
            interface="incus-cluster",
            local_app_data={
                "tokens": "{}",
                "cluster-certificate": "any-cluster-certificate",
                "created-storage": "[]",
                "created-network": '["ovn"]',
                "ovn-nb-connection-ready": "true",
            },
        )
        state = scenario.State(
            leader=True, relations={ovsdb_cms_relation, certificates_relation, cluster_relation}
        )

        ctx.run(ctx.on.relation_changed(relation=ovsdb_cms_relation), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Configuring OVN northbound connection"),
        ]
        set_ovn_northbound_connection.assert_called_once_with(
            incus.OvnConnectionOptions(
                client_cert="any-server-cert",
                client_key="any-server-key",
                client_ca="any-ca",
                northbound_connection="ssl:10.10.10.1:6641,ssl:10.10.10.2:6641,ssl:10.10.11.3:6641",
            )
        )
        create_network.assert_not_called()


def test_ovsdb_cms_relation_changed_leader_bridge_uplink():
    """Test the ovsdb-cms-relation-changed event on leader units when it triggers the creation of an OVN network with a bridge uplink.

    The unit should collect the ovn northbound database endpoints from the
    relation data, set them in Incus and create a new OVN network as well as
    its uplink network.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.incus.set_ovn_northbound_connection") as set_ovn_northbound_connection,
        patch("charm.incus.create_network") as create_network,
    ):
        ctx = scenario.Context(IncusCharm)
        ovsdb_cms_relation = scenario.Relation(
            endpoint="ovsdb-cms",
            interface="ovsdb-cms",
            remote_units_data={
                i: {"bound-address": f'"{v}"'}
                for i, v in enumerate(["10.10.10.1", "10.10.10.2", "10.10.11.3"])
            },
        )
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_units_data={
                0: {
                    "ca": "any-ca",
                    "client.cert": "any-client-cert",
                    "client.key": "any-client-key",
                    "incus_0.server.cert": "any-server-cert",
                    "incus_0.server.key": "any-server-key",
                },
            },
        )
        cluster_relation = scenario.PeerRelation(
            endpoint="cluster",
            interface="incus-cluster",
            local_app_data={
                "tokens": "{}",
                "cluster-certificate": "any-cluster-certificate",
                "created-storage": "[]",
                "created-network": "[]",
            },
            local_unit_data={
                "node-name": "node-0",
                "joined-cluster-at": "2024-12-03T12:28:53.206680+00:00",
            },
            peers_data={
                1: {"node-name": "node-1"},
                2: {
                    "node-name": "node-2",
                    "joined-cluster-at": "2024-12-03T12:28:58.206680+00:00",
                },
            },
        )

        state = scenario.State(
            leader=True,
            relations={ovsdb_cms_relation, certificates_relation, cluster_relation},
            config={
                "ovn-uplink-network-type": "bridge",
                "ovn-uplink-network-config": "any-key=any-value another-key=another-value",
                "ovn-network-config": "any-ovn-key=any-ovn-value another-ovn-key=another-ovn-value",
            },
        )

        ctx.run(ctx.on.relation_changed(relation=ovsdb_cms_relation), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Configuring OVN northbound connection"),
            scenario.MaintenanceStatus("Creating OVN network"),
        ]
        set_ovn_northbound_connection.assert_called_once_with(
            incus.OvnConnectionOptions(
                client_cert="any-server-cert",
                client_key="any-server-key",
                client_ca="any-ca",
                northbound_connection="ssl:10.10.10.1:6641,ssl:10.10.10.2:6641,ssl:10.10.11.3:6641",
            )
        )
        create_network.assert_has_calls(
            [
                call(
                    network_name="UPLINK",
                    network_type="bridge",
                    target="node-0",
                    network_config={},
                ),
                call(
                    network_name="UPLINK",
                    network_type="bridge",
                    target="node-2",
                    network_config={},
                ),
                call(
                    network_name="UPLINK",
                    network_type="bridge",
                    network_config={
                        "any-key": "any-value",
                        "another-key": "another-value",
                    },
                ),
                call(
                    network_name="ovn",
                    network_type="ovn",
                    network_config={
                        "network": "UPLINK",
                        "any-ovn-key": "any-ovn-value",
                        "another-ovn-key": "another-ovn-value",
                    },
                ),
            ]
        )

        assert cluster_relation.local_app_data.get("ovn-nb-connection-ready") == "true"
        assert cluster_relation.local_app_data.get("created-network") == '["ovn"]'


def test_ovsdb_cms_relation_changed_leader_physical_uplink():
    """Test the ovsdb-cms-relation-changed event on leader units when it triggers the creation of an OVN network with a physical uplink.

    The unit should collect the ovn northbound database endpoints from the
    relation data, set them in Incus and create a new OVN network as well as
    its uplink network.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.incus.set_ovn_northbound_connection") as set_ovn_northbound_connection,
        patch("charm.incus.create_network") as create_network,
    ):
        ctx = scenario.Context(IncusCharm)
        ovsdb_cms_relation = scenario.Relation(
            endpoint="ovsdb-cms",
            interface="ovsdb-cms",
            remote_units_data={
                i: {"bound-address": f'"{v}"'}
                for i, v in enumerate(["10.10.10.1", "10.10.10.2", "10.10.11.3"])
            },
        )
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_units_data={
                0: {
                    "ca": "any-ca",
                    "client.cert": "any-client-cert",
                    "client.key": "any-client-key",
                    "incus_0.server.cert": "any-server-cert",
                    "incus_0.server.key": "any-server-key",
                },
            },
        )
        cluster_relation = scenario.PeerRelation(
            endpoint="cluster",
            interface="incus-cluster",
            local_app_data={
                "tokens": "{}",
                "cluster-certificate": "any-cluster-certificate",
                "created-storage": "[]",
                "created-network": "[]",
            },
            local_unit_data={
                "node-name": "node-0",
                "joined-cluster-at": "2024-12-03T12:28:53.206680+00:00",
            },
            peers_data={
                1: {"node-name": "node-1"},
                2: {
                    "node-name": "node-2",
                    "joined-cluster-at": "2024-12-03T12:28:58.206680+00:00",
                    "ovn-uplink-interface": "eno2",
                },
            },
        )
        state = scenario.State(
            leader=True,
            relations={ovsdb_cms_relation, certificates_relation, cluster_relation},
            config={
                "ovn-uplink-network-type": "physical",
                "ovn-uplink-network-config": "any-key=any-value another-key=another-value",
                "ovn-network-config": "any-ovn-key=any-ovn-value another-ovn-key=another-ovn-value",
                "ovn-uplink-network-parent-interface": "any-uplink-interface",
            },
        )

        ctx.run(ctx.on.relation_changed(relation=ovsdb_cms_relation), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Configuring OVN northbound connection"),
            scenario.MaintenanceStatus("Creating OVN network"),
        ]
        set_ovn_northbound_connection.assert_called_once_with(
            incus.OvnConnectionOptions(
                client_cert="any-server-cert",
                client_key="any-server-key",
                client_ca="any-ca",
                northbound_connection="ssl:10.10.10.1:6641,ssl:10.10.10.2:6641,ssl:10.10.11.3:6641",
            )
        )
        create_network.assert_has_calls(
            [
                call(
                    network_name="UPLINK",
                    network_type="physical",
                    target="node-0",
                    network_config={"parent": "any-uplink-interface"},
                ),
                call(
                    network_name="UPLINK",
                    network_type="physical",
                    target="node-2",
                    network_config={"parent": "any-uplink-interface"},
                ),
                call(
                    network_name="UPLINK",
                    network_type="physical",
                    network_config={
                        "any-key": "any-value",
                        "another-key": "another-value",
                    },
                ),
                call(
                    network_name="ovn",
                    network_type="ovn",
                    network_config={
                        "network": "UPLINK",
                        "any-ovn-key": "any-ovn-value",
                        "another-ovn-key": "another-ovn-value",
                    },
                ),
            ]
        )

        assert cluster_relation.local_app_data.get("ovn-nb-connection-ready") == "true"
        assert cluster_relation.local_app_data.get("created-network") == '["ovn"]'
