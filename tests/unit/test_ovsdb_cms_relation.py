from typing import List
from unittest.mock import patch

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
                northbound_connection=expected_connection,
            )
        )
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
