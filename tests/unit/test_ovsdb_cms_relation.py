from typing import List
from unittest.mock import patch

import pytest
import scenario

from charm import IncusCharm


@pytest.mark.parametrize("address", ["192.168.0.2", "10.0.2.84", "38.28.79.12"])
def test_ovsdb_cms_relation_created(address: str):
    """Test the ovsdb-cms-relation-created event.

    The unit should put the IP address for the binding associated with the
    relation in the relation data.
    """
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        relation = scenario.Relation(endpoint="ovsdb-cms", interface="ovsdb-cms")
        network = scenario.Network(
            binding_name="ovsdb-cms",
            bind_addresses=[scenario.BindAddress([scenario.Address(address)])],
        )
        state = scenario.State(leader=True, relations={relation}, networks={network})

        ctx.run(ctx.on.relation_created(relation=relation), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]
        assert relation.local_unit_data.get("cms-client-bound-address") == address


def test_ovsdb_cms_relation_changed_non_leader():
    """Test the ovsdb-cms-relation-changed event on non leader units.

    The unit should skip the event.
    """
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.incus.set_ovn_northbound_connection") as set_ovn_northbound_connection,
    ):
        ctx = scenario.Context(IncusCharm)
        relation = scenario.Relation(endpoint="ovsdb-cms", interface="ovsdb-cms")
        state = scenario.State(leader=False, relations={relation})

        ctx.run(ctx.on.relation_changed(relation=relation), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]
        set_ovn_northbound_connection.assert_not_called()


@pytest.mark.parametrize(
    "addresses,expected",
    [
        (["10.0.0.1"], "ssl:10.0.0.1:6641"),
        (
            ["10.10.10.1", "10.10.10.2", "10.10.11.3"],
            "ssl:10.10.10.1:6641,ssl:10.10.10.2:6641,ssl:10.10.11.3:6641",
        ),
    ],
)
def test_ovsdb_cms_relation_changed_leader(addresses: List[str], expected: str):
    """Test the ovsdb-cms-relation-changed event on leader units.

    The unit should collect the ovn northbound database endpoints from the
    relation data and set them in Incus.
    """
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.incus.set_ovn_northbound_connection") as set_ovn_northbound_connection,
    ):
        ctx = scenario.Context(IncusCharm)
        relation = scenario.Relation(
            endpoint="ovsdb-cms",
            interface="ovsdb-cms",
            remote_units_data={i: {"bound-address": v} for i, v in enumerate(addresses)},
        )
        state = scenario.State(leader=True, relations={relation})

        ctx.run(ctx.on.relation_changed(relation=relation), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Configuring OVN northbound connection endpoints"),
        ]
        set_ovn_northbound_connection.assert_called_once_with(expected)


def test_ovsdb_cms_relation_changed_leader_no_addresses():
    """Test the ovsdb-cms-relation-changed event on leader units when no addresses are present in the relation data.

    The unit skip the event.
    """
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.incus.set_ovn_northbound_connection") as set_ovn_northbound_connection,
    ):
        ctx = scenario.Context(IncusCharm)
        relation = scenario.Relation(
            endpoint="ovsdb-cms",
            interface="ovsdb-cms",
            remote_units_data={0: {}},
        )
        state = scenario.State(leader=True, relations={relation})

        ctx.run(ctx.on.relation_changed(relation=relation), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]
        set_ovn_northbound_connection.assert_not_called()
