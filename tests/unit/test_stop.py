# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing


from unittest.mock import patch

import scenario

from charm import IncusCharm


def test_stop_not_clustered():
    """Test the stop event on units that are not clustered.

    The unit should uninstall the incus package.
    """
    with (
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.incus.evacuate_node") as evacuate_node,
        patch("charm.incus.remove_cluster_member") as remove_cluster_member,
        patch("charm.IncusCharm._uninstall_package") as uninstall_package,
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State()

        ctx.run(ctx.on.stop(), state)

        evacuate_node.assert_not_called()
        remove_cluster_member.assert_not_called()
        uninstall_package.assert_called_once()
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Uninstalling packages"),
        ]


def test_stop_clustered():
    """Test the stop event on units that are clustered.

    The unit should evacuate itself, leave the cluster and then
    uninstall the incus package.
    """
    with (
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.incus.evacuate_node") as evacuate_node,
        patch("charm.incus.remove_cluster_member") as remove_cluster_member,
        patch("charm.IncusCharm._uninstall_package") as uninstall_package,
        patch("charm.IncusCharm._node_name", "any-node-name"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State()

        ctx.run(ctx.on.stop(), state)

        evacuate_node.assert_called_once_with("any-node-name")
        remove_cluster_member.assert_called_once_with("any-node-name")
        uninstall_package.assert_called_once()
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Evacuating node"),
            scenario.MaintenanceStatus("Leaving cluster"),
            scenario.MaintenanceStatus("Uninstalling packages"),
        ]
