# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing


from unittest.mock import patch

import scenario

from charm import IncusCharm


def test_start_leader_not_clustered():
    with (
        patch("charm.IncusCharm._add_apt_repository"),
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.incus.bootstrap_node") as bootstrap_node,
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(leader=True)

        ctx.run(ctx.on.start(), state)

        bootstrap_node.assert_called_once()


def test_start_leader_already_clustered():
    with (
        patch("charm.IncusCharm._add_apt_repository"),
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.incus.bootstrap_node") as bootstrap_node,
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(leader=True)

        ctx.run(ctx.on.start(), state)

        bootstrap_node.assert_not_called()


def test_start_non_leader():
    with (
        patch("charm.IncusCharm._add_apt_repository"),
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.incus.bootstrap_node") as bootstrap_node,
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(leader=False)

        ctx.run(ctx.on.start(), state)

        bootstrap_node.assert_not_called()
