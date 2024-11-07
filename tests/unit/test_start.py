# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing


from unittest.mock import patch

import pytest
import scenario

from charm import IncusCharm


@pytest.mark.parametrize("is_clustered", (True, False))
def test_start_leader(is_clustered):
    with (
        patch("charm.IncusCharm._add_apt_repository"),
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.IncusCharm._install_package"),
        patch("charm.incus.bootstrap_node") as bootstrap_node,
        patch("charm.incus.is_clustered", return_value=is_clustered),
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(leader=True)

        ctx.run(ctx.on.start(), state)

        bootstrap_node.assert_called_once()


def test_start_non_leader():
    with (
        patch("charm.IncusCharm._add_apt_repository"),
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.IncusCharm._install_package"),
        patch("charm.incus.bootstrap_node") as bootstrap_node,
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(leader=False)

        ctx.run(ctx.on.start(), state)

        bootstrap_node.assert_not_called()
