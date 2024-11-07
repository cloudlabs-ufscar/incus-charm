# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing


from unittest.mock import patch

import pytest
import scenario

from charm import IncusCharm
from incus import IncusProcessError


def test_incus_error():
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.incus.is_clustered", return_value=True),
        patch(
            "charm.incus.cluster_list",
            side_effect=IncusProcessError("any-incus-error"),
        ) as cluster_list,
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State()

        with pytest.raises(scenario.ActionFailed) as exc_info:
            ctx.run(ctx.on.action("cluster-list"), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]
        cluster_list.assert_called_once()
        assert exc_info.value.message == "any-incus-error"


def test_unit_not_in_cluster():
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.cluster_list") as cluster_list,
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State()

        with pytest.raises(scenario.ActionFailed) as exc_info:
            ctx.run(ctx.on.action("cluster-list"), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]
        cluster_list.assert_not_called()
        assert exc_info.value.message == "Unit is not clustered"


def test_success():
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.cluster_list", return_value="any-cluster-list-result") as cluster_list,
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State()

        ctx.run(ctx.on.action("cluster-list"), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]
        cluster_list.assert_called_once()
        assert ctx.action_results == {"result": "any-cluster-list-result"}
