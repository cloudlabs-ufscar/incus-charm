# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing


from unittest.mock import patch

import pytest
import scenario

from charm import IncusCharm
from incus import IncusProcessError


@pytest.mark.parametrize("format", ("", "any-invalid-format"))
def test_invalid_input(format):
    """Test the cluster-list action with invalid input.

    No action should be performed in the Incus instance. An error should
    be returned to the operator.
    """
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
            ctx.run(ctx.on.action("cluster-list", params={"format": format}), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]
        cluster_list.assert_not_called()
        assert (
            "unexpected value; permitted: 'csv', 'json', 'table', 'yaml', 'compact'"
            in exc_info.value.message
        )


def test_incus_error():
    """Test the cluster-list action when there's an Incus error.

    The error should be returned to the operator.
    """
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
            ctx.run(ctx.on.action("cluster-list", params={"format": "table"}), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]
        cluster_list.assert_called_once()
        assert exc_info.value.message == "any-incus-error"


def test_unit_not_in_cluster():
    """Test the cluster-list action when the unit is not clustered.

    No action should be performed in the Incus instance. An error should
    be returned to the operator.
    """
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.cluster_list") as cluster_list,
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State()

        with pytest.raises(scenario.ActionFailed) as exc_info:
            ctx.run(ctx.on.action("cluster-list", params={"format": "table"}), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]
        cluster_list.assert_not_called()
        assert exc_info.value.message == "Unit is not clustered"


def test_success():
    """Test the cluster-list action.

    The unit should call return the output of the incus cluster list command
    to the operator.
    """
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.cluster_list", return_value="any-cluster-list-result") as cluster_list,
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State()

        ctx.run(ctx.on.action("cluster-list", params={"format": "table"}), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]
        cluster_list.assert_called_once()
        assert ctx.action_results == {"result": "any-cluster-list-result"}
