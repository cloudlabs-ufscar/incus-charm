# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing


from unittest.mock import patch

import pytest
import scenario

from charm import IncusCharm
from incus import ClusterMemberInfo, ClusterMemberStatus, IncusProcessError


def test_incus_evacuate_error():
    """Test the evacuate action when there's an Incus error.

    The error should be returned to the operator.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.is_clustered", return_value=True),
        patch(
            "charm.incus.evacuate_node",
            side_effect=IncusProcessError("any-incus-error"),
        ) as evacuate,
        patch(
            "charm.incus.get_cluster_member_info",
            return_value=ClusterMemberInfo(
                status=ClusterMemberStatus.ONLINE, message="any message"
            ),
        ),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State()

        with pytest.raises(scenario.ActionFailed) as exc_info:
            ctx.run(ctx.on.action("evacuate"), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Evacuating node"),
        ]
        evacuate.assert_called_once()
        assert exc_info.value.message == "any-incus-error"


def test_incus_restore_error():
    """Test the cluster-list action when there's an Incus error.

    The error should be returned to the operator.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.is_clustered", return_value=True),
        patch(
            "charm.incus.restore_node",
            side_effect=IncusProcessError("any-incus-error"),
        ) as restore,
        patch(
            "charm.incus.get_cluster_member_info",
            return_value=ClusterMemberInfo(
                status=ClusterMemberStatus.EVACUATED, message="any message"
            ),
        ),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State()

        with pytest.raises(scenario.ActionFailed) as exc_info:
            ctx.run(ctx.on.action("restore"), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Restoring node"),
        ]
        restore.assert_called_once()
        assert exc_info.value.message == "any-incus-error"


def test_evacuate_unit_not_in_cluster():
    """Test the evacuate action when the unit is not clustered.

    No action should be performed in the Incus instance. An error should
    be returned to the operator.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.evacuate_node") as evacuate,
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State()

        with pytest.raises(scenario.ActionFailed) as exc_info:
            ctx.run(ctx.on.action("evacuate"), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]
        evacuate.assert_not_called()
        assert exc_info.value.message == "Unit is not clustered"


def test_restore_unit_not_in_cluster():
    """Test the restore action when the unit is not clustered.

    No action should be performed in the Incus instance. An error should
    be returned to the operator.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.restore_node") as restore,
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State()

        with pytest.raises(scenario.ActionFailed) as exc_info:
            ctx.run(ctx.on.action("restore"), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]
        restore.assert_not_called()
        assert exc_info.value.message == "Unit is not clustered"


def test_evacuate_success():
    """Test the evacuate action.

    The evacuate action should be called by the Incus instance
    and this member would be successfully evacuated from the cluster.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.evacuate_node") as evacuate,
        patch(
            "charm.incus.get_cluster_member_info",
            return_value=ClusterMemberInfo(
                status=ClusterMemberStatus.ONLINE, message="any message"
            ),
        ),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State()

        ctx.run(ctx.on.action("evacuate"), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Evacuating node"),
        ]
        evacuate.assert_called_once()
        assert ctx.action_results == {"result": "Incus member evacuated from the cluster"}


def test_restore_success():
    """Test the restore action.

    The restore action should be called by the Incus instance
    and this member would be successfully restored to the cluster.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.restore_node") as restore,
        patch(
            "charm.incus.get_cluster_member_info",
            return_value=ClusterMemberInfo(
                status=ClusterMemberStatus.EVACUATED, message="any message"
            ),
        ),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State()

        ctx.run(ctx.on.action("restore"), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Restoring node"),
        ]
        restore.assert_called_once()
        assert ctx.action_results == {"result": "Incus member restored to the cluster"}


@pytest.mark.parametrize(
    "member_info",
    [
        ClusterMemberInfo(status=ClusterMemberStatus.BLOCKED, message="any message"),
        ClusterMemberInfo(status=ClusterMemberStatus.OFFLINE, message="any message"),
        ClusterMemberInfo(status=ClusterMemberStatus.EVACUATED, message="any message"),
    ],
)
def test_check_member_status_unsuccessfully_evacuated(member_info: ClusterMemberInfo):
    """Test the evacuate action when the unit is clustered.

    The unit should verify its status to set the next status.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.evacuate_node") as evacuate,
        patch("charm.incus.get_cluster_member_info", return_value=member_info),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State()

        with pytest.raises(scenario.ActionFailed) as exc_info:
            ctx.run(ctx.on.action("evacuate"), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]
        evacuate.assert_not_called()
        assert exc_info.value.message == "This member isn't online, so it cannot be evacuated"


@pytest.mark.parametrize(
    "member_info",
    [
        ClusterMemberInfo(status=ClusterMemberStatus.ONLINE, message="any message"),
        ClusterMemberInfo(status=ClusterMemberStatus.BLOCKED, message="any message"),
        ClusterMemberInfo(status=ClusterMemberStatus.OFFLINE, message="any message"),
    ],
)
def test_check_member_status_unsuccessfully_restored(member_info: ClusterMemberInfo):
    """Test the restore action when the unit is clustered.

    The unit should verify its status to set the next status.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.restore_node") as restore,
        patch("charm.incus.get_cluster_member_info", return_value=member_info),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State()

        with pytest.raises(scenario.ActionFailed) as exc_info:
            ctx.run(ctx.on.action("restore"), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]
        restore.assert_not_called()
        assert exc_info.value.message == "This member wasn't evacuated, so it cannot be restored"
