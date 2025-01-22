# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing


from unittest.mock import patch

import pytest
import scenario

from charm import IncusCharm
from incus import ClusterMemberInfo, ClusterMemberStatus


def test_collect_unit_status_package_not_installed():
    """Test the collect-unit-status-event when the incus package is not installed.

    The unit should be in a blocked state.
    """
    with patch("charm.IncusCharm._package_installed", return_value=False):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(leader=True)

        out = ctx.run(ctx.on.collect_unit_status(), state)

        assert out.unit_status == scenario.BlockedStatus("Package 'incus' not installed")


def test_collect_unit_status_leader_not_clustered():
    """Test the collect-unit-status-event when the leader unit is not clustered.

    The unit should be in a ready state.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.is_clustered", return_value=False),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(leader=True)

        out = ctx.run(ctx.on.collect_unit_status(), state)

        assert out.unit_status == scenario.ActiveStatus("Unit is ready")


def test_collect_unit_status_non_leader_not_clustered():
    """Test the collect-unit-status-event when the non leader unit is not clustered.

    The unit should be in a waiting state, signaling that it is waiting for
    a join token.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.is_clustered", return_value=False),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(leader=False)

        out = ctx.run(ctx.on.collect_unit_status(), state)

        assert out.unit_status == scenario.WaitingStatus("Waiting for cluster token")


@pytest.mark.parametrize(
    "member_info,expected_status",
    [
        (
            ClusterMemberInfo(status=ClusterMemberStatus.ONLINE, message="any message"),
            scenario.ActiveStatus("Online: any message"),
        ),
        (
            ClusterMemberInfo(status=ClusterMemberStatus.BLOCKED, message="any message"),
            scenario.BlockedStatus("Blocked: any message"),
        ),
        (
            ClusterMemberInfo(status=ClusterMemberStatus.OFFLINE, message="any message"),
            scenario.BlockedStatus("Offline: any message"),
        ),
        (
            ClusterMemberInfo(status=ClusterMemberStatus.EVACUATED, message="any message"),
            scenario.MaintenanceStatus("Evacuated: any message"),
        ),
    ],
)
def test_collect_unit_status_cluster_info(member_info: ClusterMemberInfo, expected_status):
    """Test the collect-unit-status-event when the unit is clustered.

    The unit should use the Incus cluster state to set its own status.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info", return_value=member_info),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(leader=True)

        out = ctx.run(ctx.on.collect_unit_status(), state)

        assert out.unit_status == expected_status
