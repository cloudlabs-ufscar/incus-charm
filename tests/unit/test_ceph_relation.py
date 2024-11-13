# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

from unittest.mock import patch

import pytest
import scenario

from charm import IncusCharm


@pytest.mark.parametrize(
    "leader,is_clustered", [(False, False), (True, False), (False, True), (True, True)]
)
def test_ceph_relation_created_driver_not_supported(leader, is_clustered):
    """Test the ceph-relation-created event when the ceph driver is not supported.

    The unit should install the needed packages and restart the Incus daemon.
    """
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.incus.is_clustered", return_value=is_clustered),
        patch(
            "charm.incus.get_supported_storage_drivers",
            side_effect=(
                ["btrfs", "dir", "lvm", "lvmcluster"],
                ["btrfs", "dir", "lvm", "lvmcluster", "ceph", "cephfs", "cephobject"],
            ),
        ),
        patch("charm.IncusCharm._install_packages") as install_packages,
        patch("charm.IncusCharm._restart_service") as restart_service,
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        relation = scenario.Relation(endpoint="ceph", interface="ceph-client")
        state = scenario.State(leader=leader, relations={relation})

        ctx.run(ctx.on.relation_created(relation=relation), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Installing ceph-common package"),
            scenario.MaintenanceStatus("Restarting incus service"),
        ]
        install_packages.assert_called_once_with("ceph-common")
        restart_service.assert_called_once_with("incus")


@pytest.mark.parametrize(
    "leader,is_clustered", [(False, False), (True, False), (False, True), (True, True)]
)
def test_ceph_relation_created_driver_supported(leader, is_clustered):
    """Test the ceph-relation-created event when the ceph driver is supported.

    The unit should not install any packages nor restart the Incus daemon.
    """
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.incus.is_clustered", return_value=is_clustered),
        patch(
            "charm.incus.get_supported_storage_drivers",
            return_value=["btrfs", "dir", "lvm", "lvmcluster", "ceph", "cephfs", "cephobject"],
        ),
        patch("charm.IncusCharm._install_packages") as install_packages,
        patch("charm.IncusCharm._restart_service") as restart_service,
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        relation = scenario.Relation(endpoint="ceph", interface="ceph-client")
        state = scenario.State(leader=leader, relations={relation})

        ctx.run(ctx.on.relation_created(relation=relation), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]
        install_packages.assert_not_called()
        restart_service.assert_not_called()


@pytest.mark.parametrize(
    "leader,is_clustered", [(False, False), (True, False), (False, True), (True, True)]
)
def test_ceph_relation_changed(leader, is_clustered):
    """Test the ceph-relation-changed event.

    The unit should write the relation data to the appropriate config files.
    """
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.incus.is_clustered", return_value=is_clustered),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.ceph.write_keyring_file") as write_keyring_file,
        patch("charm.ceph.write_ceph_conf_file") as write_ceph_conf_file,
    ):
        ctx = scenario.Context(IncusCharm, app_name="any-app-name")
        relation = scenario.Relation(
            endpoint="ceph",
            interface="ceph-client",
            remote_units_data={
                0: {
                    "key": "any-ceph-key",
                    "ceph-public-address": "10.18.196.157",
                    "auth": "cephx",
                },
                1: {
                    "key": "any-ceph-key",
                    "ceph-public-address": "10.18.196.158",
                    "auth": "cephx",
                },
                2: {
                    "key": "any-ceph-key",
                    "ceph-public-address": "10.18.196.159",
                    "auth": "cephx",
                },
            },
        )
        state = scenario.State(leader=leader, relations={relation})

        ctx.run(ctx.on.relation_changed(relation=relation), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Updating Ceph configuration files"),
        ]
        write_keyring_file.assert_called_once_with(ceph_user="any-app-name", key="any-ceph-key")
        write_ceph_conf_file.assert_called_once_with(
            {"10.18.196.157", "10.18.196.158", "10.18.196.159"}
        )
