# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing


from unittest.mock import patch

import scenario

from charm import IncusCharm


def test_start_leader_not_clustered():
    """Test the start event when the leader unit is not clustered.

    The unit should bootstrap Incus.
    """
    with (
        patch("charm.IncusCharm._add_apt_repository"),
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.bootstrap_node") as bootstrap_node,
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(leader=True)

        ctx.run(ctx.on.start(), state)

        bootstrap_node.assert_called_once_with(
            {
                "networks": [
                    {
                        "name": "incusbr0",
                        "description": "Default network",
                        "type": "",
                        "project": "default",
                        "config": {"ipv4.address": "auto", "ipv6.address": "auto"},
                    }
                ],
                "profiles": [
                    {
                        "name": "default",
                        "description": "Default profile",
                        "config": {},
                        "devices": {
                            "eth0": {"name": "eth0", "network": "incusbr0", "type": "nic"},
                            "root": {"path": "/", "pool": "default", "type": "disk"},
                        },
                    }
                ],
                "projects": [],
                "storage_pools": [
                    {
                        "name": "default",
                        "description": "Default storage pool",
                        "driver": "zfs",
                        "config": {},
                    }
                ],
            }
        )


def test_start_leader_not_clustered_local_storage_config():
    """Test the start event when the leader unit is not clustered and local storage is configured.

    The unit should bootstrap Incus and apply the appropriate config to the local storage pool.
    """
    with (
        patch("charm.IncusCharm._add_apt_repository"),
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.bootstrap_node") as bootstrap_node,
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            leader=True,
            config={
                "create-local-storage-pool": True,
                "local-storage-pool-driver": "lvm",
                "local-storage-pool-config": "any-key=any-value another-key=another-value",
            },
        )

        ctx.run(ctx.on.start(), state)

        bootstrap_node.assert_called_once_with(
            {
                "networks": [
                    {
                        "name": "incusbr0",
                        "description": "Default network",
                        "type": "",
                        "project": "default",
                        "config": {"ipv4.address": "auto", "ipv6.address": "auto"},
                    }
                ],
                "profiles": [
                    {
                        "name": "default",
                        "description": "Default profile",
                        "config": {},
                        "devices": {
                            "eth0": {"name": "eth0", "network": "incusbr0", "type": "nic"},
                            "root": {"path": "/", "pool": "default", "type": "disk"},
                        },
                    }
                ],
                "projects": [],
                "storage_pools": [
                    {
                        "name": "default",
                        "description": "Default storage pool",
                        "driver": "lvm",
                        "config": {
                            "any-key": "any-value",
                            "another-key": "another-value",
                        },
                    }
                ],
            }
        )


def test_start_leader_already_clustered():
    """Test the start event when the leader unit is already clustered.

    The unit should not try to bootstrap Incus again.
    """
    with (
        patch("charm.IncusCharm._add_apt_repository"),
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.bootstrap_node") as bootstrap_node,
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(leader=True)

        ctx.run(ctx.on.start(), state)

        bootstrap_node.assert_not_called()


def test_start_non_leader():
    """Test the start event on non leader units.

    The unit should not try to bootstrap Incus.
    """
    with (
        patch("charm.IncusCharm._add_apt_repository"),
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.bootstrap_node") as bootstrap_node,
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(leader=False)

        ctx.run(ctx.on.start(), state)

        bootstrap_node.assert_not_called()
