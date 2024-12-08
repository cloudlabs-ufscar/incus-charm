# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import json
from unittest.mock import call, patch

import charmhelpers.contrib.storage.linux.ceph as ceph_client
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
        state = scenario.State(
            leader=leader, relations={relation, scenario.PeerRelation(endpoint="cluster")}
        )

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
        state = scenario.State(
            leader=leader, relations={relation, scenario.PeerRelation(endpoint="cluster")}
        )

        ctx.run(ctx.on.relation_created(relation=relation), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]
        install_packages.assert_not_called()
        restart_service.assert_not_called()


def test_ceph_relation_changed_non_leader():
    """Test the ceph-relation-changed event when the unit is not clustered.

    The unit should write the relation data to the appropriate config files.
    """
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.ceph.write_keyring_file") as write_keyring_file,
        patch("charm.ceph.write_ceph_conf_file") as write_ceph_conf_file,
        patch("charm.ceph_client.is_request_complete") as is_request_complete,
        patch("charm.ceph_client.send_request_if_needed") as send_request_if_needed,
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
        state = scenario.State(
            leader=False, relations={relation, scenario.PeerRelation(endpoint="cluster")}
        )

        ctx.run(ctx.on.relation_changed(relation=relation), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Updating Ceph configuration files"),
        ]
        write_keyring_file.assert_called_once_with(ceph_user="any-app-name", key="any-ceph-key")
        write_ceph_conf_file.assert_called_once_with(
            {"10.18.196.157", "10.18.196.158", "10.18.196.159"}
        )
        is_request_complete.assert_not_called()
        send_request_if_needed.assert_not_called()


def test_ceph_relation_changed_leader():
    """Test the ceph-relation-changed event when the unit is the leader.

    The unit should write the relation data to the appropriate config files and
    request the creation of a Ceph storage pool in the relation.
    """
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.ceph.write_keyring_file") as write_keyring_file,
        patch("charm.ceph.write_ceph_conf_file") as write_ceph_conf_file,
        patch("charm.ceph_client.is_request_complete", return_value=False) as is_request_complete,
        patch("charm.ceph_client.send_request_if_needed") as send_request_if_needed,
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
        state = scenario.State(
            leader=True, relations={relation, scenario.PeerRelation(endpoint="cluster")}
        )

        ctx.run(ctx.on.relation_changed(relation=relation), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Updating Ceph configuration files"),
            scenario.MaintenanceStatus("Requesting Ceph pool creation"),
        ]
        write_keyring_file.assert_called_once_with(ceph_user="any-app-name", key="any-ceph-key")
        write_ceph_conf_file.assert_called_once_with(
            {"10.18.196.157", "10.18.196.158", "10.18.196.159"}
        )
        is_request_complete.assert_called_once()
        ceph_request = ceph_client.CephBrokerRq()
        ceph_request.add_op_create_replicated_pool(
            name="incus", replica_count=3, app_name="any-app-name"
        )
        assert send_request_if_needed.call_args.args[0] == ceph_request


def test_ceph_relation_changed_not_clustered_storage_pool_created():
    """Test the ceph-relation-changed event when the unit is not clustered and the storage pool is created.

    Should create the Ceph storage pool on the Incus server.
    """
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.ceph.write_keyring_file") as write_keyring_file,
        patch("charm.ceph.write_ceph_conf_file") as write_ceph_conf_file,
        patch("charm.ceph_client.is_request_complete", return_value=True) as is_request_complete,
        patch("charm.incus.create_storage") as create_storage,
    ):
        ctx = scenario.Context(IncusCharm, app_name="any-app-name")
        ceph_relation = scenario.Relation(
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
        cluster_relation = scenario.PeerRelation(
            endpoint="cluster",
            local_app_data={
                "tokens": "{}",
                "created-storage": "[]",
                "cluster-certificate": "any-certificates",
            },
        )
        state = scenario.State(
            leader=True,
            relations={ceph_relation, cluster_relation},
            config={
                "ceph-rbd-features": "any-rbd-feature,another-rbd-feature",
            },
        )

        out = ctx.run(ctx.on.relation_changed(relation=ceph_relation), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Updating Ceph configuration files"),
            scenario.MaintenanceStatus("Creating Ceph storage pool on Incus"),
        ]
        write_keyring_file.assert_called_once_with(ceph_user="any-app-name", key="any-ceph-key")
        write_ceph_conf_file.assert_called_once_with(
            {"10.18.196.157", "10.18.196.158", "10.18.196.159"}
        )
        is_request_complete.assert_called_once()
        create_storage.assert_called_once_with(
            pool_name="ceph",
            storage_driver="ceph",
            source="incus",
            pool_config={
                "ceph.user.name": "any-app-name",
                "ceph.rbd.features": "any-rbd-feature,another-rbd-feature",
            },
        )
        cluster_relation = out.get_relation(cluster_relation.id)
        assert cluster_relation.local_app_data["created-storage"] == json.dumps(["ceph"])


def test_ceph_relation_changed_leader_storage_pool_created():
    """Test the ceph-relation-changed event when the unit is the leader and the storage pool is created.

    The unit should create a pending storage pool on all cluster members that
    already joined the cluster and then instantiate the storage pool on the cluster.
    """
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.ceph.write_keyring_file") as write_keyring_file,
        patch("charm.ceph.write_ceph_conf_file") as write_ceph_conf_file,
        patch("charm.ceph_client.is_request_complete", return_value=True) as is_request_complete,
        patch("charm.incus.create_storage") as create_storage,
    ):
        ctx = scenario.Context(IncusCharm, app_name="any-app-name")
        ceph_relation = scenario.Relation(
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
        cluster_relation = scenario.PeerRelation(
            endpoint="cluster",
            peers_data={
                1: {"node-name": "node-1"},
                2: {
                    "node-name": "node-2",
                    "joined-cluster-at": "2024-12-03T12:28:58.206680+00:00",
                },
            },
            local_app_data={
                "tokens": "{}",
                "created-storage": "[]",
                "cluster-certificate": "any-certificates",
            },
            local_unit_data={
                "node-name": "node-0",
                "joined-cluster-at": "2024-12-03T12:28:53.206680+00:00",
            },
        )
        state = scenario.State(
            leader=True,
            relations={ceph_relation, cluster_relation},
            config={
                "ceph-rbd-features": "any-rbd-feature,another-rbd-feature",
            },
        )

        out = ctx.run(ctx.on.relation_changed(relation=ceph_relation), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Updating Ceph configuration files"),
            scenario.MaintenanceStatus("Creating Ceph storage pool on Incus"),
        ]
        write_keyring_file.assert_called_once_with(ceph_user="any-app-name", key="any-ceph-key")
        write_ceph_conf_file.assert_called_once_with(
            {"10.18.196.157", "10.18.196.158", "10.18.196.159"}
        )
        is_request_complete.assert_called_once()
        create_storage.assert_has_calls(
            [
                call(
                    pool_name="ceph",
                    storage_driver="ceph",
                    source="incus",
                    target="node-2",
                ),
                call(
                    pool_name="ceph",
                    storage_driver="ceph",
                    source="incus",
                    target="node-0",
                ),
                call(
                    pool_name="ceph",
                    storage_driver="ceph",
                    pool_config={
                        "ceph.user.name": "any-app-name",
                        "ceph.rbd.features": "any-rbd-feature,another-rbd-feature",
                    },
                ),
            ]
        )
        cluster_relation = out.get_relation(cluster_relation.id)
        assert cluster_relation.local_app_data["created-storage"] == json.dumps(["ceph"])


def test_ceph_relation_changed_leader_storage_pool_created_invalid_app_data():
    """Test the ceph-relation-changed event when the unit is the leader and the storage pool is created and the app data is invalid.

    The unit should defer the event.
    """
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.ceph.write_keyring_file") as write_keyring_file,
        patch("charm.ceph.write_ceph_conf_file") as write_ceph_conf_file,
        patch("charm.ceph_client.is_request_complete", return_value=True) as is_request_complete,
        patch("charm.incus.create_storage") as create_storage,
    ):
        ctx = scenario.Context(IncusCharm, app_name="any-app-name")
        ceph_relation = scenario.Relation(
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
        cluster_relation = scenario.PeerRelation(
            endpoint="cluster",
            peers_data={
                1: {"node-name": "node-1"},
                2: {
                    "node-name": "node-2",
                    "joined-cluster-at": "2024-12-03T12:28:58.206680+00:00",
                },
            },
            local_app_data={
                "tokens": "{}",
                "cluster-certificate": "any-certificates",
            },
            local_unit_data={
                "node-name": "node-0",
                "joined-cluster-at": "2024-12-03T12:28:53.206680+00:00",
            },
        )
        state = scenario.State(leader=True, relations={ceph_relation, cluster_relation})

        out = ctx.run(ctx.on.relation_changed(relation=ceph_relation), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Updating Ceph configuration files"),
        ]
        write_keyring_file.assert_called_once_with(ceph_user="any-app-name", key="any-ceph-key")
        write_ceph_conf_file.assert_called_once_with(
            {"10.18.196.157", "10.18.196.158", "10.18.196.159"}
        )
        is_request_complete.assert_called_once()
        create_storage.assert_not_called()
        assert len(out.deferred) == 1


def test_ceph_relation_changed_leader_storage_pool_created_on_incus():
    """Test the ceph-relation-changed event when the unit is the leader and the storage pool is created on Incus.

    The unit should skip the creation of the storage pool.
    """
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.ceph.write_keyring_file") as write_keyring_file,
        patch("charm.ceph.write_ceph_conf_file") as write_ceph_conf_file,
        patch("charm.ceph_client.is_request_complete", return_value=True) as is_request_complete,
        patch("charm.incus.create_storage") as create_storage,
    ):
        ctx = scenario.Context(IncusCharm, app_name="any-app-name")
        ceph_relation = scenario.Relation(
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
        cluster_relation = scenario.PeerRelation(
            endpoint="cluster",
            peers_data={
                1: {"node-name": "node-1"},
                2: {
                    "node-name": "node-2",
                    "joined-cluster-at": "2024-12-03T12:28:58.206680+00:00",
                },
            },
            local_app_data={
                "tokens": "{}",
                "created-storage": '["ceph"]',
                "cluster-certificate": "any-certificates",
            },
            local_unit_data={
                "node-name": "node-0",
                "joined-cluster-at": "2024-12-03T12:28:53.206680+00:00",
            },
        )
        state = scenario.State(leader=True, relations={ceph_relation, cluster_relation})

        ctx.run(ctx.on.relation_changed(relation=ceph_relation), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Updating Ceph configuration files"),
        ]
        write_keyring_file.assert_called_once_with(ceph_user="any-app-name", key="any-ceph-key")
        write_ceph_conf_file.assert_called_once_with(
            {"10.18.196.157", "10.18.196.158", "10.18.196.159"}
        )
        is_request_complete.assert_called_once()
        create_storage.assert_not_called()
