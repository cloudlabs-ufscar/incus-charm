# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

from unittest.mock import patch

import scenario

from charm import IncusCharm


def test_cluster_relation_created_leader():
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch("charm.incus.is_clustered", return_value=False),
    ):
        ctx = scenario.Context(IncusCharm)
        relation = scenario.PeerRelation(endpoint="cluster", interface="incus-cluster")
        state = scenario.State(leader=True, relations={relation})

        out = ctx.run(ctx.on.relation_created(relation=relation), state)

        relation = out.get_relation(relation.id)
        assert relation.local_unit_data["node-name"] == "any-node-name"
        assert relation.local_app_data["tokens"] == "{}"


def test_cluster_relation_created_non_leader():
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch("charm.incus.is_clustered", return_value=False),
    ):
        ctx = scenario.Context(IncusCharm)
        relation = scenario.PeerRelation(endpoint="cluster", interface="incus-cluster")
        state = scenario.State(leader=False, relations={relation})

        out = ctx.run(ctx.on.relation_created(relation=relation), state)

        relation = out.get_relation(relation.id)
        assert relation.local_unit_data["node-name"] == "any-node-name"
        assert "tokens" not in relation.local_app_data


def test_cluster_relation_changed_leader_not_clustered():
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.enable_clustering") as enable_clustering,
        patch("charm.incus.create_join_token", return_value="any-join-token") as create_join_token,
    ):
        ctx = scenario.Context(IncusCharm)
        relation = scenario.PeerRelation(
            endpoint="cluster",
            interface="incus-cluster",
            peers_data={1: {"node-name": "peer-node-name"}},
            local_app_data={"tokens": "{}"},
        )
        state = scenario.State(leader=True, relations={relation})

        out = ctx.run(ctx.on.relation_changed(relation=relation, remote_unit=1), state)

        enable_clustering.assert_called_once()
        create_join_token.assert_called_once_with("peer-node-name")
        relation = out.get_relation(relation.id)
        assert relation.local_app_data["tokens"] == '{"peer-node-name": "any-join-token"}'
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Enabling clustering"),
            scenario.MaintenanceStatus("Creating join token for peer-node-name"),
        ]


def test_cluster_relation_changed_leader_clustered():
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.enable_clustering") as enable_clustering,
        patch("charm.incus.create_join_token", return_value="any-join-token") as create_join_token,
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        relation = scenario.PeerRelation(
            endpoint="cluster",
            interface="incus-cluster",
            peers_data={1: {"node-name": "peer-node-name"}},
            local_app_data={"tokens": "{}"},
        )
        state = scenario.State(leader=True, relations={relation})

        out = ctx.run(ctx.on.relation_changed(relation=relation, remote_unit=1), state)

        enable_clustering.assert_not_called()
        create_join_token.assert_called_once_with("peer-node-name")
        relation = out.get_relation(relation.id)
        assert relation.local_app_data["tokens"] == '{"peer-node-name": "any-join-token"}'
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Creating join token for peer-node-name"),
        ]


def test_cluster_relation_changed_leader_existing_tokens():
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.enable_clustering") as enable_clustering,
        patch(
            "charm.incus.create_join_token", return_value="any-new-join-token"
        ) as create_join_token,
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        relation = scenario.PeerRelation(
            endpoint="cluster",
            interface="incus-cluster",
            peers_data={
                1: {"node-name": "peer-node-name"},
                2: {"node-name": "new-peer-node-name"},
            },
            local_app_data={"tokens": '{"peer-node-name": "any-join-token"}'},
        )
        state = scenario.State(leader=True, relations={relation})

        out = ctx.run(ctx.on.relation_changed(relation=relation, remote_unit=2), state)

        enable_clustering.assert_not_called()
        create_join_token.assert_called_once_with("new-peer-node-name")
        relation = out.get_relation(relation.id)
        assert (
            relation.local_app_data["tokens"]
            == '{"peer-node-name": "any-join-token", "new-peer-node-name": "any-new-join-token"}'
        )
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Creating join token for new-peer-node-name"),
        ]


def test_cluster_relation_changed_non_leader_not_clustered():
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch("charm.incus.bootstrap_node") as bootstrap_node,
        patch("charm.incus.is_clustered", return_value=False),
    ):
        ctx = scenario.Context(IncusCharm)
        relation = scenario.PeerRelation(
            endpoint="cluster",
            interface="incus-cluster",
            peers_data={
                0: {"node-name": "leader-node-name"},
                1: {"node-name": "any-node-name"},
            },
            local_app_data={"tokens": '{"any-node-name": "any-join-token"}'},
        )
        state = scenario.State(
            leader=False,
            relations={relation},
            networks=[
                scenario.Network(
                    binding_name="cluster",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.2")])],
                )
            ],
            config={"cluster_port": 8888},
        )

        out = ctx.run(ctx.on.relation_changed(relation=relation, remote_unit=1), state)

        relation = out.get_relation(relation.id)
        bootstrap_node.assert_called_once()
        assert bootstrap_node.call_args.args[0]["cluster"] == {
            "enabled": True,
            "cluster_token": "any-join-token",
            "server_address": "10.0.0.2:8888",
        }
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Bootstrapping Incus"),
        ]


def test_cluster_relation_changed_non_leader_clustered():
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch("charm.incus.bootstrap_node") as bootstrap_node,
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        relation = scenario.PeerRelation(
            endpoint="cluster",
            interface="incus-cluster",
            peers_data={
                0: {"node-name": "leader-node-name"},
                1: {"node-name": "any-node-name"},
            },
            local_app_data={"tokens": '{"any-node-name": "any-join-token"}'},
        )
        state = scenario.State(leader=False, relations={relation})

        out = ctx.run(ctx.on.relation_changed(relation=relation, remote_unit=1), state)

        relation = out.get_relation(relation.id)
        bootstrap_node.assert_not_called()
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]


def test_cluster_relation_changed_non_leader_not_clustered_no_token():
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch("charm.incus.bootstrap_node") as bootstrap_node,
        patch("charm.incus.is_clustered", return_value=False),
    ):
        ctx = scenario.Context(IncusCharm)
        relation = scenario.PeerRelation(
            endpoint="cluster",
            interface="incus-cluster",
            peers_data={
                0: {"node-name": "leader-node-name"},
                1: {"node-name": "any-node-name"},
            },
            local_app_data={"tokens": "{}"},
        )
        state = scenario.State(leader=False, relations={relation})

        out = ctx.run(ctx.on.relation_changed(relation=relation, remote_unit=1), state)

        relation = out.get_relation(relation.id)
        bootstrap_node.assert_not_called()
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]
