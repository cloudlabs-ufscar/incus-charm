# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import json
from unittest.mock import patch

import scenario

from charm import IncusCharm


def test_cluster_relation_created_leader_no_certificate():
    """Test the cluster-relation-created event on leader units.

    The unit should create the dictionary of join tokens and put its
    certificate on the relation data.
    """
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.get_server_certificate", return_value="any-certificate"),
    ):
        ctx = scenario.Context(IncusCharm)
        relation = scenario.PeerRelation(endpoint="cluster", interface="incus-cluster")
        state = scenario.State(leader=True, relations={relation})

        out = ctx.run(ctx.on.relation_created(relation=relation), state)

        relation = out.get_relation(relation.id)
        assert relation.local_app_data["tokens"] == "{}"
        assert relation.local_app_data["cluster-certificate"] == "any-certificate"


def test_cluster_relation_created_leader():
    """Test the cluster-relation-created event on leader units.

    The unit should create the dictionary of join tokens.
    """
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.get_server_certificate") as get_server_certificate,
    ):
        ctx = scenario.Context(IncusCharm)
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_units_data={
                0: {
                    "ca": "any-ca",
                    "client.cert": "any-client-cert",
                    "client.key": "any-client-key",
                    "incus_0.server.cert": "any-server-cert",
                    "incus_0.server.key": "any-server-key",
                },
            },
        )
        cluster_relation = scenario.PeerRelation(endpoint="cluster", interface="incus-cluster")
        state = scenario.State(leader=True, relations={certificates_relation, cluster_relation})

        out = ctx.run(ctx.on.relation_created(relation=cluster_relation), state)

        cluster_relation = out.get_relation(cluster_relation.id)
        assert cluster_relation.local_app_data["tokens"] == "{}"
        get_server_certificate.assert_not_called()


def test_cluster_relation_changed_leader_not_clustered():
    """Test the cluster-relation-changed event on leader units that are not clustered.

    The unit should enable clustering in the Incus instance, generate a new token
    for the remote unit that triggered the event, store it in a secret and write
    the ID of that secret in the relation data.
    """
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
            local_app_data={"tokens": "{}", "cluster-certificate": "any-cluster-certificate"},
        )
        state = scenario.State(leader=True, relations={relation})

        out = ctx.run(ctx.on.relation_changed(relation=relation, remote_unit=1), state)

        enable_clustering.assert_called_once()
        create_join_token.assert_called_once_with("peer-node-name")
        relation = out.get_relation(relation.id)
        secret = out.get_secret(label="peer-node-name-join-token")
        assert relation.local_app_data["tokens"] == json.dumps({"peer-node-name": secret.id})
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Enabling clustering"),
            scenario.MaintenanceStatus("Creating join token for peer-node-name"),
        ]


def test_cluster_relation_changed_leader_clustered():
    """Test the cluster-relation-changed event on leader units that are already clustered.

    The unit should not enable clustering in the Incus instance. It should only
    generate a new token for the remote unit that triggered the event, store it
    in a secret and write the ID of that secret in the relation data.
    """
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
            local_app_data={"tokens": "{}", "cluster-certificate": "any-cluster-certificate"},
        )
        state = scenario.State(leader=True, relations={relation})

        out = ctx.run(ctx.on.relation_changed(relation=relation, remote_unit=1), state)

        enable_clustering.assert_not_called()
        create_join_token.assert_called_once_with("peer-node-name")
        relation = out.get_relation(relation.id)
        secret = out.get_secret(label="peer-node-name-join-token")
        assert relation.local_app_data["tokens"] == json.dumps({"peer-node-name": secret.id})
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Creating join token for peer-node-name"),
        ]


def test_cluster_relation_changed_leader_existing_tokens():
    """Test the cluster-relation-changed event on leader units when there are existing tokens.

    The unit should generate a new token for the remote unit that triggered the
    event, store it in a secret and write the ID of that secret in the relation data.
    """
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
            local_app_data={
                "tokens": '{"peer-node-name": "any-join-token-secret-id"}',
                "cluster-certificate": "any-cluster-certificate",
            },
        )
        state = scenario.State(leader=True, relations={relation})

        out = ctx.run(ctx.on.relation_changed(relation=relation, remote_unit=2), state)

        enable_clustering.assert_not_called()
        create_join_token.assert_called_once_with("new-peer-node-name")
        relation = out.get_relation(relation.id)
        secret = out.get_secret(label="new-peer-node-name-join-token")
        assert relation.local_app_data["tokens"] == json.dumps(
            {
                "peer-node-name": "any-join-token-secret-id",
                "new-peer-node-name": secret.id,
            }
        )
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Creating join token for new-peer-node-name"),
        ]


def test_cluster_relation_changed_non_leader_not_clustered():
    """Test the cluster-relation-changed event on non leader units that are not clustered.

    The unit should use the secret ID from the relation to retrieve the join token
    from the secret. The token should then be used to bootstrap Incus and join the
    cluster.
    """
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
            local_app_data={
                "tokens": '{"any-node-name": "any-join-token-secret-id"}',
                "cluster-certificate": "any-cluster-certificate",
            },
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
            secrets={
                scenario.Secret(
                    id="any-join-token-secret-id", tracked_content={"token": "any-join-token"}
                )
            },
        )

        out = ctx.run(ctx.on.relation_changed(relation=relation, remote_unit=1), state)

        relation = out.get_relation(relation.id)
        bootstrap_node.assert_called_once()
        assert bootstrap_node.call_args.args[0]["cluster"] == {
            "enabled": True,
            "cluster_token": "any-join-token",
            "server_address": "10.0.0.2:8888",
            "cluster_certificate": "any-cluster-certificate",
        }
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Bootstrapping Incus"),
        ]


def test_cluster_relation_changed_non_leader_clustered():
    """Test the cluster-relation-changed event on non leader units that are already clustered.

    The unit should not try the cluster twice. It should skip the event.
    """
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
            local_app_data={
                "tokens": '{"any-node-name": "any-join-token-secret-id"}',
                "cluster-certificate": "any-cluster-certificate",
            },
        )
        state = scenario.State(leader=False, relations={relation})

        out = ctx.run(ctx.on.relation_changed(relation=relation, remote_unit=1), state)

        relation = out.get_relation(relation.id)
        bootstrap_node.assert_not_called()
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]


def test_cluster_relation_changed_non_leader_not_clustered_no_token():
    """Test the cluster-relation-changed event on non leader units when no token is available.

    The unit should not try to join the cluster without a token. It should
    skip the event.
    """
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
            local_app_data={
                "tokens": "{}",
                "cluster-certificate": "any-cluster-certificate",
            },
        )
        state = scenario.State(leader=False, relations={relation})

        out = ctx.run(ctx.on.relation_changed(relation=relation, remote_unit=1), state)

        relation = out.get_relation(relation.id)
        bootstrap_node.assert_not_called()
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]


def test_cluster_relation_changed_non_leader_certificate_not_applied():
    """Test the cluster-relation-changed event on non leader units when the certificate is not yet applied.

    The unit should not try to join the cluster. It should defer the event.
    """
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch("charm.incus.bootstrap_node") as bootstrap_node,
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.get_server_certificate", return_value="any-default-certificate"),
    ):
        ctx = scenario.Context(IncusCharm)
        cluster_relation = scenario.PeerRelation(
            endpoint="cluster",
            interface="incus-cluster",
            peers_data={
                0: {"node-name": "leader-node-name"},
                1: {"node-name": "any-node-name"},
            },
            local_app_data={
                "tokens": '{"any-node-name": "any-join-token-secret-id"}',
                "cluster-certificate": "any-cluster-certificate",
            },
        )
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_units_data={
                0: {
                    "ca": "any-ca",
                    "client.cert": "any-client-cert",
                    "client.key": "any-client-key",
                    "incus_0.server.cert": "any-server-cert",
                    "incus_0.server.key": "any-server-key",
                },
            },
        )
        state = scenario.State(leader=False, relations={cluster_relation, certificates_relation})

        out = ctx.run(ctx.on.relation_changed(relation=cluster_relation, remote_unit=1), state)

        cluster_relation = out.get_relation(cluster_relation.id)
        bootstrap_node.assert_not_called()
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]
        assert len(out.deferred) == 1
