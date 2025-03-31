# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import json
from unittest.mock import patch

import scenario

from charm import IncusCharm


def test_cluster_relation_joined_leader_no_certificate_relation():
    """Test the cluster-relation-joined event on leader units.

    The unit should create the dictionary of join tokens, the list of created
    storage and put its certificate on the relation data.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.get_server_certificate", return_value="any-certificate"),
    ):
        ctx = scenario.Context(IncusCharm)
        relation = scenario.PeerRelation(endpoint="cluster", interface="incus-cluster")
        state = scenario.State(leader=True, relations={relation})

        out = ctx.run(ctx.on.relation_joined(relation=relation), state)

        relation = out.get_relation(relation.id)
        assert relation.local_app_data["tokens"] == "{}"
        assert relation.local_app_data["created-storage"] == "[]"
        assert relation.local_app_data["created-network"] == "[]"
        assert relation.local_app_data["cluster-certificate"] == "any-certificate"


def test_cluster_relation_joined_certificate_relation():
    """Test the cluster-relation-joined event on leader units.

    The unit should create the dictionary of join tokens and the list of
    created storage.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
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
        relation = scenario.PeerRelation(endpoint="cluster", interface="incus-cluster")
        state = scenario.State(leader=True, relations={certificates_relation, relation})

        out = ctx.run(ctx.on.relation_joined(relation=relation), state)

        relation = out.get_relation(relation.id)
        assert relation.local_app_data["tokens"] == "{}"
        assert relation.local_app_data["created-storage"] == "[]"
        assert relation.local_app_data["created-network"] == "[]"
        get_server_certificate.assert_not_called()


def test_cluster_relation_joined_leader_data_already_set():
    """Test the cluster-relation-joined event on leader units when the relation data is already setup.

    The unit should not override the application data.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.get_server_certificate", return_value="any-certificate"),
    ):
        ctx = scenario.Context(IncusCharm)
        relation = scenario.PeerRelation(
            endpoint="cluster",
            interface="incus-cluster",
            local_app_data={
                "tokens": '{"any-node-name": "any-join-token-secret-id"}',
                "created-storage": '["ceph"]',
                "created-network": '["ovn"]',
                "cluster-certificate": "any-cluster-certificate",
            },
        )
        state = scenario.State(leader=True, relations={relation})

        out = ctx.run(ctx.on.relation_joined(relation=relation), state)

        relation = out.get_relation(relation.id)
        assert relation.local_app_data["tokens"] == '{"any-node-name": "any-join-token-secret-id"}'
        assert relation.local_app_data["created-storage"] == '["ceph"]'
        assert relation.local_app_data["created-network"] == '["ovn"]'
        assert relation.local_app_data["cluster-certificate"] == "any-cluster-certificate"


def test_cluster_relation_changed_leader_not_clustered():
    """Test the cluster-relation-changed event on leader units that are not clustered.

    The unit should enable clustering in the Incus instance, generate a new token
    for the remote unit that triggered the event, store it in a secret and write
    the ID of that secret in the relation data.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
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
            local_app_data={
                "tokens": "{}",
                "created-storage": "[]",
                "created-network": "[]",
                "cluster-certificate": "any-cluster-certificate",
            },
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
        assert "joined-cluster-at" in relation.local_unit_data


def test_cluster_relation_changed_leader_not_clustered_set_failure_domain():
    """Test the cluster-relation-changed event on leader units that are not clustered and have an availability zone set.

    The unit should enable clustering in the Incus instance, set its failure domain
    to the one specified by the JUJU_AVAILABILITY_ZONE environment variable, generate
    a new token for the remote unit that triggered the event, store it in a secret
    and write the ID of that secret in the relation data.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.enable_clustering") as enable_clustering,
        patch("charm.incus.create_join_token", return_value="any-join-token") as create_join_token,
        patch(
            "charm.incus.set_cluster_member_failure_domain"
        ) as set_cluster_member_failure_domain,
        patch.dict("charm.os.environ", {"JUJU_AVAILABILITY_ZONE": "any-availability-zone"}),
    ):
        ctx = scenario.Context(IncusCharm)
        relation = scenario.PeerRelation(
            endpoint="cluster",
            interface="incus-cluster",
            peers_data={1: {"node-name": "peer-node-name"}},
            local_app_data={
                "tokens": "{}",
                "created-storage": "[]",
                "created-network": "[]",
                "cluster-certificate": "any-cluster-certificate",
            },
        )
        state = scenario.State(
            leader=True, relations={relation}, config={"set-failure-domain": True}
        )

        out = ctx.run(ctx.on.relation_changed(relation=relation, remote_unit=1), state)

        enable_clustering.assert_called_once()
        set_cluster_member_failure_domain.assert_called_once_with(
            "any-node-name", "any-availability-zone"
        )
        create_join_token.assert_called_once_with("peer-node-name")
        relation = out.get_relation(relation.id)
        secret = out.get_secret(label="peer-node-name-join-token")
        assert relation.local_app_data["tokens"] == json.dumps({"peer-node-name": secret.id})
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Enabling clustering"),
            scenario.MaintenanceStatus("Creating join token for peer-node-name"),
        ]
        assert "joined-cluster-at" in relation.local_unit_data


def test_cluster_relation_changed_leader_not_clustered_set_failure_domain_disabled():
    """Test the cluster-relation-changed event on leader units that are not clustered and have a config to not set the failure domain.

    The unit should enable clustering in the Incus instance, generate a new
    token for the remote unit that triggered the event, store it in a secret
    and write the ID of that secret in the relation data. The unit should not
    set any failure domain.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.enable_clustering") as enable_clustering,
        patch("charm.incus.create_join_token", return_value="any-join-token") as create_join_token,
        patch(
            "charm.incus.set_cluster_member_failure_domain"
        ) as set_cluster_member_failure_domain,
        patch.dict("charm.os.environ", {"JUJU_AVAILABILITY_ZONE": "any-availability-zone"}),
    ):
        ctx = scenario.Context(IncusCharm)
        relation = scenario.PeerRelation(
            endpoint="cluster",
            interface="incus-cluster",
            peers_data={1: {"node-name": "peer-node-name"}},
            local_app_data={
                "tokens": "{}",
                "created-storage": "[]",
                "created-network": "[]",
                "cluster-certificate": "any-cluster-certificate",
            },
        )
        state = scenario.State(
            leader=True, relations={relation}, config={"set-failure-domain": False}
        )

        out = ctx.run(ctx.on.relation_changed(relation=relation, remote_unit=1), state)

        enable_clustering.assert_called_once()
        set_cluster_member_failure_domain.assert_not_called()
        create_join_token.assert_called_once_with("peer-node-name")
        relation = out.get_relation(relation.id)
        secret = out.get_secret(label="peer-node-name-join-token")
        assert relation.local_app_data["tokens"] == json.dumps({"peer-node-name": secret.id})
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Enabling clustering"),
            scenario.MaintenanceStatus("Creating join token for peer-node-name"),
        ]
        assert "joined-cluster-at" in relation.local_unit_data


def test_cluster_relation_changed_leader_clustered():
    """Test the cluster-relation-changed event on leader units that are already clustered.

    The unit should not enable clustering in the Incus instance. It should only
    generate a new token for the remote unit that triggered the event, store it
    in a secret and write the ID of that secret in the relation data.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
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
            local_app_data={
                "tokens": "{}",
                "created-storage": "[]",
                "created-network": "[]",
                "cluster-certificate": "any-cluster-certificate",
            },
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
        patch("charm.IncusCharm._package_installed", return_value=True),
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
                "created-storage": "[]",
                "created-network": "[]",
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
        patch("charm.IncusCharm._package_installed", return_value=True),
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
                "created-storage": "[]",
                "created-network": "[]",
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
            config={"cluster-port": 8888},
            secrets={
                scenario.Secret(
                    id="any-join-token-secret-id", tracked_content={"token": "any-join-token"}
                )
            },
        )

        ctx.run(ctx.on.relation_changed(relation=relation, remote_unit=1), state)

        bootstrap_node.assert_called_once()
        assert bootstrap_node.call_args.args[0]["cluster"] == {
            "enabled": True,
            "cluster_token": "any-join-token",
            "server_address": "10.0.0.2:8888",
            "cluster_certificate": "any-cluster-certificate",
            "member_config": [],
        }
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Bootstrapping Incus"),
        ]
        assert "joined-cluster-at" in relation.local_unit_data


def test_cluster_relation_changed_non_leader_not_clustered_failure_domain():
    """Test the cluster-relation-changed event on non leader units that are not clustered and have an availability zone set.

    The unit should use the secret ID from the relation to retrieve the join token
    from the secret. The token should then be used to bootstrap Incus and join the
    cluster. The unit should also set its failure domain to the one specified by
    the JUJU_AVAILABILITY_ZONE environment variable
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch("charm.incus.bootstrap_node") as bootstrap_node,
        patch("charm.incus.is_clustered", return_value=False),
        patch(
            "charm.incus.set_cluster_member_failure_domain"
        ) as set_cluster_member_failure_domain,
        patch.dict("charm.os.environ", {"JUJU_AVAILABILITY_ZONE": "any-availability-zone"}),
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
                "created-storage": "[]",
                "created-network": "[]",
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
            config={"cluster-port": 8888, "set-failure-domain": True},
            secrets={
                scenario.Secret(
                    id="any-join-token-secret-id", tracked_content={"token": "any-join-token"}
                )
            },
        )

        ctx.run(ctx.on.relation_changed(relation=relation, remote_unit=1), state)

        bootstrap_node.assert_called_once()
        assert bootstrap_node.call_args.args[0]["cluster"] == {
            "enabled": True,
            "cluster_token": "any-join-token",
            "server_address": "10.0.0.2:8888",
            "cluster_certificate": "any-cluster-certificate",
            "member_config": [],
        }
        set_cluster_member_failure_domain.assert_called_once_with(
            "any-node-name", "any-availability-zone"
        )
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Bootstrapping Incus"),
        ]
        assert "joined-cluster-at" in relation.local_unit_data


def test_cluster_relation_changed_non_leader_not_clustered_failure_domain_disabled():
    """Test the cluster-relation-changed event on non leader units that are not clustered and have a config to not set the failure domain.

    The unit should use the secret ID from the relation to retrieve the join token
    from the secret. The token should then be used to bootstrap Incus and join the
    cluster. The unit should not set its failure domain.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch("charm.incus.bootstrap_node") as bootstrap_node,
        patch("charm.incus.is_clustered", return_value=False),
        patch(
            "charm.incus.set_cluster_member_failure_domain"
        ) as set_cluster_member_failure_domain,
        patch.dict("charm.os.environ", {"JUJU_AVAILABILITY_ZONE": "any-availability-zone"}),
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
                "created-storage": "[]",
                "created-network": "[]",
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
            config={"cluster-port": 8888, "set-failure-domain": False},
            secrets={
                scenario.Secret(
                    id="any-join-token-secret-id", tracked_content={"token": "any-join-token"}
                )
            },
        )

        ctx.run(ctx.on.relation_changed(relation=relation, remote_unit=1), state)

        bootstrap_node.assert_called_once()
        assert bootstrap_node.call_args.args[0]["cluster"] == {
            "enabled": True,
            "cluster_token": "any-join-token",
            "server_address": "10.0.0.2:8888",
            "cluster_certificate": "any-cluster-certificate",
            "member_config": [],
        }
        set_cluster_member_failure_domain.assert_not_called()
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Bootstrapping Incus"),
        ]
        assert "joined-cluster-at" in relation.local_unit_data


def test_cluster_relation_changed_non_leader_clustered():
    """Test the cluster-relation-changed event on non leader units that are already clustered.

    The unit should not try the cluster twice. It should skip the event.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
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
                "created-storage": "[]",
                "created-network": "[]",
                "cluster-certificate": "any-cluster-certificate",
            },
        )
        state = scenario.State(leader=False, relations={relation})

        ctx.run(ctx.on.relation_changed(relation=relation, remote_unit=1), state)

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
        patch("charm.IncusCharm._package_installed", return_value=True),
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
                "created-storage": "[]",
                "created-network": "[]",
                "cluster-certificate": "any-cluster-certificate",
            },
        )
        state = scenario.State(leader=False, relations={relation})

        ctx.run(ctx.on.relation_changed(relation=relation, remote_unit=1), state)

        bootstrap_node.assert_not_called()
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]


def test_cluster_relation_changed_non_leader_certificate_not_applied():
    """Test the cluster-relation-changed event on non leader units when the certificate is not yet applied.

    The unit should not try to join the cluster. It should defer the event.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
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
                "created-storage": "[]",
                "created-network": "[]",
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

        bootstrap_node.assert_not_called()
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]
        assert len(out.deferred) == 1


def test_cluster_relation_changed_non_leader_ceph_not_configured():
    """Test the cluster-relation-changed event on non leader units when Ceph is not configured.

    The unit should not try to join the cluster when Ceph is not configured. It
    should defer the event.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch("charm.incus.bootstrap_node") as bootstrap_node,
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.ceph.is_configured", return_value=False),
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
                "created-storage": "[]",
                "created-network": "[]",
                "cluster-certificate": "any-cluster-certificate",
            },
        )
        state = scenario.State(
            leader=False,
            relations={relation, scenario.Relation(endpoint="ceph")},
            networks=[
                scenario.Network(
                    binding_name="cluster",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.2")])],
                )
            ],
            config={"cluster-port": 8888},
            secrets={
                scenario.Secret(
                    id="any-join-token-secret-id", tracked_content={"token": "any-join-token"}
                )
            },
        )

        out = ctx.run(ctx.on.relation_changed(relation=relation, remote_unit=1), state)

        bootstrap_node.assert_not_called()
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]
        assert len(out.deferred) == 1


def test_cluster_relation_changed_non_leader_ceph_pool_not_created():
    """Test the cluster-relation-changed event on non leader units when the Ceph pool is not created.

    The unit should not try to join the cluster when the Ceph pool is not created. It
    should defer the event.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch("charm.incus.bootstrap_node") as bootstrap_node,
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.ceph.is_configured", return_value=True),
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
                "created-storage": "[]",
                "created-network": "[]",
                "cluster-certificate": "any-cluster-certificate",
            },
        )
        state = scenario.State(
            leader=False,
            relations={relation, scenario.Relation(endpoint="ceph")},
            networks=[
                scenario.Network(
                    binding_name="cluster",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.2")])],
                )
            ],
            config={"cluster-port": 8888},
            secrets={
                scenario.Secret(
                    id="any-join-token-secret-id", tracked_content={"token": "any-join-token"}
                )
            },
        )

        out = ctx.run(ctx.on.relation_changed(relation=relation, remote_unit=1), state)

        bootstrap_node.assert_not_called()
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]
        assert len(out.deferred) == 1


def test_cluster_relation_changed_non_leader_ceph_pool_created():
    """Test the cluster-relation-changed event on non leader units when the Ceph pool is created.

    The unit should use the secret ID from the relation to retrieve the join token
    from the secret. The token should then be used to bootstrap Incus and join the
    cluster.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch("charm.incus.bootstrap_node") as bootstrap_node,
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.ceph.is_configured", return_value=True),
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
                "created-storage": '["ceph"]',
                "created-network": "[]",
                "cluster-certificate": "any-cluster-certificate",
            },
        )
        state = scenario.State(
            leader=False,
            relations={relation, scenario.Relation(endpoint="ceph")},
            networks=[
                scenario.Network(
                    binding_name="cluster",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.2")])],
                )
            ],
            config={"cluster-port": 8888},
            secrets={
                scenario.Secret(
                    id="any-join-token-secret-id", tracked_content={"token": "any-join-token"}
                )
            },
        )

        ctx.run(ctx.on.relation_changed(relation=relation, remote_unit=1), state)

        bootstrap_node.assert_called_once()
        assert bootstrap_node.call_args.args[0]["cluster"] == {
            "enabled": True,
            "cluster_token": "any-join-token",
            "server_address": "10.0.0.2:8888",
            "cluster_certificate": "any-cluster-certificate",
            "member_config": [],
        }
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Bootstrapping Incus"),
        ]
        assert "joined-cluster-at" in relation.local_unit_data


def test_cluster_relation_changed_non_leader_ovn_not_ready():
    """Test the cluster-relation-changed event on non leader units when the OVN connection is not ready.

    The unit should not try to join the cluster when the OVN connection is not ready. It
    should defer the event.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch("charm.incus.bootstrap_node") as bootstrap_node,
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.ceph.is_configured", return_value=True),
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
                "created-storage": "[]",
                "created-network": "[]",
                "cluster-certificate": "any-cluster-certificate",
            },
        )
        state = scenario.State(
            leader=False,
            relations={relation, scenario.Relation(endpoint="ovsdb-cms")},
            networks=[
                scenario.Network(
                    binding_name="cluster",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.2")])],
                )
            ],
            config={"cluster-port": 8888},
            secrets={
                scenario.Secret(
                    id="any-join-token-secret-id", tracked_content={"token": "any-join-token"}
                )
            },
        )

        out = ctx.run(ctx.on.relation_changed(relation=relation, remote_unit=1), state)

        bootstrap_node.assert_not_called()
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
        ]
        assert len(out.deferred) == 1


def test_cluster_relation_changed_non_leader_ovn_ready():
    """Test the cluster-relation-changed event on non leader units when the OVN connection is ready.

    The unit should use the secret ID from the relation to retrieve the join token
    from the secret. The token should then be used to bootstrap Incus and join the
    cluster.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch("charm.incus.bootstrap_node") as bootstrap_node,
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.ceph.is_configured", return_value=True),
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
                "created-storage": "[]",
                "created-network": "[]",
                "ovn-nb-connection-ready": "true",
                "cluster-certificate": "any-cluster-certificate",
            },
        )
        state = scenario.State(
            leader=False,
            relations={relation, scenario.Relation(endpoint="ovsdb-cms")},
            networks=[
                scenario.Network(
                    binding_name="cluster",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.2")])],
                )
            ],
            config={"cluster-port": 8888},
            secrets={
                scenario.Secret(
                    id="any-join-token-secret-id", tracked_content={"token": "any-join-token"}
                )
            },
        )

        ctx.run(ctx.on.relation_changed(relation=relation, remote_unit=1), state)

        bootstrap_node.assert_called_once()
        assert bootstrap_node.call_args.args[0]["cluster"] == {
            "enabled": True,
            "cluster_token": "any-join-token",
            "server_address": "10.0.0.2:8888",
            "cluster_certificate": "any-cluster-certificate",
            "member_config": [],
        }
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Bootstrapping Incus"),
        ]
        assert "joined-cluster-at" in relation.local_unit_data


def test_cluster_relation_changed_non_leader_ovn_network_created_uplink_physical():
    """Test the cluster-relation-changed event on non leader units when the OVN network is created and the uplink interface is configured to physical.

    The unit should use the secret ID from the relation to retrieve the join token
    from the secret. The token should then be used to bootstrap Incus and join the
    cluster. Finally, the unit should also include the uplink network data on the
    preseed data when bootstrapping the node.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch("charm.incus.bootstrap_node") as bootstrap_node,
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.ceph.is_configured", return_value=True),
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
                "created-storage": "[]",
                "created-network": '["ovn"]',
                "ovn-nb-connection-ready": "true",
                "cluster-certificate": "any-cluster-certificate",
            },
        )
        state = scenario.State(
            leader=False,
            relations={relation, scenario.Relation(endpoint="ovsdb-cms")},
            networks=[
                scenario.Network(
                    binding_name="cluster",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.2")])],
                ),
            ],
            config={
                "cluster-port": 8888,
                "ovn-uplink-network-type": "physical",
                "ovn-uplink-network-parent-interface": "any-uplink-interface",
            },
            secrets={
                scenario.Secret(
                    id="any-join-token-secret-id", tracked_content={"token": "any-join-token"}
                )
            },
        )

        ctx.run(ctx.on.relation_changed(relation=relation, remote_unit=1), state)

        bootstrap_node.assert_called_once()
        bootstrap_data = bootstrap_node.call_args.args[0]
        assert bootstrap_data == {
            "cluster": {
                "enabled": True,
                "cluster_token": "any-join-token",
                "server_address": "10.0.0.2:8888",
                "cluster_certificate": "any-cluster-certificate",
                "member_config": [
                    {
                        "entity": "network",
                        "name": "UPLINK",
                        "key": "parent",
                        "value": "any-uplink-interface",
                    }
                ],
            }
        }
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Bootstrapping Incus"),
        ]
        assert "joined-cluster-at" in relation.local_unit_data


def test_cluster_relation_changed_non_leader_ovn_network_created_uplink_bridge():
    """Test the cluster-relation-changed event on non leader units when the OVN network is created and the uplink interface is configured to a bridge.

    The unit should use the secret ID from the relation to retrieve the join token
    from the secret. The token should then be used to bootstrap Incus and join the
    cluster. Finally, the unit should also include the uplink network data on the
    preseed data when bootstrapping the node.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch("charm.incus.bootstrap_node") as bootstrap_node,
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.ceph.is_configured", return_value=True),
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
                "created-storage": "[]",
                "created-network": '["ovn"]',
                "ovn-nb-connection-ready": "true",
                "cluster-certificate": "any-cluster-certificate",
            },
        )
        state = scenario.State(
            leader=False,
            relations={relation, scenario.Relation(endpoint="ovsdb-cms")},
            networks=[
                scenario.Network(
                    binding_name="cluster",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.2")])],
                ),
            ],
            config={"cluster-port": 8888, "ovn-uplink-network-type": "bridge"},
            secrets={
                scenario.Secret(
                    id="any-join-token-secret-id", tracked_content={"token": "any-join-token"}
                )
            },
        )

        ctx.run(ctx.on.relation_changed(relation=relation, remote_unit=1), state)

        bootstrap_node.assert_called_once()
        bootstrap_data = bootstrap_node.call_args.args[0]
        assert bootstrap_data == {
            "cluster": {
                "enabled": True,
                "cluster_token": "any-join-token",
                "server_address": "10.0.0.2:8888",
                "cluster_certificate": "any-cluster-certificate",
                "member_config": [],
            }
        }
        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Bootstrapping Incus"),
        ]
        assert "joined-cluster-at" in relation.local_unit_data
        assert "ovn-uplink-interface" not in relation.local_unit_data
