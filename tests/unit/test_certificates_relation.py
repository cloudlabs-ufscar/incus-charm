# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

from unittest.mock import patch

import pytest
import scenario
from charms.tls_certificates_interface.v0.tls_certificates import (
    Certificate,
    CertificateChangedEvent,
)

import incus
from charm import IncusCharm


@pytest.mark.parametrize(
    "leader,is_clustered", [(False, False), (True, False), (False, True), (True, True)]
)
def test_certificates_relation_joined(leader, is_clustered):
    """Test the certificates-relation-joined event.

    The unit should populate the relation data with the information needed
    to generate a new certificate.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._node_name", "any-node-name"),
        patch("charm.incus.is_clustered", return_value=is_clustered),
        patch("charm.socket.getfqdn", return_value="any-host-fqdn"),
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        relation = scenario.Relation(endpoint="certificates", interface="tls-certificates")
        state = scenario.State(
            leader=leader,
            relations={relation},
            networks=[
                scenario.Network(
                    binding_name="public",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.1")])],
                ),
                scenario.Network(
                    binding_name="cluster",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.2")])],
                ),
            ],
        )

        out = ctx.run(ctx.on.relation_joined(relation=relation), state)

        relation = out.get_relation(relation.id)
        assert relation.local_unit_data["unit_name"] == "incus_0"
        assert relation.local_unit_data["certificate_name"] == "incus"
        assert relation.local_unit_data["common_name"] == "any-host-fqdn"
        assert relation.local_unit_data["sans"] == '["10.0.0.1", "10.0.0.2"]'


def test_certificates_relation_changed_single_remote_unit_empty_data():
    """Test the certificates-relation-changed event when the relation data is empty.

    No certificate changed event should be emitted.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.is_clustered", return_value=False),
    ):
        ctx = scenario.Context(IncusCharm)
        relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_units_data={
                0: {},
            },
        )
        state = scenario.State(leader=True, relations={relation})

        out = ctx.run(ctx.on.relation_changed(relation=relation), state)

        relation = out.get_relation(relation.id)
        assert len(ctx.emitted_events) == 1


def test_certificates_relation_changed_single_remote_unit_incomplete_data():
    """Test the certificates-relation-changed event when the relation data is incomplete.

    No certificate changed event should be emitted.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.is_clustered", return_value=False),
    ):
        ctx = scenario.Context(IncusCharm)
        relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_units_data={
                0: {
                    "ca": "any-ca",
                    "client.cert": "any-client-cert",
                    "client.key": "any-client-key",
                },
            },
        )
        state = scenario.State(leader=True, relations={relation})

        out = ctx.run(ctx.on.relation_changed(relation=relation), state)

        relation = out.get_relation(relation.id)
        assert len(ctx.emitted_events) == 1


def test_certificates_relation_changed_single_remote_unit():
    """Test the certificates-relation-changed event when the certificate is available.

    A certificate changed event should be emitted to the charm.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._restart_service"),
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.update_server_certificate"),
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

        out = ctx.run(ctx.on.relation_changed(relation=certificates_relation), state)

        certificates_relation = out.get_relation(certificates_relation.id)
        assert len(ctx.emitted_events) == 2
        event = ctx.emitted_events[1]
        assert isinstance(event, CertificateChangedEvent)
        assert event.certificate == Certificate(
            cert="any-server-cert", key="any-server-key", ca="any-ca"
        )
        stored = out.get_stored_state(
            "_stored", owner_path="IncusCharm/TLSCertificatesRequires[certificates]"
        )
        assert stored.content == {
            "certificate": {"cert": "any-server-cert", "key": "any-server-key", "ca": "any-ca"}
        }


def test_certificates_relation_changed_multiple_remote_units_inconsistency():
    """Test the certificates-relation-changed event when the relation data is inconsistent across units.

    A certificate changed event should be emitted to the charm.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._restart_service"),
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.update_server_certificate"),
    ):
        ctx = scenario.Context(IncusCharm)
        relation = scenario.Relation(
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
                1: {
                    "ca": "any-ca",
                    "client.cert": "any-client-cert",
                    "client.key": "any-client-key",
                    "incus_0.server.cert": "another-server-cert",
                    "incus_0.server.key": "another-server-key",
                },
            },
        )
        state = scenario.State(leader=True, relations={relation})

        out = ctx.run(ctx.on.relation_changed(relation=relation), state)

        relation = out.get_relation(relation.id)
        assert len(ctx.emitted_events) == 1


def test_certificates_relation_changed_multiple_remote_units():
    """Test the certificates-relation-changed event when the certificate is available.

    A certificate changed event should be emitted to the charm.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._restart_service"),
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.update_server_certificate"),
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
                1: {
                    "ca": "any-ca",
                    "client.cert": "any-client-cert",
                    "client.key": "any-client-key",
                    "incus_0.server.cert": "any-server-cert",
                    "incus_0.server.key": "any-server-key",
                },
                2: {
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

        out = ctx.run(ctx.on.relation_changed(relation=certificates_relation), state)

        certificates_relation = out.get_relation(certificates_relation.id)
        assert len(ctx.emitted_events) == 2
        event = ctx.emitted_events[1]
        assert isinstance(event, CertificateChangedEvent)
        assert event.certificate == Certificate(
            cert="any-server-cert", key="any-server-key", ca="any-ca"
        )


def test_certificate_changed_not_clustered():
    """Test the certificate-changed event when the unit is not clustered.

    The certificate should be applied and the service restarted.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._restart_service") as restart_service,
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.update_server_certificate") as update_server_certificate,
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

        ctx.run(ctx.on.relation_changed(relation=certificates_relation), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Applying certificate"),
        ]
        update_server_certificate.assert_called_once_with(
            cert="any-server-cert", key="any-server-key", ca="any-ca"
        )
        restart_service.assert_called_once_with("incus")


def test_certificate_changed_clustered_not_leader():
    """Test the certificate-changed event when the unit is clustered but is not the leader.

    The certificate should be applied.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._restart_service") as restart_service,
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.update_server_certificate") as update_server_certificate,
        patch("charm.incus.update_cluster_certificate") as update_cluster_certificate,
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        relation = scenario.Relation(
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
        state = scenario.State(leader=False, relations={relation})

        ctx.run(ctx.on.relation_changed(relation=relation), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Applying certificate"),
        ]
        update_server_certificate.assert_called_once_with(
            cert="any-server-cert", key="any-server-key", ca="any-ca"
        )
        restart_service.assert_not_called()
        update_cluster_certificate.assert_not_called()


def test_certificate_changed_clustered_leader():
    """Test the certificate-changed event when the unit is clustered but is the leader.

    The certificate should be applied and the cluster certificate should be updated.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._restart_service") as restart_service,
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.update_server_certificate") as update_server_certificate,
        patch("charm.incus.update_cluster_certificate") as update_cluster_certificate,
        patch("charm.incus.get_cluster_member_info"),
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

        ctx.run(ctx.on.relation_changed(relation=certificates_relation), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Applying certificate"),
        ]
        update_server_certificate.assert_called_once_with(
            cert="any-server-cert", key="any-server-key", ca="any-ca"
        )
        restart_service.assert_not_called()
        update_cluster_certificate.assert_called_once_with(
            cert="any-server-cert", key="any-server-key"
        )


def test_certificates_relation_changed_certificate_already_stored():
    """Test the certificates-relation-changed event when the certificate is already stored.

    A certificate changed event should not be emitted to the charm.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._restart_service"),
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.update_server_certificate"),
    ):
        ctx = scenario.Context(IncusCharm)
        relation = scenario.Relation(
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
        stored_state = scenario.StoredState(
            "_stored",
            owner_path="IncusCharm/TLSCertificatesRequires[certificates]",
            content={
                "certificate": {"cert": "any-server-cert", "key": "any-server-key", "ca": "any-ca"}
            },
        )
        state = scenario.State(leader=True, relations={relation}, stored_states={stored_state})

        out = ctx.run(ctx.on.relation_changed(relation=relation), state)

        relation = out.get_relation(relation.id)
        assert len(ctx.emitted_events) == 1


def test_certificates_relation_changed_certificate_old_stored():
    """Test the certificates-relation-changed event when the certificate is updated and the old certificate is stored.

    A certificate changed event should be emitted to the charm.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._restart_service"),
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.update_server_certificate"),
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
                    "incus_0.server.cert": "any-updated-cert",
                    "incus_0.server.key": "any-updated-key",
                },
            },
        )
        cluster_relation = scenario.PeerRelation(endpoint="cluster", interface="incus-cluster")
        stored_state = scenario.StoredState(
            "_stored",
            owner_path="IncusCharm/TLSCertificatesRequires[certificates]",
            content={
                "certificate": {"cert": "any-server-cert", "key": "any-server-key", "ca": "any-ca"}
            },
        )
        state = scenario.State(
            leader=True,
            relations={certificates_relation, cluster_relation},
            stored_states={stored_state},
        )

        out = ctx.run(ctx.on.relation_changed(relation=certificates_relation), state)

        certificates_relation = out.get_relation(certificates_relation.id)
        assert len(ctx.emitted_events) == 2
        event = ctx.emitted_events[1]
        assert isinstance(event, CertificateChangedEvent)
        assert event.certificate == Certificate(
            cert="any-updated-cert", key="any-updated-key", ca="any-ca"
        )


def test_certificate_changed_ovn_leader():
    """Test the certificate-changed event when the unit is the leader and has an ovsdb-cms relation.

    The certificate should be applied and the ovn client certificate should be updated.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._restart_service") as restart_service,
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.update_server_certificate") as update_server_certificate,
        patch("charm.incus.update_cluster_certificate") as update_cluster_certificate,
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.incus.set_ovn_northbound_connection") as set_ovn_northbound_connection,
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
        cluster_relation = scenario.PeerRelation(
            endpoint="cluster",
            interface="incus-cluster",
            local_app_data={
                "tokens": "{}",
                "cluster-certificate": "any-cluster-certificate",
                "created-storage": "[]",
                "created-network": "[]",
            },
        )
        ovsdb_cms_relation = scenario.Relation(
            endpoint="ovsdb-cms",
            interface="ovsdb-cms",
            remote_units_data={0: {"bound-address": "10.10.0.1"}},
        )
        state = scenario.State(
            leader=True, relations={certificates_relation, cluster_relation, ovsdb_cms_relation}
        )

        ctx.run(ctx.on.relation_changed(relation=certificates_relation), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Applying certificate"),
            scenario.MaintenanceStatus("Configuring OVN northbound connection"),
        ]
        update_server_certificate.assert_called_once_with(
            cert="any-server-cert", key="any-server-key", ca="any-ca"
        )
        restart_service.assert_not_called()
        update_cluster_certificate.assert_called_once_with(
            cert="any-server-cert", key="any-server-key"
        )
        set_ovn_northbound_connection.assert_called_once_with(
            incus.OvnConnectionOptions(
                client_cert="any-server-cert",
                client_key="any-server-key",
                client_ca="any-ca",
                northbound_connection="ssl:10.10.0.1:6641",
            )
        )
        assert cluster_relation.local_app_data.get("created-network") == '["ovn"]'


def test_certificate_changed_ovn_not_leader():
    """Test the certificate-changed event when the unit is not the leader and has an ovsdb-cms relation.

    The certificate should be applied but the ovn client certificate should not be updated.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._restart_service") as restart_service,
        patch("charm.incus.is_clustered", return_value=True),
        patch("charm.incus.update_server_certificate") as update_server_certificate,
        patch("charm.incus.update_cluster_certificate"),
        patch("charm.incus.get_cluster_member_info"),
        patch("charm.incus.set_ovn_northbound_connection") as set_ovn_northbound_connection,
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
        ovsdb_cms_relation = scenario.Relation(endpoint="ovsdb-cms", interface="ovsdb-cms")
        state = scenario.State(
            leader=False, relations={certificates_relation, cluster_relation, ovsdb_cms_relation}
        )

        ctx.run(ctx.on.relation_changed(relation=certificates_relation), state)

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Applying certificate"),
        ]
        update_server_certificate.assert_called_once_with(
            cert="any-server-cert", key="any-server-key", ca="any-ca"
        )
        restart_service.assert_not_called()
        set_ovn_northbound_connection.assert_not_called()
