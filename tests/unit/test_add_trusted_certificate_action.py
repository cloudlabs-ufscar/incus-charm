# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing


from unittest.mock import patch

import pytest
import scenario

from charm import IncusCharm
from incus import IncusProcessError


def test_invalid_certificate():
    """Test the add-trusted-certificate action with an invalid certificate.

    No action should be performed in the Incus instance. An error should
    be returned to the operator.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.add_trusted_certificate") as add_trusted_certificate,
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            config={"server-port": 8443},
            networks=[
                scenario.Network(
                    binding_name="public",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.1")])],
                )
            ],
        )

        with pytest.raises(scenario.ActionFailed) as exc_info:
            ctx.run(
                ctx.on.action("add-trusted-certificate", params={"cert": "invalid-cert"}),
                state,
            )

        assert ctx.unit_status_history == [scenario.UnknownStatus()]
        assert "value is not a valid x509 certificate" in exc_info.value.message
        add_trusted_certificate.assert_not_called()


def test_invalid_type(certificate: str):
    """Test the add-trusted-certificate action with an invalid type.

    No action should be performed in the Incus instance. An error should
    be returned to the operator.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.add_trusted_certificate") as add_trusted_certificate,
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            config={"server-port": 8443},
            networks=[
                scenario.Network(
                    binding_name="public",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.1")])],
                )
            ],
        )

        with pytest.raises(scenario.ActionFailed) as exc_info:
            ctx.run(
                ctx.on.action(
                    "add-trusted-certificate", params={"cert": certificate, "type": "any-type"}
                ),
                state,
            )

        assert ctx.unit_status_history == [scenario.UnknownStatus()]
        assert "unexpected value; permitted: 'client', 'metrics'" in exc_info.value.message
        add_trusted_certificate.assert_not_called()


def test_incus_error(certificate: str):
    """Test the add-trusted-certificate action when there's an Incus error.

    The error should be returned to the operator.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.is_clustered", return_value=False),
        patch(
            "charm.incus.add_trusted_certificate",
            side_effect=IncusProcessError("any-incus-error"),
        ) as add_trusted_certificate,
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            config={"server-port": 8443},
            networks=[
                scenario.Network(
                    binding_name="public",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.1")])],
                )
            ],
        )

        with pytest.raises(scenario.ActionFailed) as exc_info:
            ctx.run(
                ctx.on.action("add-trusted-certificate", params={"cert": certificate}),
                state,
            )

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Adding trusted certificate"),
        ]
        add_trusted_certificate.assert_called_once_with(
            cert=certificate,
            type="client",
            projects=None,
            name=None,
        )
        assert exc_info.value.message == "any-incus-error"


def test_success(certificate: str):
    """Test the add-trusted-certificate action.

    The unit should add the given certificate to the incus truststore.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.add_trusted_certificate") as add_trusted_certificate,
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            config={"server-port": 8443},
            networks=[
                scenario.Network(
                    binding_name="public",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.1")])],
                )
            ],
        )

        ctx.run(
            ctx.on.action(
                "add-trusted-certificate",
                params={
                    "cert": certificate,
                    "projects": "a,b,c",
                    "name": "any-cert-name",
                },
            ),
            state,
        )

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Adding trusted certificate"),
        ]
        add_trusted_certificate.assert_called_once_with(
            cert=certificate,
            type="client",
            projects=["a", "b", "c"],
            name="any-cert-name",
        )
        assert ctx.action_results == {"result": "Certificate added to Incus truststore"}
