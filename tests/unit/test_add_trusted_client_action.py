# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing


from unittest.mock import patch

import pytest
import scenario

from charm import IncusCharm
from incus import IncusProcessError


def test_incus_error():
    """Test the add-trusted-client action when there's an Incus error.

    The error should be returned to the operator.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.is_clustered", return_value=False),
        patch(
            "charm.incus.add_trusted_client",
            side_effect=IncusProcessError("any-incus-error"),
        ) as add_trusted_client,
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
                ctx.on.action("add-trusted-client", params={"name": "any-name"}),
                state,
            )

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Adding trusted client"),
        ]
        add_trusted_client.assert_called_once_with(
            name="any-name",
            projects=None,
        )
        assert exc_info.value.message == "any-incus-error"


def test_success():
    """Test the add-trusted-client action.

    The unit should add the given client to the incus truststore and return
    the trust token.
    """
    with (
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.incus.is_clustered", return_value=False),
        patch(
            "charm.incus.add_trusted_client", return_value="any-trust-token"
        ) as add_trusted_client,
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
                "add-trusted-client",
                params={
                    "name": "any-name",
                    "projects": "a,b,c",
                },
            ),
            state,
        )

        assert ctx.unit_status_history == [
            scenario.UnknownStatus(),
            scenario.MaintenanceStatus("Adding trusted client"),
        ]
        add_trusted_client.assert_called_once_with(
            name="any-name",
            projects=["a", "b", "c"],
        )
        assert ctx.action_results == {
            "result": "Client added to Incus truststore.\nRun `incus remote add <remote-name> <token>` to add the server as a remote.",
            "token": "any-trust-token",
        }
