# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing


from unittest.mock import call, patch

import pytest
import scenario
from scenario.errors import UncaughtCharmError

from charm import IncusCharm


@pytest.mark.parametrize("server_port,cluster_port", [(8443, 8443), (1234, 1235), (9999, 2000)])
def test_config_changed(server_port, cluster_port):
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.incus.set_config") as set_config,
        patch("charm.incus.is_clustered", return_value=True),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            config={"server_port": server_port, "cluster_port": cluster_port},
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

        ctx.run(ctx.on.config_changed(), state)

        set_config.assert_has_calls(
            [
                call("core.https_address", f"10.0.0.1:{server_port}"),
                call("cluster.https_address", f"10.0.0.2:{cluster_port}"),
            ]
        )


@pytest.mark.parametrize(
    "server_port,cluster_port",
    [(-1, 8443), (1234, -1), (99999999, 8843), (8843, 99999999)],
)
def test_config_changed_invalid_port(server_port, cluster_port):
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.incus.set_config") as set_config,
        patch("charm.incus.is_clustered", return_value=True),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            config={"server_port": server_port, "cluster_port": cluster_port},
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

        with pytest.raises(UncaughtCharmError):
            ctx.run(ctx.on.config_changed(), state)

        assert ctx.unit_status_history == [scenario.UnknownStatus()]
        set_config.assert_not_called()
