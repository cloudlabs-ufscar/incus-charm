# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing


from unittest.mock import call, patch

import pytest
import scenario
from scenario.errors import UncaughtCharmError

from charm import IncusCharm


def test_install():
    with (
        patch("charm.IncusCharm._add_apt_repository") as add_apt_repository,
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.IncusCharm._install_package") as install_package,
        patch("charm.IncusCharm._package_version", "any-version"),
        patch("charm.IncusCharm._bootstrap_incus"),
        patch("charm.incus.is_clustered", return_value=True),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State()

        out = ctx.run(ctx.on.install(), state)

        assert out.unit_status == scenario.ActiveStatus("Unit is ready")
        assert out.workload_version == "any-version"
        add_apt_repository.assert_called_once_with(
            repository_line="deb https://pkgs.zabbly.com/incus/stable jammy main",
            gpg_key_url="https://pkgs.zabbly.com/key.asc",
        )
        install_package.assert_called_once_with()


def test_start_leader():
    with (
        patch("charm.IncusCharm._add_apt_repository"),
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.IncusCharm._install_package"),
        patch("charm.IncusCharm._bootstrap_incus") as bootstrap_incus,
        patch("charm.incus.is_clustered", return_value=True),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(leader=True)

        out = ctx.run(ctx.on.start(), state)

        assert out.unit_status == scenario.ActiveStatus("Unit is ready")
        bootstrap_incus.assert_called_once()


def test_start_non_leader():
    with (
        patch("charm.IncusCharm._add_apt_repository"),
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.IncusCharm._install_package"),
        patch("charm.IncusCharm._bootstrap_incus") as bootstrap_incus,
        patch("charm.incus.is_clustered", return_value=True),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(leader=False)

        out = ctx.run(ctx.on.start(), state)

        assert out.unit_status == scenario.ActiveStatus("Unit is ready")
        bootstrap_incus.assert_not_called()


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

        out = ctx.run(ctx.on.config_changed(), state)

        assert out.unit_status == scenario.ActiveStatus("Unit is ready")
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
