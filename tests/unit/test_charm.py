# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing


from unittest.mock import patch

import pytest
import scenario

from charm import IncusCharm


def test_install():
    with (
        patch("charm.IncusCharm._add_apt_repository") as add_apt_repository,
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.IncusCharm._install_package") as install_package,
        patch("charm.IncusCharm._package_version", "any-version"),
        patch("charm.IncusCharm._bootstrap_incus"),
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


def test_start():
    with (
        patch("charm.IncusCharm._add_apt_repository"),
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.IncusCharm._install_package"),
        patch("charm.IncusCharm._bootstrap_incus") as bootstrap_incus,
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State()

        out = ctx.run(ctx.on.start(), state)

        assert out.unit_status == scenario.ActiveStatus("Unit is ready")
        bootstrap_incus.assert_called_once()


@pytest.mark.parametrize("port", (8443, 1234, 9999))
def test_config_changed(port):
    with (
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.incus.set_config") as set_config,
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            config={"server_port": port},
            networks=[
                scenario.Network(
                    binding_name="public",
                    bind_addresses=[scenario.BindAddress([scenario.Address("10.0.0.1")])],
                )
            ],
        )

        out = ctx.run(ctx.on.config_changed(), state)

        assert out.unit_status == scenario.ActiveStatus("Unit is ready")
        set_config.assert_called_once_with("core.https_address", f"10.0.0.1:{port}")
