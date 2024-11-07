# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing


from unittest.mock import patch

import pytest
import scenario

from charm import IncusCharm


@pytest.mark.parametrize(
    "leader,is_clustered", [(False, False), (True, False), (False, True), (True, True)]
)
def test_install(leader, is_clustered):
    with (
        patch("charm.IncusCharm._add_apt_repository") as add_apt_repository,
        patch("charm.IncusCharm._package_installed", True),
        patch("charm.IncusCharm._install_package") as install_package,
        patch("charm.IncusCharm._package_version", "any-version"),
        patch("charm.incus.is_clustered", return_value=is_clustered),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(leader=leader)

        out = ctx.run(ctx.on.install(), state)

        assert out.workload_version == "any-version"
        add_apt_repository.assert_called_once_with(
            repository_line="deb https://pkgs.zabbly.com/incus/stable jammy main",
            gpg_key_url="https://pkgs.zabbly.com/key.asc",
        )
        install_package.assert_called_once_with()
