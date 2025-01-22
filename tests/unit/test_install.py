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
    """Test the install event.

    The unit should add the APT repository and install the incus package.
    """
    with (
        patch("charm.IncusCharm._add_apt_repository") as add_apt_repository,
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._install_packages") as install_packages,
        patch("charm.IncusCharm._package_version", "any-version"),
        patch("charm.incus.is_clustered", return_value=is_clustered),
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(leader=leader)

        out = ctx.run(ctx.on.install(), state)

        assert out.workload_version == "any-version"
        add_apt_repository.assert_called_once_with(
            repository_line="deb https://pkgs.zabbly.com/incus/stable jammy main",
            gpg_key_url="https://pkgs.zabbly.com/key.asc",
        )
        install_packages.assert_called_once_with("incus")


@pytest.mark.parametrize(
    "leader,is_clustered", [(False, False), (True, False), (False, True), (True, True)]
)
def test_install_with_ceph_relation(leader, is_clustered):
    """Test the install event when a ceph relation is already established.

    The unit should add the APT repository and install both the incus and
    ceph packages.
    """
    with (
        patch("charm.IncusCharm._add_apt_repository") as add_apt_repository,
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._install_packages") as install_packages,
        patch("charm.IncusCharm._package_version", "any-version"),
        patch("charm.incus.is_clustered", return_value=is_clustered),
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            leader=leader,
            relations=[
                scenario.Relation(endpoint="ceph", interface="ceph-client"),
                scenario.PeerRelation(endpoint="cluster"),
            ],
        )

        out = ctx.run(ctx.on.install(), state)

        assert out.workload_version == "any-version"
        add_apt_repository.assert_called_once_with(
            repository_line="deb https://pkgs.zabbly.com/incus/stable jammy main",
            gpg_key_url="https://pkgs.zabbly.com/key.asc",
        )
        install_packages.assert_called_once_with("incus", "ceph-common")


@pytest.mark.parametrize(
    "leader,is_clustered", [(False, False), (True, False), (False, True), (True, True)]
)
def test_install_with_web_ui_enabled(leader, is_clustered):
    """Test the install event when the web UI is enabled.

    The unit should add the APT repository and install both the incus and
    incus-ui-canonical packages.
    """
    with (
        patch("charm.IncusCharm._add_apt_repository") as add_apt_repository,
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._install_packages") as install_packages,
        patch("charm.IncusCharm._package_version", "any-version"),
        patch("charm.incus.is_clustered", return_value=is_clustered),
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            leader=leader,
            config={"enable-web-ui": True},
            relations=[
                scenario.PeerRelation(endpoint="cluster"),
            ],
        )

        out = ctx.run(ctx.on.install(), state)

        assert out.workload_version == "any-version"
        add_apt_repository.assert_called_once_with(
            repository_line="deb https://pkgs.zabbly.com/incus/stable jammy main",
            gpg_key_url="https://pkgs.zabbly.com/key.asc",
        )
        install_packages.assert_called_once_with("incus", "incus-ui-canonical")


def test_install_repository_config():
    """Test the install event for the repository config.

    The unit should add the APT repository and install the incus package.
    """
    with (
        patch("charm.IncusCharm._add_apt_repository") as add_apt_repository,
        patch("charm.IncusCharm._package_installed", return_value=True),
        patch("charm.IncusCharm._install_packages") as install_packages,
        patch("charm.IncusCharm._package_version", "any-version"),
        patch("charm.incus.is_clustered", return_value=False),
        patch("charm.incus.get_cluster_member_info"),
    ):
        ctx = scenario.Context(IncusCharm)
        state = scenario.State(
            leader=True,
            config={
                "package-repository": "any-package-repository",
                "package-repository-gpg-key": "any-package-repository-gpg-key",
            },
        )

        out = ctx.run(ctx.on.install(), state)

        assert out.workload_version == "any-version"
        add_apt_repository.assert_called_once_with(
            repository_line="any-package-repository",
            gpg_key_url="any-package-repository-gpg-key",
        )
        install_packages.assert_called_once_with("incus")
