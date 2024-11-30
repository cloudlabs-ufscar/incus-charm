"""Abstractions to interact with Ceph config files."""

import logging
from configparser import ConfigParser
from pathlib import Path
from typing import Set

logger = logging.getLogger(__name__)

CEPH_DIR = Path("/etc/ceph")


def write_keyring_file(ceph_user: str, key: str, ceph_dir=CEPH_DIR):
    """Write the given `key` to a keyring file for the given `ceph_user`.

    If a keyring file for this user already exists, it is overriten with the
    new content.
    """
    keyring_path = ceph_dir / f"ceph.client.{ceph_user}.keyring"
    logger.debug("Writing keyring file. path=%s ceph_user=%s", keyring_path, ceph_user)
    keyring_path.parent.mkdir(parents=True, exist_ok=True)
    keyring_conf = ConfigParser()
    keyring_conf[f"client.{ceph_user}"] = {"key": key}
    with open(keyring_path, "w") as file:
        keyring_conf.write(file)
    logger.debug("Wrote keyring file. ceph_user=%s", ceph_user)


def write_ceph_conf_file(ceph_addresses: Set[str], ceph_dir=CEPH_DIR):
    """Write the given `ceph_addresses` to the ceph.conf file.

    If a ceph.conf file already exists and contains only the fields set by the
    charm, it is overriten with the new content. Otherwise, the file is left
    untouched.
    """
    ceph_conf_path = ceph_dir / "ceph.conf"
    logger.debug(
        "Writing ceph.conf file. path=%s ceph_addresses=%s", ceph_conf_path, ceph_addresses
    )
    ceph_conf_path.parent.mkdir(parents=True, exist_ok=True)
    ceph_conf = ConfigParser()

    # NOTE: The /etc/ceph/ceph.conf file might already exist for two reasons:
    #   1. The node is also a Ceph monitor node, and in this
    #   case, we don't want to override the ceph.conf file.
    #   2. This charm already created this file, and we now
    #   need to update it.
    # Since we control what the charm writes to the file, we can distinguish
    # between both cases by checking if the existing file contains only the
    # fields set by the charm.
    if ceph_conf_path.exists():
        ceph_conf.read(ceph_conf_path)
        conf_has_extra_sections = len(ceph_conf.sections()) > 1
        conf_global_has_extra_sections = "global" in ceph_conf and len(ceph_conf["global"]) > 1
        if conf_has_extra_sections or conf_global_has_extra_sections:
            logger.warning(
                "Ceph config file is either managed by other service or was manually edited. Skipping update of Ceph config file. file=%s",
                ceph_conf_path,
            )
            return

    hosts = list(ceph_addresses)
    hosts.sort()
    ceph_conf["global"] = {"mon host": " ".join(hosts)}
    with open(ceph_conf_path, "w") as file:
        ceph_conf.write(file)
    logger.debug(
        "Wrote Ceph config file. file=%s ceph_addresses=%s", ceph_conf_path, ceph_addresses
    )


def is_configured(ceph_user: str, ceph_dir=CEPH_DIR) -> bool:
    """Check if the required Ceph config files are present in the system."""
    ceph_conf_path = ceph_dir / "ceph.conf"
    keyring_path = ceph_dir / f"ceph.client.{ceph_user}.keyring"
    return ceph_conf_path.exists() and keyring_path.exists()
