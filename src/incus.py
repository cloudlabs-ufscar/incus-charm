"""Abstractions to interact with Incus."""

import json
import logging
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Dict, List, Literal, Optional, Union

import yaml
from pydantic import BaseModel

logger = logging.getLogger(__name__)


CLIFormats = Literal["csv", "json", "table", "yaml", "compact"]
IncusStorageDriver = Literal["dir", "btrfs", "zfs", "ceph"]
IncusNetworkDriver = Literal["ovn"]
IncusClientCertificateType = Literal["client", "metrics"]

INCUS_VAR_DIR = Path("/var/lib/incus")


class ClusterMemberStatus(str, Enum):
    """Possible statuses for a cluster member."""

    ONLINE = "Online"
    EVACUATED = "Evacuated"
    OFFLINE = "Offline"
    BLOCKED = "Blocked"


class ClusterMemberInfo(BaseModel, extra="ignore"):
    """Information about the state of a cluster member."""

    status: ClusterMemberStatus
    message: str


@dataclass
class OvnConnectionOptions:
    """Configuration options to setup the OVN connection in Incus."""

    client_cert: str
    client_key: str
    client_ca: str
    northbound_connection: str


class IncusProcessError(Exception):
    """Error raised when an Incus CLI command fails."""

    # HACK: this is a temporary workaround for a known issue in which Incus
    # cannot propagate changes across some cluster members, causing the overall
    # command to fail.
    retryable_error_messages: List[str] = ["failed to connect to : failed to open connection:"]

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message

    @property
    def is_retryable(self) -> bool:
        """Whether the error is retryable.

        An error is considered retryable if its message is empirically
        known to indicate a transient failure.
        """
        return any(message in self.message for message in self.retryable_error_messages)


def set_config(key: str, value: Union[str, int]):
    """Set config `key` to `value` in the Incus daemon."""
    run_command("config", "set", key, str(value))


def is_clustered() -> bool:
    """Whether the local Incus node has clustering enabled."""
    output = run_command("query", "/1.0/cluster")
    cluster_data = json.loads(output)
    return cluster_data["enabled"]


def evacuate_node(node_name: str):
    """Evacuate the member identified by `node_name` in the Incus cluster."""
    run_command("cluster", "evacuate", node_name, "--force")


def remove_cluster_member(node_name: str):
    """Remove the member identified by `node_name` from the Incus cluster."""
    run_command("cluster", "remove", node_name)


def get_cluster_member_info(node_name: str) -> ClusterMemberInfo:
    """Get information for the member identified by `node_name` in the Incus cluster."""
    output = run_command("query", f"/1.0/cluster/members/{node_name}")
    member_data = json.loads(output)
    return ClusterMemberInfo(**member_data)


def set_cluster_member_failure_domain(node_name: str, failure_domain: str):
    """Set the failure domain of the cluster member identified by `node_name`."""
    run_command("cluster", "set", node_name, "--property", f"failure_domain={failure_domain}")


def get_supported_storage_drivers() -> List[str]:
    """Get all currently supported storage drivers."""
    output = run_command("query", "/1.0")
    node_data = json.loads(output)
    drivers = [driver["Name"] for driver in node_data["environment"]["storage_supported_drivers"]]
    return drivers


def enable_clustering(member_name: str):
    """Enable clustering on the local Incus node."""
    run_command("cluster", "enable", member_name)


def create_join_token(member_name: str) -> str:
    """Create a join token for the Incus cluster.

    The token can then be used by other units to join the Incus cluster.
    """
    token = run_command("cluster", "add", member_name)
    return token


def cluster_list(format: CLIFormats) -> str:
    """List all cluster members and their state."""
    return run_command("cluster", "list", "--format", format)


def bootstrap_node(preseed: dict):
    """Bootstrap the Incus node with the given `preseed` data."""
    run_command("admin", "init", "--preseed", input=yaml.dump(preseed))


def add_trusted_certificate(
    cert: str,
    type: IncusClientCertificateType,
    name: Optional[str] = None,
    projects: Optional[List[str]] = None,
):
    """Add the PEM encoded `cert` to the Incus daemon truststore."""
    with NamedTemporaryFile() as file:
        args = ["config", "trust", "add-certificate", file.name, "--type", type]
        if name:
            args.extend(["--name", name])
        if projects:
            args.extend(["--projects", ",".join(projects)])

        file.write(cert.strip().encode())
        file.flush()
        run_command(*args)


def update_cluster_certificate(cert: str, key: str):
    """Update the cluster members certificate to the new `cert` and `key`."""
    with NamedTemporaryFile() as cert_file, NamedTemporaryFile() as key_file:
        cert_file.write(cert.strip().encode())
        cert_file.flush()
        key_file.write(key.strip().encode())
        key_file.flush()
        run_command("cluster", "update-certificate", cert_file.name, key_file.name)


def update_server_certificate(cert: str, key: str, ca: str):
    """Update the server certificate with to the new `cert`, `key` and `ca`."""
    with open(INCUS_VAR_DIR / "server.crt", "w+") as file:
        file.write(cert)
    with open(INCUS_VAR_DIR / "server.key", "w+") as file:
        file.write(key)
    with open(INCUS_VAR_DIR / "server.ca", "w+") as file:
        file.write(ca)


def get_server_certificate() -> str:
    """Get the server certificate in the Incus var directory."""
    cert_path = INCUS_VAR_DIR / "server.crt"
    assert cert_path.exists(), f"Certificate file does not exist. cert_path={cert_path}"
    return cert_path.read_text().strip()


def create_storage(
    pool_name: str,
    storage_driver: IncusStorageDriver,
    source: Optional[str] = None,
    target: Optional[str] = None,
    pool_config: Optional[Dict[str, str]] = None,
):
    """Create a storage pool in Incus.

    Driver-specific parameters can be specified in `pool_config`.
    """
    args = ["storage", "create", pool_name, storage_driver]
    if source:
        args.append(f"source={source}")
    if pool_config:
        for name, value in pool_config.items():
            args.append(f"{name}={value}")
    if target:
        args.extend(["--target", target])

    run_command(*args)


def configure_storage(pool_name: str, pool_config: Dict[str, str]):
    """Configure a storage pool in Incus.

    The `pool_config` contains the parameters to be assigned to the storage pool
    identified by `pool_name`.
    """
    args = ["storage", "set", pool_name]
    for name, value in pool_config.items():
        args.append(f"{name}={value}")
    run_command(*args)


def set_ovn_northbound_connection(options: OvnConnectionOptions):
    """Set OVN northbound connection options in Incus.

    The options include the northbound database endpoints as well as the client
    certificates to be used when connecting to OVN.
    """
    run_command(
        "config",
        "set",
        f"network.ovn.ca_cert={options.client_ca}",
        f"network.ovn.client_cert={options.client_cert}",
        f"network.ovn.client_key={options.client_key}",
        f"network.ovn.northbound_connection={options.northbound_connection}",
    )


def run_command(*args: str, input: Optional[str] = None) -> str:
    """Execute the incus CLI with the given `args` on the local socket.

    When provided, the `input` will be sent to the CLI process's stdin.

    Returns the stdout output produced by the command.
    """
    command = ["incus", "--force-local", "--quiet", *args]
    logger.debug("Executing Incus command. command=%s input=%s", command, input)
    input_data = input.encode() if input else None
    process = subprocess.run(command, capture_output=True, input=input_data)
    logger.debug("Incus Command executed. command=%s process=%s", command, process)
    if process.returncode != 0:
        logger.error(
            "Error when running incus command. command=%s returncode=%s stderr=%s stdout=%s stdin=%s",
            process.args,
            process.returncode,
            process.stderr,
            process.stdout,
            input,
        )
        raise IncusProcessError(process.stderr.decode().strip())
    return process.stdout.decode().strip()
