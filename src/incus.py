"""Abstractions to interact with Incus."""

import logging
import subprocess
from tempfile import NamedTemporaryFile
from typing import List, Literal, Optional, Union

logger = logging.getLogger(__name__)


class IncusProcessError(Exception):
    """Error raised when an Incus CLI command fails."""

    ...


def set_config(key: str, value: Union[str, int]):
    """Set config `key` to `value` in the Incus daemon."""
    run_command("config", "set", key, str(value))


def add_trusted_certificate(
    cert: str,
    type: Literal["client", "metrics"],
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


def run_command(*args: str, input: Optional[str] = None):
    """Execute the incus CLI with the given `args` on the local socket.

    When provided, the `input` will be sent to the CLI process's stdin.
    """
    command = ["incus", "--force-local", *args]
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
