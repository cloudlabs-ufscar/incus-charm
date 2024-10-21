"""Abstractions to interact with Incus."""

import logging
import subprocess
from typing import Optional, Union

logger = logging.getLogger(__name__)


class IncusProcessError(Exception):
    """Error raised when an Incus CLI command fails."""

    ...


def set_config(key: str, value: Union[str, int]):
    """Set config `key` to `value` in the Incus daemon."""
    run_command("config", "set", key, str(value))


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
        raise IncusProcessError
