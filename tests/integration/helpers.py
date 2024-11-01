from glob import glob
from logging import getLogger
from os import getenv
from pathlib import Path

from pytest_operator.plugin import OpsTest

logger = getLogger(__name__)


async def build_charm(ops_test: OpsTest) -> Path:
    """Build the current charm for integration tests.

    If running in a CI environment (indicated by the $CI env variable), finds
    the first .charm file in the $GITHUB_WORKSPACE directory and returns it.
    """
    in_ci = getenv("CI")
    if not in_ci:
        charm = await ops_test.build_charm(".")
        return charm

    logger.info("CI environment detected. Will get the .charm from the build step.")
    root_dir = getenv("GITHUB_WORKSPACE")
    if not root_dir:
        raise RuntimeError("No 'GITHUB_WORKSPACE' variable set")

    charm_dir = Path(root_dir) / "charm"
    charm_files = glob(str(charm_dir / "*.charm"))
    logger.debug(
        "Got all .charm files in directory. directory=%s files%s",
        charm_dir,
        charm_files,
    )
    if not charm_files:
        raise RuntimeError(f"No .charm files found in {charm_dir}")

    charm_file = Path(charm_files.pop()).absolute()
    logger.info("Found charm file. file=%s", charm_file)
    return charm_file
