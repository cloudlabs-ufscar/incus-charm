#!/usr/bin/env python3
# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.

import asyncio
import json
import logging
from pathlib import Path

import pytest
import requests
import yaml
from jinja2 import Template
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
DEPLOY_TIMEOUT = 10 * 60  # 10min
OPERATION_TIMEOUT = 60  # 1min
APP_NAME = METADATA["name"]
BUNDLE_FILENAME = Path("tests/integration/bundles/incus.yaml.j2").absolute()


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest, tmp_path: Path):
    """Build the charm-under-test and deploy it together with related charms.

    Assert on the unit status before any relations/configurations take place.
    """
    assert ops_test.model, "No model found"

    # Build and deploy charm from local source folder
    charm = await ops_test.build_charm(".")

    # Render the test bundle with the built charm
    bundle_path = tmp_path / "bundle.yaml"
    with open(BUNDLE_FILENAME) as file:
        template = Template(file.read())
        rendered_bundle = template.render(charm_incus=charm)

    # Write the rendered bundle to a temporary file
    with open(bundle_path, "w+") as file:
        file.write(rendered_bundle)

    # Deploy the charm and wait for active/idle status
    await asyncio.gather(
        ops_test.model.deploy(bundle_path),
        ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="active",
            raise_on_blocked=True,
            timeout=DEPLOY_TIMEOUT,
        ),
    )


@pytest.mark.abort_on_fail
async def test_workload_connectivity(ops_test: OpsTest):
    assert ops_test.model, "No model found"

    application = ops_test.model.applications[APP_NAME]
    assert application, "Application not found in model"

    for unit in application.units:
        assert unit.workload_status_message == "Unit is ready"
        public_address = await unit.get_public_address()

        response = requests.get(f"https://{public_address}:8443", verify=False)
        assert response.ok

        content = json.loads(response.content)
        assert content["status"] == "Success"
        assert content["status_code"] == 200
        assert content["error_code"] == 0


@pytest.mark.abort_on_fail
async def test_change_port(ops_test: OpsTest):
    assert ops_test.model, "No model found"

    application = ops_test.model.applications[APP_NAME]
    assert application, "Application not found in model"

    new_port = 8888
    await application.set_config({"server_port": str(new_port)})
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        raise_on_blocked=True,
        timeout=OPERATION_TIMEOUT,
    )

    for unit in application.units:
        public_address = await unit.get_public_address()

        response = requests.get(f"https://{public_address}:{new_port}", verify=False)
        assert response.ok

        content = json.loads(response.content)
        assert content["status"] == "Success"
        assert content["status_code"] == 200
        assert content["error_code"] == 0
