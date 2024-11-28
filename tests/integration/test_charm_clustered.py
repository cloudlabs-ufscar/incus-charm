#!/usr/bin/env python3
# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.

import asyncio
import json
import logging
import ssl
import subprocess
from pathlib import Path
from typing import Set

import juju.constraints as constraints
import pytest
import requests
import yaml
from helpers import build_charm
from jinja2 import Template
from juju.unit import Unit
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
DEPLOY_TIMEOUT = 30 * 60  # 30min
OPERATION_TIMEOUT = 60  # 1min
APP_NAME = METADATA["name"]
BUNDLE_FILENAME = Path("tests/integration/bundles/incus_clustered.yaml.j2").absolute()
TEST_INSTANCE_NAME = "test-instance"


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest, tmp_path: Path):
    """Build the charm-under-test and deploy it together with related charms.

    Assert on the unit status before any relations/configurations take place.
    """
    assert ops_test.model, "No model found"

    # Build and deploy charm from local source folder
    charm = await build_charm(ops_test)

    # Render the test bundle with the built charm
    bundle_path = tmp_path / "bundle.yaml"
    with open(BUNDLE_FILENAME) as file:
        template = Template(file.read())
        rendered_bundle = template.render(charm_incus=charm)

    # Write the rendered bundle to a temporary file
    with open(bundle_path, "w+") as file:
        file.write(rendered_bundle)

    # Retrieve applications present in the bundle
    bundle = yaml.safe_load(rendered_bundle)
    apps = list(bundle["applications"])

    # Deploy the charm and wait for an active/idle status on all applications
    await asyncio.gather(
        ops_test.model.deploy(bundle_path),
        ops_test.model.wait_for_idle(
            apps=apps,
            status="active",
            raise_on_blocked=True,
            timeout=DEPLOY_TIMEOUT,
        ),
    )


async def get_certificate_chain(ops_test: OpsTest, unit: Unit, tmp_path: Path) -> str:
    """Retrieve the certificate from the incus `unit` and validate it against Vault's root CA."""
    ca_path = tmp_path / "ca.crt"
    action = await ops_test.model.units["vault/0"].run_action("get-root-ca")
    await action.fetch_output()
    assert action.status == "completed", f"Action not completed: {action.results}"
    assert "output" in action.results
    ca_cert = yaml.safe_load(action.results.get("output"))
    ca_cert = "\n".join(ca_cert.replace(" CERTIFICATE-", "CERTIFICATE-").split()).replace(
        "CERTIFICATE-", " CERTIFICATE-"
    )
    ca_path.write_text(ca_cert)

    public_address = await unit.get_public_address()
    certificate = ssl.get_server_certificate(
        addr=(public_address, 8443), ca_certs=str(ca_path.absolute())
    )
    return "\n".join([certificate.strip(), ca_cert])


@pytest.mark.abort_on_fail
async def test_workload_connectivity(ops_test: OpsTest, tmp_path: Path):
    """Test the workload connectivity.

    All units should have an active status and be remotely accessible via
    the HTTPS API.
    """
    assert ops_test.model, "No model found"

    application = ops_test.model.applications[APP_NAME]
    assert application, "Application not found in model"

    certificates: Set[str] = set()
    for unit in application.units:
        certificate = await get_certificate_chain(ops_test, unit=unit, tmp_path=tmp_path)
        certificates.add(certificate)
        assert unit.workload_status_message == "Online: Fully operational"

        cert_path = tmp_path / "cert.crt"
        cert_path.write_text(certificate)
        public_address = await unit.get_public_address()
        response = requests.get(f"https://{public_address}:8443", verify=False)
        assert response.ok
        content = json.loads(response.content)
        assert content["status"] == "Success"
        assert content["status_code"] == 200
        assert content["error_code"] == 0

    assert len(certificates) == 1, "Mismatched certificates between units"


@pytest.mark.abort_on_fail
async def test_cluster_state(ops_test: OpsTest):
    """Test the Incus cluster state.

    All units should be part of the Incus cluster and have an operational status.
    """
    assert ops_test.model, "No model found"

    application = ops_test.model.applications[APP_NAME]
    assert application, "Application not found in model"

    unit = application.units[0]
    action = await unit.run_action("cluster-list", format="yaml")
    await action.fetch_output()
    assert action.status == "completed", f"Action not completed: {action.results}"

    assert "result" in action.results
    result = yaml.safe_load(action.results.get("result"))

    assert len(result) == len(application.units), "Not all units are part of the Incus cluster."
    machines = [
        ops_test.model.machines[machine] for machine in await ops_test.model.get_machines()
    ]
    machine_hostnames = [machine.hostname for machine in machines]
    for member in result:
        assert member["server_name"] in machine_hostnames
        assert member["status"] == "Online"
        assert member["message"] == "Fully operational"
        assert member["failure_domain"] == "default"


@pytest.mark.abort_on_fail
@pytest.mark.parametrize("port", (8888, 8443))
async def test_change_port(ops_test: OpsTest, port: int):
    """Test changing the server port via a config option.

    All Incus servers should be updated and accessible on the new port.
    """
    assert ops_test.model, "No model found"

    application = ops_test.model.applications[APP_NAME]
    assert application, "Application not found in model"

    await application.set_config({"server_port": str(port)})
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        raise_on_blocked=True,
        timeout=OPERATION_TIMEOUT,
    )

    for unit in application.units:
        public_address = await unit.get_public_address()
        response = requests.get(f"https://{public_address}:{port}", verify=False)
        assert response.ok
        content = json.loads(response.content)
        assert content["status"] == "Success"
        assert content["status_code"] == 200
        assert content["error_code"] == 0


@pytest.mark.abort_on_fail
async def test_add_trusted_certificate(ops_test: OpsTest, tmp_path: Path):
    """Test adding a trusted certificate via the add-trusted-certificate action.

    The certificate should be added and trusted to all Incus servers.
    """
    assert ops_test.model, "No model found"

    application = ops_test.model.applications[APP_NAME]
    assert application, "Application not found in model"

    # Create the certificate and key
    key_path = str((tmp_path / "incus.key").absolute())
    cert_path = str((tmp_path / "incus.crt").absolute())
    process = subprocess.run(
        f"openssl req -x509 -newkey rsa:2048 -keyout {key_path} -nodes -out {cert_path} -subj /CN=incus.local".split(),
        capture_output=True,
    )
    assert (
        process.returncode == 0
    ), f"Failed to create certificate. returncode={process.returncode} stdout={process.stdout} stderr={process.stderr}"

    # The certificate is not trusted
    for unit in application.units:
        public_address = await unit.get_public_address()
        response = requests.get(
            f"https://{public_address}:8443/1.0", verify=False, cert=(cert_path, key_path)
        )
        assert response.ok
        content = json.loads(response.content)
        assert content["status"] == "Success"
        assert content["status_code"] == 200
        assert content["error_code"] == 0
        assert content["metadata"]["auth"] == "untrusted"

    # Add the trusted certificate
    unit = application.units[0]
    action = await unit.run_action(
        "add-trusted-certificate",
        cert=Path(cert_path).read_text(),
        name="test-certificate",
    )
    await action.fetch_output()
    assert action.status == "completed", f"Action not completed: {action.results}"

    # The certificate is now trusted
    for unit in application.units:
        public_address = await unit.get_public_address()
        response = requests.get(
            f"https://{public_address}:8443/1.0", verify=False, cert=(cert_path, key_path)
        )
        assert response.ok
        content = json.loads(response.content)
        assert content["status"] == "Success"
        assert content["status_code"] == 200
        assert content["error_code"] == 0
        assert content["metadata"]["auth"] == "trusted"


@pytest.mark.abort_on_fail
async def test_add_unit(ops_test: OpsTest, tmp_path: Path):
    """Test adding a new unit to the application.

    The new unit should join the existing Incus cluster and be remotely
    accessible via the HTTPS API.
    """
    assert ops_test.model, "No model found"

    application = ops_test.model.applications[APP_NAME]
    assert application, "Application not found in model"

    await ops_test.model.add_machine(
        constraints=constraints.parse("virt-type=virtual-machine mem=1G")
    )
    await application.add_unit(to="3")
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        raise_on_blocked=True,
        timeout=DEPLOY_TIMEOUT,
    )

    await test_workload_connectivity(ops_test, tmp_path)
    await test_cluster_state(ops_test)


@pytest.mark.abort_on_fail
async def test_create_instance(ops_test: OpsTest):
    """Test the creation of an instance in the Incus cluster.

    The instance should be successfully created and assigned to a cluster member.
    """
    assert ops_test.model, "No model found"

    application = ops_test.model.applications[APP_NAME]
    assert application, "Application not found in model"

    # NOTE: we explicitly create the instance on the incus/3 unit because we'll
    # remove it on the next test. This lets us more easily test the evacuation of
    # departing units
    unit = application.units[0]
    target_node = ops_test.model.units["incus/3"].machine.hostname
    action = await unit.run(
        f"incus launch images:ubuntu/22.04 {TEST_INSTANCE_NAME} --vm --quiet --target {target_node}"
    )
    await action.fetch_output()
    assert action.status == "completed", f"Action not completed: {action.results}"
    assert action.results["return-code"] == 0, f"Action failed: {action.results['stderr']}"

    # The new instance should have been created in the specified node
    action = await unit.run("incus ls --format json")
    await action.fetch_output()
    assert action.status == "completed", f"Action not completed: {action.results}"
    assert action.results["return-code"] == 0, f"Action failed: {action.results['stderr']}"
    result = json.loads(action.results["stdout"])
    assert len(result) == 1
    assert result[0]["name"] == TEST_INSTANCE_NAME
    assert result[0]["status"] == "Running"
    assert result[0]["type"] == "virtual-machine"
    assert result[0]["location"] == target_node


@pytest.mark.abort_on_fail
async def test_remove_unit(ops_test: OpsTest, tmp_path: Path):
    """Test removing an existing unit from the application.

    The removed unit should be evacuated and leave the Incus cluster.
    """
    assert ops_test.model, "No model found"

    application = ops_test.model.applications[APP_NAME]
    assert application, "Application not found in model"

    # Remove the unit
    removed_node = ops_test.model.units["incus/3"].machine.hostname
    await ops_test.model.destroy_unit("incus/3")
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=DEPLOY_TIMEOUT,
    )

    # The existing instance should have migrated to another node
    action = await application.units[0].run("incus ls --format json")
    await action.fetch_output()
    assert action.status == "completed", f"Action not completed: {action.results}"
    assert action.results["return-code"] == 0, f"Action failed: {action.results['stderr']}"
    result = json.loads(action.results["stdout"])
    assert len(result) == 1
    assert result[0]["name"] == TEST_INSTANCE_NAME
    assert result[0]["status"] == "Running"
    assert result[0]["type"] == "virtual-machine"
    assert result[0]["location"] != removed_node

    # The cluster should remain completely functional
    await test_workload_connectivity(ops_test, tmp_path=tmp_path)
    await test_cluster_state(ops_test)


@pytest.mark.abort_on_fail
async def test_reissue_certificates(ops_test: OpsTest, tmp_path: Path):
    """Test reissuing the certificates on Vault.

    The cluster should remain operational. The certificate should be updated
    on all cluster members.
    """
    assert ops_test.model, "No model found"

    application = ops_test.model.applications[APP_NAME]
    assert application, "Application not found in model"

    # Get the current certificates
    certificates: Set[str] = set()
    for unit in application.units:
        certificate = await get_certificate_chain(ops_test, unit=unit, tmp_path=tmp_path)
        certificates.add(certificate)
    assert len(certificates) == 1, "Mismatched certificates between units"
    certificate = certificates.pop()

    # Reissue the certificates
    action = await ops_test.model.units["vault/0"].run_action("reissue-certificates")
    await action.fetch_output()
    assert action.status == "completed", f"Action not completed: {action.results}"
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME, "vault"],
        status="active",
        timeout=DEPLOY_TIMEOUT,
    )

    # The cluster should remain completely functional
    await test_workload_connectivity(ops_test, tmp_path=tmp_path)
    await test_cluster_state(ops_test)

    # Get the new certificates
    new_certificates: Set[str] = set()
    for unit in application.units:
        new_certificate = await get_certificate_chain(ops_test, unit=unit, tmp_path=tmp_path)
        new_certificates.add(new_certificate)
    assert len(new_certificates) == 1, "Mismatched certificates between units"
    new_certificate = new_certificates.pop()

    # Assert that the certificates changed
    assert new_certificate != certificate
