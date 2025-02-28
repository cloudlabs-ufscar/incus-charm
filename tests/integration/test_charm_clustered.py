#!/usr/bin/env python3
# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.

import asyncio
import base64
import json
import logging
import ssl
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
DEPLOY_TIMEOUT = 60 * 60  # 1h
OPERATION_TIMEOUT = 60 * 5  # 5min
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
        ops_test.model.wait_for_idle(apps=apps, status="active", timeout=DEPLOY_TIMEOUT),
    )


async def get_root_ca_cert(ops_test: OpsTest) -> str:
    """Retrieve the root CA certificate from Vault."""
    assert ops_test.model, "No model found"

    action = await ops_test.model.units["vault/0"].run_action("get-root-ca")
    await action.fetch_output()
    assert action.status == "completed", f"Action not completed: {action.results}"
    assert "output" in action.results
    ca_cert = yaml.safe_load(action.results.get("output"))
    ca_cert = "\n".join(ca_cert.replace(" CERTIFICATE-", "CERTIFICATE-").split()).replace(
        "CERTIFICATE-", " CERTIFICATE-"
    )
    return ca_cert


async def get_certificate_chain(ops_test: OpsTest, unit: Unit, tmp_path: Path) -> str:
    """Retrieve the certificate from the incus `unit` and validate it against Vault's root CA."""
    ca_path = tmp_path / "ca.crt"
    ca_cert = await get_root_ca_cert(ops_test)
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
async def test_storage_pools(ops_test: OpsTest, ceph_rbd_features: str = "layering,deep-flatten"):
    """Test the configured storage pools.

    All units should have a local Btrfs and a Ceph storage pool.
    """
    assert ops_test.model, "No model found"

    application = ops_test.model.applications[APP_NAME]
    assert application, "Application not found in model"
    for unit in application.units:
        # HACK: Incus's first command always outputs a help message that breaks
        # output parsing. To bypass this, we always run a dummy command first.
        await ops_test.juju(*f"exec --unit {unit.name} -- incus info".split())
        result_code, stdout, stderr = await ops_test.juju(
            *f"exec --unit {unit.name} -- incus query /1.0/storage-pools?recursion=1".split()
        )

        assert result_code == 0, stderr
        assert stderr == ""
        assert stdout

        storage_pools = json.loads(stdout)
        assert len(storage_pools) == 2

        btrfs_storage_pools = [pool for pool in storage_pools if pool["driver"] == "btrfs"]
        assert len(btrfs_storage_pools) == 1
        btrfs_storage_pool = btrfs_storage_pools[0]
        assert btrfs_storage_pool["name"] == "default"
        assert btrfs_storage_pool["status"] == "Created"
        assert len(btrfs_storage_pool["locations"]) == len(application.units), (
            "Storage pool not created on all cluster members"
        )

        ceph_storage_pools = [pool for pool in storage_pools if pool["driver"] == "ceph"]
        assert len(ceph_storage_pools) == 1
        ceph_storage_pool = ceph_storage_pools[0]
        assert ceph_storage_pool["name"] == "ceph"
        assert ceph_storage_pool["status"] == "Created"
        assert len(ceph_storage_pool["locations"]) == len(application.units), (
            "Storage pool not created on all cluster members"
        )
        assert ceph_storage_pool["config"]["ceph.osd.pool_name"] == "incus"
        assert ceph_storage_pool["config"]["ceph.user.name"] == "incus"
        assert ceph_storage_pool["config"]["ceph.rbd.features"] == ceph_rbd_features


@pytest.mark.abort_on_fail
async def test_ovn_northbound_config(ops_test: OpsTest):
    """Test the configuration for OVN Northbound connection.

    All units should have the OVN endpoints and client certificates set.
    """
    assert ops_test.model, "No model found"

    ovn_central_application = ops_test.model.applications["ovn-central"]
    assert ovn_central_application, "Application ovn-central not found in model"
    ovn_central_ips = [await unit.get_public_address() for unit in ovn_central_application.units]
    ovn_northbound_connection = ",".join(sorted([f"ssl:{ip}:6641" for ip in ovn_central_ips]))

    incus_unit = ops_test.model.units["incus/0"]
    result_code, stdout, stderr = await ops_test.juju(
        *f"exec --unit {incus_unit.name} -- cat /var/lib/incus/cluster.crt".split()
    )
    assert result_code == 0, stderr
    assert stderr == ""
    assert stdout
    client_cert = "\n".join(stdout.replace(" CERTIFICATE-", "CERTIFICATE-").split()).replace(
        "CERTIFICATE-", " CERTIFICATE-"
    )

    result_code, stdout, stderr = await ops_test.juju(
        *f"exec --unit {incus_unit.name} -- cat /var/lib/incus/cluster.key".split()
    )
    assert result_code == 0, stderr
    assert stderr == ""
    assert stdout
    client_key = "\n".join(stdout.replace(" RSA PRIVATE KEY-", "RSAPRIVATEKEY-").split()).replace(
        "RSAPRIVATEKEY-", " RSA PRIVATE KEY-"
    )

    root_ca_cert = await get_root_ca_cert(ops_test)

    application = ops_test.model.applications[APP_NAME]
    assert application, "Application not found in model"
    for unit in application.units:
        # HACK: Incus's first command always outputs a help message that breaks
        # output parsing. To bypass this, we always run a dummy command first.
        await ops_test.juju(*f"exec --unit {unit.name} -- incus info".split())
        result_code, stdout, stderr = await ops_test.juju(
            *f"exec --unit {unit.name} -- incus query /1.0".split()
        )

        assert result_code == 0, stderr
        assert stderr == ""
        assert stdout

        output = json.loads(stdout)
        config = output["config"]

        assert config.get("network.ovn.northbound_connection") == ovn_northbound_connection
        assert config.get("network.ovn.ca_cert") == root_ca_cert
        assert config.get("network.ovn.client_cert") == client_cert
        assert config.get("network.ovn.client_key") == client_key


@pytest.mark.abort_on_fail
@pytest.mark.parametrize("port", (8888, 8443))
async def test_change_port(ops_test: OpsTest, port: int):
    """Test changing the server port via a config option.

    All Incus servers should be updated and accessible on the new port.
    """
    assert ops_test.model, "No model found"

    application = ops_test.model.applications[APP_NAME]
    assert application, "Application not found in model"

    await application.set_config({"server-port": str(port)})
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
@pytest.mark.parametrize(
    "ceph_rbd_features", ("layering,exclusive-lock,fast-diff,journaling", "layering,deep-flatten")
)
async def test_change_ceph_rbd_features(ops_test: OpsTest, ceph_rbd_features):
    """Test changing the Ceph RBD features via a config option.

    All Incus servers should be updated.
    """
    assert ops_test.model, "No model found"

    application = ops_test.model.applications[APP_NAME]
    assert application, "Application not found in model"

    await application.set_config({"ceph-rbd-features": str(ceph_rbd_features)})
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        raise_on_blocked=True,
        timeout=OPERATION_TIMEOUT,
    )

    await test_storage_pools(ops_test, ceph_rbd_features=ceph_rbd_features)


@pytest.mark.abort_on_fail
async def test_enable_web_ui(ops_test: OpsTest):
    """Test enabling and disabling the Incus web UI via a config option.

    All Incus servers should be updated.
    """
    assert ops_test.model, "No model found"

    application = ops_test.model.applications[APP_NAME]
    assert application, "Application not found in model"

    # The web UI is disabled by default
    for unit in application.units:
        assert unit.workload_status_message == "Online: Fully operational"
        public_address = await unit.get_public_address()
        response = requests.get(f"https://{public_address}:8443/ui/login", verify=False)
        assert response.status_code == 404

    # Enable the web UI
    await application.set_config({"enable-web-ui": "true"})
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=OPERATION_TIMEOUT * 5,
    )

    # The web UI is now enabled
    for unit in application.units:
        assert unit.workload_status_message == "Online: Fully operational"
        public_address = await unit.get_public_address()
        response = requests.get(f"https://{public_address}:8443/ui/login", verify=False)
        assert response.ok
        assert response.headers["content-type"] == "text/html; charset=utf-8"
        assert b"Incus UI" in response.content

    # Disable the web UI
    await application.set_config({"enable-web-ui": "false"})
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=OPERATION_TIMEOUT * 5,
    )

    # The web UI is now disabled
    for unit in application.units:
        assert unit.workload_status_message == "Online: Fully operational"
        public_address = await unit.get_public_address()
        response = requests.get(f"https://{public_address}:8443/ui/login", verify=False)
        assert response.status_code == 404


@pytest.mark.abort_on_fail
async def test_add_trusted_certificate(ops_test: OpsTest, tmp_path: Path):
    """Test adding a trusted certificate via the add-trusted-certificate action.

    The certificate should be added and trusted to all Incus servers.
    """
    assert ops_test.model, "No model found"

    application = ops_test.model.applications[APP_NAME]
    assert application, "Application not found in model"

    # Request the certificate and key from vault
    key_path = (tmp_path / "incus.key").absolute()
    cert_path = (tmp_path / "incus.crt").absolute()
    unit = ops_test.model.units["vault/0"]
    assert unit, "No vault/0 unit found in model"
    vault_action = await unit.run_action(
        "generate-certificate", **{"common-name": "test-certificate", "sans": ""}
    )
    await vault_action.fetch_output()
    assert vault_action.status == "completed", f"Action not completed: {vault_action.results}"

    assert "output" in vault_action.results
    vault_result = json.loads(vault_action.results.get("output").replace("'", '"'))
    cert_path.write_text(vault_result["certificate"])
    key_path.write_text(vault_result["private_key"])

    # The certificate is not trusted
    for unit in application.units:
        public_address = await unit.get_public_address()
        response = requests.get(
            f"https://{public_address}:8443/1.0",
            verify=False,
            cert=(str(cert_path), str(key_path)),
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
async def test_add_trusted_client(ops_test: OpsTest):
    """Test adding a trusted client via the add-trusted-client action.

    A valid trust token should be generated.
    """
    assert ops_test.model, "No model found"

    application = ops_test.model.applications[APP_NAME]
    assert application, "Application not found in model"

    # Add the trusted client
    unit = application.units[0]
    action = await unit.run_action(
        "add-trusted-client",
        name="test-client",
    )
    await action.fetch_output()
    assert action.status == "completed", f"Action not completed: {action.results}"

    token = action.results.get("token")
    assert token, f"No join token found in action results: {action.results}"
    token_content = json.loads(base64.b64decode(token))
    assert token_content["client_name"] == "test-client"


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
        constraints=constraints.parse("virt-type=virtual-machine mem=1536M")
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
    await test_storage_pools(ops_test)
    await test_ovn_northbound_config(ops_test)


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
        f"incus launch images:ubuntu/22.04 {TEST_INSTANCE_NAME} --vm --storage ceph --quiet --target {target_node}"
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
    await test_storage_pools(ops_test)
    await test_ovn_northbound_config(ops_test)


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
    await test_storage_pools(ops_test)
    await test_ovn_northbound_config(ops_test)

    # Get the new certificates
    new_certificates: Set[str] = set()
    for unit in application.units:
        new_certificate = await get_certificate_chain(ops_test, unit=unit, tmp_path=tmp_path)
        new_certificates.add(new_certificate)
    assert len(new_certificates) == 1, "Mismatched certificates between units"
    new_certificate = new_certificates.pop()

    # Assert that the certificates changed
    assert new_certificate != certificate


@pytest.mark.abort_on_fail
async def test_evacuate_cluster_member(ops_test: OpsTest, tmp_path: Path):
    """Test evacuating a cluster's member.

    The unit should be evacuated from the Incus cluster.
    """
    assert ops_test.model, "No model found"

    application = ops_test.model.applications[APP_NAME]
    assert application, "Application not found in model"

    # Verify which unit has the instance (VM)
    unit = application.units[0]
    action = await unit.run("incus ls --format json")
    await action.fetch_output()
    assert action.status == "completed", f"Action not completed: {action.results}"
    assert action.results["return-code"] == 0, f"Action failed: {action.results['stderr']}"
    result = json.loads(action.results["stdout"])
    assert len(result) == 1
    instance_node = int(result[0]["location"][-1])

    # Evacuate a unit that doesn't have the instance
    evacuated_node = (instance_node + 1) % 3
    action = await ops_test.model.units[f"incus/{evacuated_node}"].run_action("evacuate")
    await action.fetch_output()
    assert action.status == "completed", f"Action not completed: {action.results}"

    # The unit should have its status updated to "Evacuated"
    unit = application.units[0]
    action = await unit.run_action("cluster-list", format="yaml")
    await action.fetch_output()
    assert action.status == "completed", f"Action not completed: {action.results}"
    assert "result" in action.results
    result = yaml.safe_load(action.results.get("result"))
    assert len(result) == len(application.units), "Not all units are part of the Incus cluster."
    for member in result:
        if member["server_name"][-1] == str(evacuated_node):
            assert member["status"] == "Evacuated"
            assert member["message"] == "Unavailable due to maintenance"


@pytest.mark.abort_on_fail
async def test_restore_cluster_member(ops_test: OpsTest, tmp_path: Path):
    """Test restoring a cluster's member.

    The unit should be restored to the Incus cluster.
    """
    assert ops_test.model, "No model found"

    application = ops_test.model.applications[APP_NAME]
    assert application, "Application not found in model"

    # Verify which unit has the instance (VM)
    unit = application.units[0]
    action = await unit.run("incus ls --format json")
    await action.fetch_output()
    assert action.status == "completed", f"Action not completed: {action.results}"
    assert action.results["return-code"] == 0, f"Action failed: {action.results['stderr']}"
    result = json.loads(action.results["stdout"])
    assert len(result) == 1
    instance_node = int(result[0]["location"][-1])

    # Restore the unit
    restored_node = (instance_node + 1) % 3
    action = await ops_test.model.units[f"incus/{restored_node}"].run_action("restore")
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=DEPLOY_TIMEOUT,
    )
    await action.fetch_output()
    assert action.status == "completed", f"Action not completed: {action.results}"

    # The unit should have its status updated to "Online"
    unit = application.units[0]
    action = await unit.run_action("cluster-list", format="yaml")
    await action.fetch_output()
    assert action.status == "completed", f"Action not completed: {action.results}"
    assert "result" in action.results
    result = yaml.safe_load(action.results.get("result"))
    assert len(result) == len(application.units), "Not all units are part of the Incus cluster."
    for member in result:
        if member["server_name"][-1] == str(restored_node):
            assert member["status"] == "Online"
            assert member["message"] == "Fully operational"

    # The cluster should remain completely functional
    await test_workload_connectivity(ops_test, tmp_path=tmp_path)
    await test_cluster_state(ops_test)
