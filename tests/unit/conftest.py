import sys
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def certificate() -> str:
    return """
-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIUBiNmB78ZaFxpvbvlv/TGdsreF7AwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLaW5jdXMubG9jYWwwHhcNMjQxMDMxMTA1MjA0WhcNMjQx
MTMwMTA1MjA0WjAWMRQwEgYDVQQDDAtpbmN1cy5sb2NhbDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBALV+WYKz0RCVBTSPIR9qThDfrtWzGuwBchdeYi0D
oKzRf3xGme8NTo8woKn39XjQ6+LL9rguzm9rlfwQw84C0ECz4nBiy9Vo54/4w+Af
WVNnY0LPncQTLuRdEqvsQ/J6Vxat5/2EA83txs0fI4rn/dAbdQnMgZvmreBOPUeC
pZgINgRvipC3p/SUHvScXnV7+fWZ5dVdB6yXyUYuCYcAB/IwrydwBBI8LAvGOKUb
uiJdavIhaAiuzaK7BOly4Rz8Ac6ojXoK56RYBsghNW8MRjvpVn4Y/0+YMtcmV+PP
6B9z2V0hLb6/kOlQno4FaETLTLjnBJ9qn5z2V5ggq3Dm71ECAwEAAaNTMFEwHQYD
VR0OBBYEFEZDv7FWk8WVvV8nCBi0ZnxoZ97oMB8GA1UdIwQYMBaAFEZDv7FWk8WV
vV8nCBi0ZnxoZ97oMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
AJptjWWs5zeg2aJQme+00F8yHXcvrSjMKw/tpt32hiubJ/4eVU9bCn5QhGBMUDCK
MJxzf65AMZBPt/wlFhfUNrHHA+gY1B/AbEYuDzj/dbOjiIjNc1KllZK52qh2D4kB
inW5m6/GhFrcnwRNwYjQ8Oj1AgprAIjSKu65LSV7PrFAFlYlE8d5QCUvwpLJo6dS
Hwr6woY26gY8F2ufXT4+3k3G1oAIFCbpQaSSNsuQm7gA6sIkN2J4dBxny6hWRuEj
uo2X0ZQJ9mItK1ddreRO9pY9H9RyIwXIn5YtYrcit/pFB3HDDlmIwXGIUS+FCrOO
JRtVephE8skzsbl6LVHuoGM=
-----END CERTIFICATE-----
    """.strip()


# HACK: charmhelpers does some platform-specific checks at the module level
# this means that if we import its modules on any OS other than Ubuntu or
# CentOS we'll get a runtime error. To make the tests run on other systems,
# we need to mock some of those modules.
fake_modules = [
    "charmhelpers",
    "charmhelpers.contrib",
    "charmhelpers.contrib.storage",
    "charmhelpers.contrib.storage.linux",
    "charmhelpers.contrib.storage.linux.ceph",
    "charmhelpers.core",
    "charmhelpers.fetch",
    "charmhelpers.fetch.ubuntu",
    "charmhelpers.fetch.ubuntu_apt_pkg",
    "charmhelpers.osplatform",
]
for module_name in fake_modules:
    sys.modules[module_name] = MagicMock(name=module_name)

import charmhelpers.osplatform  # noqa: E402

# Mock the platform inside the charmhelpers module
charmhelpers.osplatform.get_platform.return_value = "ubuntu"
