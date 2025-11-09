# CI

The project's CI process relies on self-hosted GitHub Actions runners. This document provides an overview of the environment setup to ensure reproducibility.

## Runner Infrastructure

We use [garm](https://github.com/cloudbase/garm) to manage our self-hosted runners. Garm uses an [Incus](https://linuxcontainers.org/incus/) back-end to spin up ephemeral job runners in containers.

### Runner Image

The runners are based on the official LXC Ubuntu cloud image: `images:ubuntu/noble/cloud`.

### Incus Profile

A custom Incus profile is applied to each runner container to set resource limits, load extra kernel modules and enabling nested virtualization (relevant for integration tests). The profile is defined as follows:

```yaml
config:
  # Basic resource limits
  limits.cpu: "4"
  limits.memory: 16GiB
  # Extra kernel modules that need to be loaded to enable nested virtualization
  linux.kernel_modules: iptable_nat, ip6table_nat, ebtables, kvm, kvm_intel, tap, vhost_net
  # Allow this container to create containers and virtual machines
  security.nesting: "true"
description: Profile for incus-charm GitHub runners
devices:
  # Basic devices, the actual network and storage pool will depend on the Incus deployment
  eth0:
    name: eth0
    network: incusbr0
    type: nic
  root:
    path: /
    pool: default
    type: disk
  # Extra devices required to enable nested virtualization
  kvm:
    source: /dev/kvm
    type: unix-char
  vhost-net:
    source: /dev/vhost-net
    type: unix-char
  vhost-sock:
    source: /dev/vhost-vsock
    type: unix-char
  vsock:
    source: /dev/vsock
    type: unix-char
```

### Dependencies

The CI workflows are responsible for installing any necessary dependencies required for their execution. This approach keeps the base runner image minimal and ensures that dependencies are explicitly managed within each workflow.
