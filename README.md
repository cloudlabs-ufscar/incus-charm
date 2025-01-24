# Incus charm

Incus is a modern, secure and powerful system container and virtual machine manager. This [Juju](https://juju.is/) charm provides a way to deploy and operate Incus in one or more servers, handling cluster formation and day 2 operations.

The charm also enables integration of Incus with network and storage providers such as Ceph and OVN, as well as with Vault for cluster-wide certificate management.

## Features

- Automatic cluster formation
- Actions for cluster management such as evacuating and restoring nodes
- Actions for generating client trust tokens and adding client certificates
- [Failure domains](https://linuxcontainers.org/incus/docs/main/explanation/clustering/#failure-domains) can be automatically configured using [Juju availability zones](https://juju.is/docs/juju/availability-zone)
- Integration with Vault to provide cluster-wide certificates
- Integration with OVN to provide cluster networking
- Integration with Ceph to provide storage

## Getting started

To get started with the charm, check out the [getting started docs](/docs/getting-started.md). All documentation is also available on [Charmhub](https://charmhub.io/incus).

## Contributing

Contributions are highly appreciated. Make sure to read the [contributing guide](CONTRIBUTING.md) before you get started.
