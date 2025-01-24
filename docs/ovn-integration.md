# OVN integration

The Incus charm can be integrated with the [ovn-central charm](https://charmhub.io/ovn-central) to configure an OVN Northbound connection in Incus.

Note that the ovn-central charm requires authentication via SSL certificates signed by a common CA. Therefore, OVN integration requires the [Vault integration](/docs/vault-integration.md) to be setup for both Incus and the ovn-central charms.

Assuming that a `ovn-central` application is available on the current model, integrating it with an `incus` application can be done via `juju relate`:

```shell
$ juju relate incus ovn-central
```

After the relationship is setup, the Incus charm will fetch the OVN Northbound database endpoints from the ovn-central charm and configure them in Incus. This enables the creation of OVN networks in Incus that allow a common virtual network to be used by instances across cluster members. Automatic creation of OVN networks by the charm is currently not supported.
