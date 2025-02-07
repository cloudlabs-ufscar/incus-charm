# Vault integration

The Incus charm can be integrated with the [Vault charm](https://charmhub.io/vault?channel=1.8/stable) that will act as a PKI system to provide SSL certificates for the Incus cluster.

It is important to note that, due to compatibility with other charms such as ovn-central, the Incus charm is compatible only with the Vault charm version 1.8, and not the newer versions. For a detailed overview of the differences between versions, refer to the [vault charm documentation](https://charmhub.io/vault/docs/h-key-differences-between-vault-operator-1.15-and-1.8)

Assuming that a `vault` application is available on the current model, integrating it with an `incus` application can be done via `juju relate`:

```shell
$ juju relate incus vault
```

After the relation is setup and all units finish applying the certificates, the Incus HTTPS endpoints on all units will use the certificate issued from vault. The new certificates will also be used in the communication between cluster members and also as client certificates for [integrating with OVN](/docs/ovn-integration.md).

Note that using an PKI system for signing certificates has implications on the way Incus handles the authentication of client certificates. For more details about those implications, refer to the [the Incus documentation](https://linuxcontainers.org/incus/docs/main/authentication/#using-a-pki-system).
