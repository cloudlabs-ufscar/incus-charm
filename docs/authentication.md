# Authentication

Incus supports two methods of authentication to its remote API: TLS client certificates and Open ID Connect. Integrating with an OIDC provider is currently not supported by the charm, and therefore is out of the scope of this document. As such, we'll focus on the mechanisms that the charm provides for managing authentication based on TLS client certificates.

For a comprehensive guide on all authentication methods, check the [Incus documentation](https://linuxcontainers.org/incus/docs/main/authentication/#authentication).

## Adding a trusted client

A new trusted client can be added by using the `add-trusted-client`. This action creates a new trust token in Incus and returns it for the operator. The token can then be used when adding the new remote server on via the client CLI. This method is usually the preferred way to get access to Incus as a user.

To generate the token, run the `add-trusted-client` action on any unit. In this example we choose the leader unit.

```shell
$ juju run incus/leader add-trusted-client name=my-client
```

Then, we use the returned token to add the remote to our local client.

```shell
$ incus remote add incus-juju <token>
```

The `incus remote add` command will automatically create the remote and add the client certificate present in `~/.config/incus/client.crt` to Incus's trust store using the token. For a full overview of the process, check out the [Incus documentation](https://linuxcontainers.org/incus/docs/main/authentication/#adding-client-certificates-using-tokens).

After that, we should now be able to see our remote with `incus remote ls` and switch to it with `incus remote switch incus-juju`.

## Adding a trusted certificate

Incus supports adding client certificates to its trust store. The charm exposes this functionality via the `add-trusted-certificate` action. The certificate type can be either `client` or `metrics`, depending on the purpose of the client. This method is usually the preferred way to get access to Incus as a service or a user that already has the remote configured locally.

It is important to note that the action expects the certificate **content**, and **not its path**. Supposing that we have a `client.crt` file containing a PEM-encoded X509 certificate that we wish to add as a trusted certificate on Incus, this could be done by running the following command:

```shell
$ juju run incus/leader add-trusted-certificate cert="$(cat client.crt)"
```

For more information about adding trusted certificates to Incus, refer to the [Incus documentation](https://linuxcontainers.org/incus/docs/main/authentication/#adding-trusted-certificates-to-the-server).

## TLS certificate authentication with PKI certificates

When the certificates for the Incus server are signed by an external CA, all client certificates must also be signed by that CA. Because of this, when the charm is [integrated with Vault](/docs/vault-integration.md), we need to generate client client certificates signed by it and then add those into the Incus trust store using the same methods describe in [Adding a trusted client](#adding-a-trusted-client) or [Adding a trusted certificate](#adding-a-trusted-certificate).

To generate a certificate and key pair using Vault, we can use the `generate-certificate` action from the Vault charm:

```shell
$ juju run vault/leader generate-certificate common-name=my-client sans=""
```

We then need to copy the generated certificate and key to the desired path on the system. If we intend to use those certificates for authentication via the CLI, the certificate and key should be copied to `~/.config/incus/client.crt` and `~/.config/incus/client.key`, making sure to fix the formatting from the action's output.

With the certificate setup on the client side, we can now add them the Incus trust store as described in [Adding a trusted client](#adding-a-trusted-client) or [Adding a trusted certificate](#adding-a-trusted-certificate). For more information about authentication when using a PKI system, refer to [the Incus documentation](https://linuxcontainers.org/incus/docs/main/authentication/#using-a-pki-system).
