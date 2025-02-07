# Getting started

To get started with the charm, we'll perform a simple deployment with no integrations. This is as simple as just deploying the charm directly.

```shell
$ juju deploy incus --constraints="mem=4G virt-type=virtual-machine"
```

In this guide, we assume that a LXD cloud is being used by Juju to provision machines, so we add some extra constraints. If you're using a different cloud, you'll probably want to adjust your constraints as needed.

After the unit reaches an active state, we can then get access to the Incus server via our local `incus` CLI. For instructions on how to install the `incus` command, refer to the [Incus documentation](https://linuxcontainers.org/incus/docs/main/installing/).

To get access to the Incus server, we first need to create a new trusted client token. To generate the token, run the `add-trusted-client` action on the deployed unit:

```shell
$ juju run incus/leader add-trusted-client name=my-client
```

Then, we use the returned token to add the remote to our local client.

```shell
$ incus remote add incus-juju <token>
```

Now, we should be able to list all remotes and switch to our new `incus-juju` remote.

```shell
$ incus remote list
$ incus remote switch incus-juju
```

Now we have access to our fully functional Incus server. For instructions on using Incus itself, refer to [the official documentation](https://linuxcontainers.org/incus/docs/main/).
