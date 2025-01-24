# Ceph integration

The Incus charm can be integrated with the [ceph-mon charm](https://charmhub.io/ceph-mon) to configure and create a Ceph storage pool in Incus.

Assuming that a `ceph-mon` application is available on the current model, integrating it with an `incus` application can be done via `juju relate`:

```shell
$ juju relate incus ceph-mon
```

After the relation is setup, the Incus charm will fetch the endpoints and keyring from the ceph-mon charm, request the creation of a new OSD pool and create an Incus storage pool consuming the newly created OSD pool.
