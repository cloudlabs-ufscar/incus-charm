# Clustering

The charm provides functionality to automatically form an [Incus cluster](https://linuxcontainers.org/incus/docs/main/explanation/clustering/) and manage the life cycle of its members.

When more than one unit is present on an application, a cluster is automatically formed. Therefore, we can create a new cluster by deploying multiple units upfront or by adding new units to an existing standalone deployment.

The state of each cluster member is displayed in the output of `juju status`. To get a more detailed view of the state of the cluster (the equivalent of running `incus cluster list`), use the `cluster-list` action:

```shell
$ juju run incus/leader cluster-list
```

The action can be executed on any unit of the application, and will yield the same result for all units.

We can also evacuate and restore cluster members via the `evacuate` and `restore` actions. For more information about evacuating and restoring members of a cluster, refer to the [Incus documentation](https://linuxcontainers.org/incus/docs/main/howto/cluster_manage/#evacuate-and-restore-cluster-members).
