# Contributing

Contributions are highly appreciated. You can contribute by opening a new issue with a bug report or by opening a new pull request with a fix, feature or enhancement.

## Code of Conduct

When contributing, you must adhere to the project's [Code of Conduct](/CODE_OF_CONDUCT.md).

## License and copyright

By default, any contribution to this project is made under the Apache 2.0 license.

The author of a change remains the copyright holder of their code (no copyright assignment).

## Pull requests

### Commit structure

The commits of this project follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) format. This makes it easier to automate releases and improves readability of the git log in general. When making creating a commit, make sure to append `feat:`, `fix:`, `chore:` or any other type as you see fit specifying the nature of the commit.

### Developer Certificate of Origin

The project uses DCO as a way to track contributions. This means that all individual commits to the project must contain a Signed-off-by line. This can be done by using the `-s | --signoff` flag to the `git commit` command, like so: `git commit -s`.

The Developer Certificate of Origin (DCO) is a lightweight way for contributors to certify that they wrote or otherwise have the right to submit the code they are contributing to the project.

The full text of the DCO is provided below:

> Developer Certificate of Origin
> Version 1.1
>
> Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
>
> Everyone is permitted to copy and distribute verbatim copies of this
> license document, but changing it is not allowed.
>
>
> Developer's Certificate of Origin 1.1
>
> By making a contribution to this project, I certify that:
>
> (a) The contribution was created in whole or in part by me and I
>     have the right to submit it under the open source license
>     indicated in the file; or
>
> (b) The contribution is based upon previous work that, to the best
>     of my knowledge, is covered under an appropriate open source
>     license and I have the right under that license to submit that
>     work with modifications, whether created in whole or in part
>     by me, under the same open source license (unless I am
>     permitted to submit under a different license), as indicated
>     in the file; or
>
> (c) The contribution was provided directly to me by some other
>     person who certified (a), (b) or (c) and I have not modified
>     it.
>
> (d) I understand and agree that this project and the contribution
>     are public and that a record of the contribution (including all
>     personal information I submit with it, including my sign-off) is
>     maintained indefinitely and may be redistributed consistent with
>     this project or the open source license(s) involved.

## Local development

To make contributions to this charm, you'll need a working [development setup](https://canonical-juju.readthedocs-hosted.com/en/latest/user/howto/manage-your-deployment/manage-your-deployment-environment/). If you're using [nix](https://nixos.org/), a `shell.nix` is provided with all system development dependencies.

The Python dependencies are also needed for local development. You can create a Python virtual environment with all dependencies needed for development with `tox`:

```shell
tox devenv -e integration
source venv/bin/activate
```

### Testing

This project uses `tox` for managing test environments. There are some pre-configured environments that can be used for linting and formatting code when you're preparing contributions to the charm:

```shell
tox run -e format        # update your code according to linting rules
tox run -e lint          # code style
tox run -e static        # static type checking
tox run -e unit          # unit tests
tox run -e integration   # integration tests
tox                      # runs 'format', 'lint', 'static', and 'unit' environments
```

As a rule of thumb, we try to abuse unit tests as much as possible while keeping integration tests to the bare minimum needed to validate E2E functionality. Although very valuable for testing integration with the underlying services, integration tests are quite expensive in both time to execute and to maintain. They are also inherently flaky and can fail for a variety of external factors. With that in mind, we usually test just the happy path on integration tests, leaving edge cases and other paths for units tests.

### Build the charm

Build the charm using:

```shell
charmcraft pack
```

### Refresh

If you already have an existing Juju model and just want to update the charm version for quick iteration, you can do a refresh:

```shell
juju refresh <incus-application-name> --path=<packed-charm-path>
```
