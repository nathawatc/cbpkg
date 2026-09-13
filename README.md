# Codeberg Package

Rust tool for building optimized Arch Linux packages and publishing to Codeberg
Packages.

## Features

- Build `PKGBUILD`s with `generic`, `v3`, `v4`, `native`, or all profiles.
- Use CachyOS-derived C/C++, linker, Rust, Go, compression, and makepkg policy.
- Ignore host compiler/linker/makepkg override variables.
- Validate x86-64 psABI support on the build host before running v3/v4 builds.
- Reject optimized packages that are incorrectly labeled as baseline `x86_64`.
- Inspect `.PKGINFO` after every build before accepting the artifact.
- Use `run0` for makepkg package-manager privilege escalation via `PACMAN_AUTH=(run0)`.
- Publish packages to Codeberg Packages over HTTPS with HTTP Basic authentication.
- Store one credential per Codeberg host in the Linux D-Bus Secret Service.
- Build and validate every selected profile before starting deferred uploads.

## Requirements

Runtime requirements:

- `makepkg`
- `run0` when dependency installation through `makepkg --syncdeps` is enabled
- the tools and build dependencies required by the target `PKGBUILD`

For Codeberg authentication, a Linux D-Bus Secret Service is also required.

To build `cbpkg` itself, install a current Rust toolchain with Cargo.

## Installation

Build and install from the repository:

```sh
cargo install --path .
```

Or build a release binary without installing it:

```sh
cargo build --release
```

The binary will be written to:

```text
target/release/cbpkg
```

## Quick start

Run `cbpkg` from the directory containing the `PKGBUILD` you want to build.

Build a baseline x86-64 package:

```sh
cbpkg build --profile generic
```

Build for x86-64-v3:

```sh
cbpkg build --profile v3
```

Build every supported profile:

```sh
cbpkg build --profile all
```

If `--profile` is omitted, `cbpkg` opens an interactive profile picker.

## Build profiles

| Profile   | C/C++ target                                    | Rust target CPU | Go                          | Package arch    | Codeberg group |
| --------- | ----------------------------------------------- | --------------- | --------------------------- | --------------- | -------------- |
| `generic` | `x86-64`, generic tuning                        | `x86-64`        | unchanged                   | `x86_64`        | `x86-64`       |
| `v3`      | `x86-64-v3`, generic tuning, CachyOS `-mpclmul` | `x86-64-v3`     | `GOAMD64=v3`                | `x86_64_v3`     | `x86-64-v3`    |
| `v4`      | `x86-64-v4`, generic tuning, CachyOS `-mpclmul` | `x86-64-v4`     | `GOAMD64=v4`                | `x86_64_v4`     | `x86-64-v4`    |
| `native`  | `-march=native -mtune=native`                   | `native`        | highest detected host level | `x86_64_native` | `native`       |

Packages with `arch=('any')` are accepted for every profile.

Before a v3 or v4 build starts, `cbpkg` checks the host CPU and OS-managed
extended state required by the corresponding x86-64 psABI level. The CachyOS
v3/v4 policy also requires PCLMUL on the build host.

## Build behavior

By default, `cbpkg build` invokes `makepkg` with the equivalent of:

```text
--syncdeps --clean --cleanbuild --force
```

Use the opt-out flags when needed:

```text
--no-syncdeps
--no-clean
--no-cleanbuild
--no-force
```

Pass `--noconfirm` to forward `--noconfirm` to `makepkg`.

For example:

```sh
cbpkg build --profile native --no-cleanbuild
```

`cbpkg` first asks `makepkg --packagelist` for the expected outputs, validates
their architecture labels, runs the build, then reads `.PKGINFO` from each
resulting package archive and validates the final `arch` value.

Optimized profiles are not allowed to publish a package labeled as baseline
`x86_64`. A package must use the profile-specific architecture or `any`.

## Isolated makepkg policy

`cbpkg` does not replace `makepkg` and does not execute a `PKGBUILD` itself. It
orchestrates the system `makepkg` process using generated temporary
configuration files.

The generated policy is based on pinned CachyOS `docker-makepkg` configuration
and includes profile-specific compiler and Rust flags. `cbpkg` intentionally
overrides the package-manager authorization command with:

```sh
PACMAN_AUTH=(run0)
```

This is build-policy isolation, not a container or chroot. The package is still
built on the current host and uses the normal Arch package build environment.

## Authentication

Log in before using `--upload`:

```sh
cbpkg auth login
```

You can provide the username directly:

```sh
cbpkg auth login --username alice
```

Check the stored credential without retrieving the secret token:

```sh
cbpkg auth status
```

Remove it with:

```sh
cbpkg auth logout
```

Only one `cbpkg` credential is allowed per normalized host. To change the stored
username or token, log out first and then log in again.

A different Codeberg-compatible host can be selected with `--host` or `CODEBERG_HOST`:

```sh
cbpkg auth login --host codeberg.example
```

Authentication and package uploads require HTTPS.

## Uploading packages

Build and upload one profile:

```sh
cbpkg build --profile v3 --upload
```

Build and upload every profile:

```sh
cbpkg build --profile all --upload
```

If `--owner` is omitted, the stored credential username is used as the Codeberg
package owner. Override the destination namespace with:

```sh
cbpkg build --profile v3 --upload --owner my-namespace
```

## Environment variables

| Variable         | Purpose                                             |
| ---------------- | --------------------------------------------------- |
| `CODEBERG_HOST`  | Default Codeberg host for auth and build commands   |
| `CODEBERG_OWNER` | Default package owner / namespace for `cbpkg build` |

Build-policy variables such as `CFLAGS`, `RUSTFLAGS`, `GOAMD64`, `CARCH`,
`MAKEPKG_CONF`, `PACMAN_AUTH`, and related makepkg overrides are deliberately
sanitized for child `makepkg` processes.
