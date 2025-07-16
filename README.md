[![crates.io](https://img.shields.io/crates/v/gnoci?style=flat-square&logo=rust)](https://crates.io/crates/gnoci)
[![Build Status](https://github.com/tofay/gnoci/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tofay/gnoci/actions/workflows/ci.yml?query=branch%3Amain)
[![Documentation](https://docs.rs/gnoci/badge.svg)](https://docs.rs/gnoci/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Coverage Status (codecov.io)](https://codecov.io/gh/tofay/gnoci/branch/main/graph/badge.svg)](https://codecov.io/gh/tofay/gnoci/)

# gnoci

**gnoci** is a command-line tool for building auditable OCI container images from a simple TOML configuration file.

## Features

**Small** - Images only contain the specified binaries and their dynamic library dependencies, resulting in minimal image sizes.

**Auditable** - Includes sufficient OS metadata for scanning tools like [Trivy](https://github.com/aquasecurity/trivy) and [Syft](https://github.com/anchore/syft) to determine what OS packages the files came from (Debian/RPM-based distros only).

**Fast** - No Docker or container runtime required. Builds images directly on the host filesystem.

## Usage

```sh
$ gnoci --help
Small OCI image builder

Usage: gnoci [OPTIONS] <PATH>

Arguments:
  <PATH>  Output OCI image directory path

Options:
  -t, --tag <TAG>      Optional tag for the image
  -f, --file <FILE>    Config file [default: gnoci.toml]
      --label <LABEL>  Labels to apply to the image, as KEY=VALUE strings
  -h, --help           Print help
  -V, --version        Print version
```

### Example

```sh
gnoci -t v1 -f custom.toml ./output-dir
```

This builds an OCI image using `custom.toml` and writes it to the OCI image directory (which is created if it doesn't exist) `./output-dir` with the tag `v1`.

## Configuration

The config file (default: `gnoci.toml`) is written in TOML and supports the following structure:

```toml
# gnoci.toml
# Image configuration fields
cmd = ["/usr/bin/myapp"]
# ...other OCI image configuration fields... 

# Entries can be files or directories
# Symlinks are resolved.
[[entries]]
source = "bin/myapp"
target = "/usr/bin/myapp"
mode = 0o755       # optional
uid = 1001         # optional
gid = 1001         # optional
```

### Scanning tool integration

When building an image on an RPM-based distro, **gnoci** will automatically generate an RPM manifest at  
`/var/lib/rpmmanifest/container-manifest-2` inside the image layer (if `rpm` is available on the host).  
This will list any packages that own files included in the image.  
This enables vulnerability and package scanning with tools like [Trivy](https://github.com/aquasecurity/trivy) and [Syft](https://github.com/anchore/syft), which can detect and report installed RPM packages based on this manifest.

For debian based distros, dpkg status files are created for any packages whose files were included in the image.

For both debian and RPM based builds, any license files from the detected packages are also included in the images.
