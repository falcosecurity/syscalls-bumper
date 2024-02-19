# syscalls-bumper

[![Falco Infra Repository](https://github.com/falcosecurity/evolution/blob/main/repos/badges/falco-infra-blue.svg)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#infra-scope) [![Incubating](https://img.shields.io/badge/status-incubating-orange?style=for-the-badge)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#incubating) [![License](https://img.shields.io/github/license/falcosecurity/syscalls-bumper?style=for-the-badge)](./LICENSE)

[![CI Build](https://github.com/falcosecurity/syscalls-bumper/actions/workflows/ci.yml/badge.svg)](https://github.com/falcosecurity/syscalls-bumper/actions/workflows/ci.yml)
[![Latest](https://img.shields.io/github/v/release/falcosecurity/syscalls-bumper?style=flat)](https://github.com/falcosecurity/syscalls-bumper/releases/latest)
![Architectures](https://img.shields.io/badge/ARCHS-x86__64|aarch64|s390x|ppc64le|riscv64|loong64-blueviolet?style=flat)

Utility to bump supported syscalls in falcosecurity/libs

The latest release of the tool is available in [`falcosecurity/syscalls-bumper:latest`](https://hub.docker.com/r/falcosecurity/syscalls-bumper)

## Usage

```shell
syscalls-bumper -h
  Usage of syscalls-bumper
    -dry-run
      enable dry run mode
    -overwrite
      whether to overwrite existing files in libs repo if local
    -repo-root string
      falcosecurity/libs repo root (supports http too) (default "https://raw.githubusercontent.com/falcosecurity/libs/master")
    -verbose
      enable verbose logging
```

## CI Usage

To better suit the CI usage, a [Github composite action](https://docs.github.com/en/actions/creating-actions/creating-a-composite-action) has been developed.  
Therefore, running syscalls-bumper in your Github workflow is as easy as adding this step:
```
- name: Bump syscalls
  uses: falcosecurity/syscalls-bumper@main
  with:
    # Path to the libs repo.
    # No default. Mandatory.
    repo-root: 'libs'
```

> __NOTE:__ Since we don't use annotated tags, one cannot use eg: falcosecurity/syscalls-bumper@v0, but only either exact tag name, branch name or commit hash.
