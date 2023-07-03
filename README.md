# syscalls-bumper

[![Falco Infra Repository](https://github.com/falcosecurity/evolution/blob/main/repos/badges/falco-infra-blue.svg)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#infra-scope) [![Incubating](https://img.shields.io/badge/status-incubating-orange?style=for-the-badge)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#incubating) [![License](https://img.shields.io/github/license/falcosecurity/syscalls-bumper?style=for-the-badge)](./LICENSE)

[![CI Build](https://github.com/falcosecurity/syscalls-bumper/actions/workflows/ci.yml/badge.svg)](https://github.com/falcosecurity/syscalls-bumper/actions/workflows/ci.yml)
[![Latest](https://img.shields.io/github/v/release/falcosecurity/syscalls-bumper?style=flat)](https://github.com/falcosecurity/syscalls-bumper/releases/latest)
![Architectures](https://img.shields.io/badge/ARCHS-x86__64|aarch64|s390x|riscv64-blueviolet?style=flat)

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
