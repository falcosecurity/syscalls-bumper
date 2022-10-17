# SyscallsBumper

[![CI Build](https://github.com/FedeDP/SyscallsBumper/actions/workflows/ci.yml/badge.svg)](https://github.com/FedeDP/SyscallsBumper/actions/workflows/ci.yml)
[![Latest](https://img.shields.io/github/v/release/FedeDP/SyscallsBumper?style=for-the-badge)](https://github.com/FedeDP/SyscallsBumper/releases/latest)
![Architectures](https://img.shields.io/badge/ARCHS-x86__64%7Caarch64-blueviolet?style=for-the-badge)

Utility to bump supported syscalls in falcosecurity/libs

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
