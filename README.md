# cortado
Consolidated RTAs (Red Team Automations)

The repository contains Red Team Automations (RTAs) implemented in Python. These RTAs either reference binary samples by
specifying a sample hash that exhibits behaviors we aim to detect or emulate attacker behaviors through code.

RTAs provide a simple way to verify that detection rules are generating the expected alerts.

## Table of Contents

- [Running](#running)
  - [Main CLI](#main-cli)
  - [RTA CLI](#rta-cli)
- [Development](#development)
  - [Setup](#setup)
  - [Build and deploy to VM](#build-and-deploy-to-vm)

## Running

Cortado registers the script endpoints (defined in `pyproject.toml`) that become available in the environment after
installation with `poetry`.

### Main CLI

The package defines `cortado` entry point as a main CLI command for `cortado` package:

```bash
$ cortado --help

 Usage: cortado [OPTIONS] COMMAND [ARGS]...

╭─ Options ─────────────────────────────────────────────────────────────────────╮
│ --verbose               --no-verbose           [default: no-verbose]          │
│ --logs-as-json          --no-logs-as-json      [default: no-logs-as-json]     │
│ --install-completion                           Install completion for the     │
│                                                current shell.                 │
│ --show-completion                              Show completion for the        │
│                                                current shell, to copy it or   │
│                                                customize the installation.    │
│ --help                                         Show this message and exit.    │
╰───────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ────────────────────────────────────────────────────────────────────╮
│ get-coverage   Calculate RTA coverage for the rules with paths that match     │
│                provided glob                                                  │
│ print-rtas     Print information about all available RTAs                     │
╰───────────────────────────────────────────────────────────────────────────────╯
```

This script requires `utils` extra dependencies to be installed.

### RTA CLI

RTA CLI are used to execute RTAs in a sandboxed environment with minimal dependencies.

- `cortado-run-rta` -- a command to execute a particular RTA
- `cortado-run-rtas` -- a command to execute all RTAs that match the current OS

These scripts run without any external dependencies.

## Development

### Setup

Make sure you have `poetry` installed and run the following command:

```bash
poetry install --with dev --all-extras
```

This will install full set of dependencies needed to run orchestration code and develop `cortado`.

### Build and deploy to VM

Cortado is deployed as a Python wheel package. To build a Cortado wheel, run `poetry build` command:

```bash
$ poetry build -f wheel
Building cortado (0.1.0)
  - Building wheel
  - Built cortado-0.1.0-py3-none-any.whl
```

`cortado-0.1.0-py3-none-any.whl` file is a python wheel that can be delivered to a VM and installed with `pip`:

```bash
$ pip install ./cortado-0.1.0-py3-none-any.whl
Processing ./cortado-0.1.0-py3-none-any.whl
Installing collected packages: cortado
Successfully installed cortado-0.1.0
$
```

Note that the wheel does not contain any dependencies and will not install any dependencies needed for the orchestration
code to run. It's main purpose it to deliver and run RTAs.

## How to contribute

We welcome contributions to Cortado! Before contributing, please first familiarize yourself with this repository. When
you're ready to contribute, read the [contribution guide](CONTRIBUTING.md) to learn how to prepare the pull request for
a review.

## Licensing

Everything in this repository — code, RTAs, etc. — is licensed under the [Elastic License v2](LICENSE.txt).

We require contributors to sign a [Contributor License Agreement](https://www.elastic.co/contributor-agreement) before
contributing code to any Elastic repositories.

## Questions? Problems? Suggestions?

- Want to know more about the Elastic Security Detection Engine? Check out the
  [overview](https://www.elastic.co/guide/en/security/current/detection-engine-overview.html) in Kibana.
