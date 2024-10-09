# cortado
Consolidated RTAs


## Install for development

Make sure you have `poetry` installed and run the following command:

```bash
poetry install --with dev --all-extras
```

This will install full set of dependencies needed to run orchestration code and develop `cortado`.


## Run

Cortado registered script endpoints (defined in `pyproject.toml`) that become available in the environment after
installation with `poetry`

### Running orchestration code


The package defines `cortado` entry point as a main CLI command for `cortado` package:

```bash
$ cortado --help

 Usage: cortado [OPTIONS] COMMAND [ARGS]...

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────╮
│ --verbose               --no-verbose           [default: no-verbose]                             │
│ --logs-as-json          --no-logs-as-json      [default: no-logs-as-json]                        │
│ --install-completion                           Install completion for the current shell.         │
│ --show-completion                              Show completion for the current shell, to copy it │
│                                                or customize the installation.                    │
│ --help                                         Show this message and exit.                       │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ───────────────────────────────────────────────────────────────────────────────────────╮
│ generate-mapping   Generate a mapping file that contains rule to RTA relations.                  │
│ get-coverage       Calculate RTA coverage for the rules with paths that match provided glob      │
│ print-rtas         Print information about all available RTAs                                    │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
```

This script requires `utils` extra dependencies to be installed.

### Running RTAs

- `cortado-run-rta` -- a command to execute a particular RTA
- `cortado-run-rtas` -- a command to execute all RTAs that match the current OS

These scripts run without any external dependencies.
