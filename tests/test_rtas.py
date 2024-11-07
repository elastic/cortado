# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path

from cortado.rtas import get_registry, load_all_modules


def test_load_all_modules():
    # All RTA modules must be imported without issues
    load_all_modules()

    registry = get_registry()

    # NOTE: we assime here that 1 RTA == 1 file in `cortado/rtas` folder, which might not be always correct
    rtas_directory_path = Path("cortado/rtas")
    rta_files_found_gen = rtas_directory_path.glob("[!_]*.py")
    rta_files_found_count = sum(1 for _ in rta_files_found_gen)

    assert len(registry) == rta_files_found_count
