# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from cortado.rtas import load_all_modules, get_registry


def test_load_all_modules():
    # All RTA modules must be imported without issues
    load_all_modules()

    registry = get_registry()

    # Continuously changing number of RTAs
    # Please make sure that the change corresponds with the number of new RTAs added
    assert len(registry) == 590
