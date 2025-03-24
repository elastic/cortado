
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="a33c5a52-921a-4200-8f01-4ee0b1e472ce",
    name="script_execution_from_webdav",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="4bdd5646-f7b2-4e1d-962d-fd0f591f8f87", name="Script Execution from WebDav")
    ],
    techniques=['T1204', 'T1204.002', 'T1021', 'T1021.002'],
    sample_hash="0ac574ea2c50f2305e9fca0f7b680d6b2679ea5f61f6c0a6f0ca81d719ba0b88",
)
