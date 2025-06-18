# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="5e59211e-50c0-4ed6-8b78-ad58c6fa6f65",
    name="script_execution_from_webdav",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="4bdd5646-f7b2-4e1d-962d-fd0f591f8f87", name="Script Execution from WebDav")
    ],
    techniques=['T1204', 'T1204.002', 'T1021', 'T1021.002'],
    sample_hash="eff23a6a6760f74a437cd5cca64bdf97d929b0c3bd50e7ba66a2c5e7a183bf87",
)
