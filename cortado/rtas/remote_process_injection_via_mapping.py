
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="8ea44fd6-2419-4f96-ad52-f0ff3078e850",
    name="remote_process_injection_via_mapping",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="95c534ee-1a49-4a35-bea2-2853f2737a17", name="Remote Process Injection via Mapping")
    ],
    techniques=['T1055'],
    sample_hash="38bc81b03cadb8769accfb9f84adc4638d2173153cbab047ec4d6cc7d27b3ebf",
)
