# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="1728887a-c3f0-42d0-b590-b175341caab7",
    name="potential_windows_script_evasion_via_sleep",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="30203e6b-0f9e-410a-a34d-6fe037866cca", name="Potential Windows Script Evasion via Sleep")
    ],
    techniques=['T1059', 'T1059.005', 'T1059.007'],
    sample_hash="5a049c1a40bd41636bd3602019154e333fa83db601f862c7f370fb06b21db561",
)
