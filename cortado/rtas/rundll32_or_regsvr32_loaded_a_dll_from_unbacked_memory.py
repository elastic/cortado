# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="ee850735-544f-4d59-bd8b-f355033144f0",
    name="rundll32_or_regsvr32_loaded_a_dll_from_unbacked_memory",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="226df8a0-6ef8-4965-91b4-7ce64078c206", name="Rundll32 or Regsvr32 Loaded a DLL from Unbacked Memory")
    ],
    techniques=['T1055', 'T1218', 'T1218.011', 'T1218.010'],
    sample_hash="09bc480835114679224d2e98980a85e2f67ab99a682b3a27f45f9ee520ea3b6b",
)
