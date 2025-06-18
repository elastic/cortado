# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="a2047077-2333-4a2d-8d22-49768c8ae12a",
    name="windows_defender_exclusions_via_wmi",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="73310ee3-5e48-4680-b7c5-c096813c7f03", name="Windows Defender Exclusions via WMI")
    ],
    techniques=['T1562', 'T1562.001', 'T1047'],
    sample_hash="a8ad0cb7c6c4d332bc50ca8af649af8877555a79e0d4d1df3cad1ea68acd26fb",
)
