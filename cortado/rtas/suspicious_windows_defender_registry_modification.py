
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="adec29bb-8caf-465b-934d-c62bbf46b195",
    name="suspicious_windows_defender_registry_modification",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="56751d32-cded-41ad-a273-e6860820c4c3", name="Suspicious Windows Defender Registry Modification")
    ],
    techniques=['T1562', 'T1562.001', 'T1112'],
    sample_hash="0ad4c1b5018e8b639a26c8eca1415dffcd4f828fa82a65bf90955f1925831f64",
)
