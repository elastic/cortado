
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="3178b53c-d91d-45dd-b7d6-a1da98595190",
    name="potential_dll_hollowing_with_transactional_ntfs",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="7f61cf66-1363-4b2a-8f82-73cc2bd46b17", name="Potential DLL Hollowing with Transactional NTFS")
    ],
    techniques=['T1055'],
    sample_hash="e7fa4f8df8fa95adffb3b0a08d091dd26830c17ef4cceed95f33ec087fbcf0ce",
)
