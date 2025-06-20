# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="7e5e28fc-b112-47f0-92d2-0a5c54c5cf03",
    name="suspicious_api_from_an_unsigned_service_dll",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="1a16b12e-6719-4f58-8835-84880092f3a0", name="Suspicious API from an Unsigned Service DLL")
    ],
    techniques=['T1543', 'T1543.003'],
    sample_hash="caaff622a1f527db9d3d05f83ae343351bd4c0214ca2de705397154c48435480",
)
