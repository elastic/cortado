# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="24c3ec30-36fd-4723-9371-3f7318278fa8",
    name="suspicious_windows_ldap_image_load",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="21daeeb2-fb66-432e-9ca4-92e35f2c154c", name="Suspicious Windows LDAP Image Load")
    ],
    techniques=[],
    sample_hash="534b8130a00712c5ecc8a0bfd19c89657c69d519d2fa02e889bc9ba415732cd6",
)
