# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="59a74cc6-f57d-491d-be32-d227b2be2320",
    name="dscl_auth_validation_via_unsigned_or_untrusted_binary",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="4c0a820c-fe42-400b-8b20-57bc7d256f36", name="Dscl auth validation via Unsigned or Untrusted binary"
        )
    ],
    techniques=["T1059", "T1033"],
    sample_hash="574a0a47811b06228271c48dab1e3da889c643b90515b36bcdbdc8a48385785e",
)
