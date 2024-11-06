# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="58faa99c-d9ca-4603-9e11-b696139f8d72",
    name="network_file_unzipped_via_unsigned_or_untrusted_binary",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="28611239-08e6-47d5-a88b-76136670788c",
            name="Network file unzipped via Unsigned or Untrusted binary",
        )
    ],
    techniques=["T1027", "T1140", "T1059"],
    sample_hash="122877b338ec943ac0b33dcedc973aab6db48dd93cd30263255a7e7351ee60e6",
)
