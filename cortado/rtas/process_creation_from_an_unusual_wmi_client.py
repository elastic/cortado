# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="c065d4a4-3128-449d-91e4-23adeb6d789c",
    name="process_creation_from_an_unusual_wmi_client",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="2cbb7988-4fea-4242-a0c0-25f4dd068946", name="Process Creation from an Unusual WMI Client")
    ],
    techniques=["T1047"],
    sample_hash="fea10c485839f80cc78106c2ef1d4a3ef70a5a0c208586be219a070bca061d6c",
)
