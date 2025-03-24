# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="9c5b7e6f-9053-44a3-ab28-36409845bdec",
    name="netsupport_execution_form_unusual_path",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="f36c407e-27c1-4682-a322-73dd0cddf29d", name="NetSupport Execution form unusual Path")
    ],
    techniques=['T1219'],
    sample_hash="8967c17e9f455d2af6b0c65817851bc03b1389bfaa92f566728de2d2a562f58a",
)
