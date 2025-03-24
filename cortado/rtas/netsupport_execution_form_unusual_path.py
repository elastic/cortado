
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="5a54e164-4516-4af9-9c8b-009ed0759946",
    name="netsupport_execution_form_unusual_path",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="f36c407e-27c1-4682-a322-73dd0cddf29d", name="NetSupport Execution form unusual Path")
    ],
    techniques=['T1219'],
    sample_hash="57d92ae16c8766995a28d8a6b9f579739324d9e090bea1ed0ed99a4ea8564933",
)
