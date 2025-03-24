
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="7cca0cc4-85e0-4505-ab9c-d84550520e14",
    name="potential_injection_via_asynchronous_procedure_call",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="2316b571-731d-4745-97ac-4fd6922d32df", name="Potential Injection via Asynchronous Procedure Call")
    ],
    techniques=['T1055'],
    sample_hash="84499164a4848a100a22361f38d36ddaea66d01d2e68580271692f9a6fc2a570",
)
