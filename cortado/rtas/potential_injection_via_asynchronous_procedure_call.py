# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="009e8ec8-6a9e-4449-9fa5-8961907b636e",
    name="potential_injection_via_asynchronous_procedure_call",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="2316b571-731d-4745-97ac-4fd6922d32df", name="Potential Injection via Asynchronous Procedure Call")
    ],
    techniques=['T1055'],
    sample_hash="94827a4ab543972eacee8e610ec94d8469de43fe8dc0302015f1c587b158025d",
)
