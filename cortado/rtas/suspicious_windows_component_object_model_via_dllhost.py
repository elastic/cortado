
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="2bfea0d2-2839-4358-b96e-294b9f4b3446",
    name="suspicious_windows_component_object_model_via_dllhost",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="f678ec9a-c348-485c-ac9e-84b0923ff5f5", name="Suspicious Windows Component Object Model via DLLHOST")
    ],
    techniques=['T1559', 'T1559.001', 'T1059', 'T1059.005', 'T1059.007', 'T1059.001', 'T1218', 'T1218.011', 'T1218.010', 'T1218.005'],
    sample_hash="66524529b7f3e73a721288b900414fe867974a9475887acc40a95275f4d0304a",
)
