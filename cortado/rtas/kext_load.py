# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="c4ac8740-3dca-4550-831b-e03d21de581d",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        {
            "rule_name": "New System Kext File and Immediate Load via KextLoad",
            "rule_id": "de869aa1-c63a-451e-a953-7069ec39ba60",
        }
    ],
    siem_rules=[],
    techniques=["T1547", "T1547.006", "T1059", "T1059.004"],
)
def main():
    # create masquerades
    masquerade = "/tmp/mv"
    _common.create_macos_masquerade(masquerade)

    # Execute command"
    _common.log("Launching fake commands load Kext file.")
    _common.execute([masquerade, "/System/Library/Extensions/*.kext"], timeout=10, kill=True)
    _common.execute(["kextload", "test.kext"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


