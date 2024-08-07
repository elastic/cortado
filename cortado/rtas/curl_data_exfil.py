# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="aec658cc-a5df-42e8-8e09-810b484b9ef2",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        {
            "rule_name": "MacOS Potential Data Exfiltration via Curl",
            "rule_id": "192ec591-1d00-4c16-a717-8a7481038d23",
        }
    ],
    siem_rules=[],
    techniques=["T1048"],
)
def main():
    # create masquerades
    masquerade = "/tmp/curl"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake curl commands to simulate data exfil")
    _common.execute([masquerade, "-F", "*@*.zip", "http*"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


