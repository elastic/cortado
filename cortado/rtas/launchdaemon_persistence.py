# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="762adc57-58c2-413d-a98d-258a223c07da",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        {
            "rule_name": "LaunchDaemon Creation or Modification and Immediate Loading",
            "rule_id": "9d19ece6-c20e-481a-90c5-ccca596537de",
        }
    ],
    techniques=["T1543"],
)
def main():
    masquerade = "/tmp/launchctl"
    _common.create_macos_masquerade(masquerade)

    payload_file = "/Library/LaunchDaemons/test.payload"
    _common.temporary_file_helper("testing", file_name=payload_file)

    # Execute command
    _common.log("Launching fake launchctl command to mimic LaunchDaemons payload persistence")
    _common.execute([masquerade, "load"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


