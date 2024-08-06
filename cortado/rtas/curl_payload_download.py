# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import __common, register_code_rta, OSType, RuleMetadata


@register_code_rta(
    id="bf7645b2-d0cf-428d-a158-b1479160e60c",
    name="curl_payload_download",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="04d124d4-2be7-405e-b830-9494f927a51e",
            name="Payload Downloaded by Process Running in Suspicious Directory",
        )
    ],
    techniques=["T1105"],
)
def main():
    masquerade = "/tmp/testfile"
    __common.create_macos_masquerade(masquerade)

    # Execute command
    __common.log("Launching fake curl commands to download payload")
    __common.execute([masquerade, "childprocess", "curl", "portquiz.net"], timeout=5, kill=True)

    # cleanup
    __common.remove_file(masquerade)
