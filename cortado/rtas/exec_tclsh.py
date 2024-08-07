# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="9332cece-38b7-49e1-9f8d-e879913ffdfb",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="ac1eaed8-2aee-48d7-9824-2be1f00eda0e", name="Tclsh execution followed by immediate network connection"
        )
    ],
    siem_rules=[],
    techniques=["T1059"],
)
def main():
    masquerade = "/tmp/tclsh"
    _common.copy_file("/usr/bin/curl", masquerade)

    _common.log("Executing commands to mimic network activity from tclsh")
    _common.execute([masquerade, url], shell=True)
