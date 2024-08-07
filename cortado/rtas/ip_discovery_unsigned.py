# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="5e1ca4f9-16cc-4dd3-bfba-4bd5c7579f4a",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        {
            "rule_name": "External IP Address Discovery via Untrusted Program",
            "rule_id": "dfe28e03-9b0b-47f5-9753-65ed2666663f",
        }
    ],
    siem_rules=[],
    techniques=["T1016"],
)

EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    posh = "C:\\Users\\Public\\posh.exe"
    _common.copy_file(EXE_FILE, posh)

    # Execute command
    _common.log("Retrieving the public IP Address using ipify")
    _common.execute([posh, "/c", "iwr", "http://api.ipify.org/", "-UseBasicParsing"], timeout=10)
    _common.remove_file(posh)


