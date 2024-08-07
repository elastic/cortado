# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="9e85eb9f-ee9e-4c73-8a83-14dd29a5aa80",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        {
            "rule_name": "Connection to Dynamic DNS Provider by an Unsigned Binary",
            "rule_id": "75b80e66-90d0-4ab6-9e6b-976f7d690906",
        }
    ],
    siem_rules=[],
    techniques=["T1071"],
)

EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    posh = "C:\\Users\\Public\\posh.exe"
    _common.copy_file(EXE_FILE, posh)

    # Execute command
    _common.log("Using PowerShell to connect to a DDNS provider website")
    _common.execute([posh, "/c", "iwr", "https://www.noip.com", "-UseBasicParsing"], timeout=10)
    _common.remove_file(posh)


if __name__ == "__main__":
    exit(main())
