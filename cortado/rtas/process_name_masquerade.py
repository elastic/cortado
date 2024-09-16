# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path

from . import _common, register_code_rta, OSType, RuleMetadata

CMD_PATH = "c:\\windows\\system32\\cmd.exe"


@register_code_rta(
    id="98adf0ff-2d8e-4eea-8d68-42084204bb74",
    name="process_name_masquerade",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(id="5b00c9ba-9546-47cc-8f9f-1c1a3e95f65c", name="Potential Masquerading as SVCHOST"),
        RuleMetadata(id="b0207677-5041-470b-981d-13ab956cf5b4", name="Execution via Renamed Signed Binary Proxy"),
    ],
    techniques=["T1218", "T1036"],
)
def main():
    masquerades = ["svchost.exe", "lsass.exe"]

    for name in masquerades:
        path = Path(name).resolve()
        _common.copy_file(CMD_PATH, path)
        _common.execute(path, timeout=3, kill=True)
        _common.remove_file(path)
