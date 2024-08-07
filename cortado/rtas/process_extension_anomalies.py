# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Executable with Unusual Extensions
# RTA: process_extension_anomalies.py
# ATT&CK: T1036
# Description: Creates processes with anomalous extensions

from . import _common



@register_code_rta(
    id="c7d9d63d-09ff-40e9-b990-4c273281d6a0",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[],
    techniques=[]
)


MY_APP = _common.get_path("bin", "myapp.exe")



@_common.dependencies(MY_APP)
def main():
    anomalies = [
        "bad.pif",
        "evil.cmd",
        "evil.gif",
        "bad.pdf",
        "suspicious.bat",
        "hiding.vbs",
        "evil.xlsx",
    ]

    for path in anomalies:
        _common.log("Masquerading python as %s" % path)
        _common.copy_file(MY_APP, path)
        _common.execute([path])
        _common.remove_file(path)


if __name__ == "__main__":
    exit(main())
