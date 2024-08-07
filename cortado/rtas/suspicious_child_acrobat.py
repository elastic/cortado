# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="d62cd5fb-0e8f-4f20-9477-b8622772ed16",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[{'rule_id': '53a26770-9cbd-40c5-8b57-61d01a325e14', 'rule_name': 'Suspicious PDF Reader Child Process'}],
    techniques=['T1204'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    acrobat = "C:\\Users\\Public\\Acrobat.exe"
    arp = "C:\\Windows\\System32\\arp.exe"
    _common.copy_file(EXE_FILE, acrobat)

    # Execute command
    _common.execute([acrobat, "/c", arp], timeout=2, kill=True)
    _common.remove_file(acrobat)


if __name__ == "__main__":
    exit(main())
