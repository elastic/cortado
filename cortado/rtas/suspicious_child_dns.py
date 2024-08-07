# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="9f58f9e7-a0f5-48e6-a924-d437fd626195",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        {'rule_id': '8c37dc0e-e3ac-4c97-8aa0-cf6a9122de45', 'rule_name': 'Unusual Child Process of dns.exe'},
        {'rule_id': 'c7ce36c0-32ff-4f9a-bfc2-dcb242bf99f9', 'rule_name': 'Unusual File Modification by dns.exe'}
    ],
    techniques=['T1133'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    dns = "C:\\Users\\Public\\dns.exe"
    _common.copy_file(EXE_FILE, dns)

    _common.execute([dns, "/c", EXE_FILE, "echo AAAAAA | Out-File a.txt"], timeout=5, kill=True)
    _common.remove_files(dns)


if __name__ == "__main__":
    exit(main())
