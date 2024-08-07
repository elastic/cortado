# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="5faf9f55-c52e-41e0-8195-b183aba8b876",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[{
        'rule_id': 'c25e9c87-95e1-4368-bfab-9fd34cf867ec',
        'rule_name': 'Microsoft IIS Connection Strings Decryption'
    }],
    techniques=['T1003'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    aspnet_regiis = "C:\\Users\\Public\\aspnet_regiis.exe"
    _common.copy_file(EXE_FILE, aspnet_regiis)

    # Execute command
    _common.execute([aspnet_regiis, "/c", "echo", "connectionStrings", "-pdf"], timeout=10)
    _common.remove_file(aspnet_regiis)


if __name__ == "__main__":
    exit(main())
