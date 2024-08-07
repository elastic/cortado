# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="46f6ae71-2fd8-46bd-8209-9fc0f59432ef",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[{'rule_id': 'c4210e1c-64f2-4f48-b67e-b5a8ffe3aa14', 'rule_name': 'Mounting Hidden or WebDav Remote Shares'}],
    techniques=['T1021', 'T1021.002', 'T1078', 'T1078.003'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    net = "C:\\Users\\Public\\net.exe"
    _common.copy_file(EXE_FILE, net)

    # Execute command
    _common.execute([net, "/c", "echo", "use", "http"], timeout=10)
    _common.remove_file(net)


