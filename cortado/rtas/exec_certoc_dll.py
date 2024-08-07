# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="b39cddfa-97ec-41c7-8d4d-7cf0d5a7ddd4",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[{
        'rule_id': '6fcbf73f-4413-4689-be33-61b0d6bd0ffc',
        'rule_name': 'Suspicious ImageLoad via Windows CertOC'
    }],
    siem_rules=[],
    techniques=[""],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    certoc = "C:\\Users\\Public\\certoc.exe"
    _common.copy_file(EXE_FILE, certoc)

    _common.execute([certoc, "-LoadDLL"], timeout=1, kill=True)
    _common.remove_file(certoc)


