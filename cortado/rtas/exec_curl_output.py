# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="c3be0d35-069b-4b2b-ab92-63530e8c23f7",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[{'rule_id': '336ada1c-69f8-46e8-bdd2-790c85429696', 'rule_name': 'Ingress Tool Transfer via CURL'}],
    siem_rules=[],
    techniques=[""],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    curl = "C:\\Users\\Public\\curl.exe"
    _common.copy_file(EXE_FILE, curl)

    # Execute command
    _common.execute([curl, "-o"], timeout=10, kill=True)

    _common.remove_file(curl)


if __name__ == "__main__":
    exit(main())
