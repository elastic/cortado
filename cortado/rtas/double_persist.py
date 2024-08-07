# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="74d0c16a-8af1-4dbb-9202-cc4b25208ea6",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        {
            "rule_name": "Untrusted Process Writing to Commonly Abused Persistence Locations",
            "rule_id": "392b0c89-1427-4601-8b32-01e8e40600a6",
        }
    ],
    siem_rules=[],
    techniques=["T1547", "T1112"],
)

EXE_FILE = _common.get_path("bin", "DoublePersist.exe")



def main():
    binary = "DoublePersist.exe"
    _common.copy_file(EXE_FILE, binary)

    _common.execute([binary])
    _common.remove_files(binary)


if __name__ == "__main__":
    exit(main())
