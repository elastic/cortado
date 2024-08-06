# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="be6619a2-324a-443b-9f23-2dc84733c847",
    platforms=["windows"],
    endpoint_rules=[
        RuleMetadata(id="89c9c5a0-a136-41e9-8cc8-f21ef5ad894b", name="Suspicious Microsoft IIS Worker Descendant")
    ],
    siem_rules=[],
    techniques=["T1190", "T1059"],
)

EXE_FILE = _common.get_path("bin", "renamed_posh.exe")


@_common.requires_os(*metadata.platforms)
def main():
    w3wp = "C:\\Users\\Public\\w3wp.exe"
    _common.copy_file(EXE_FILE, w3wp)

    # Creating a high entropy file, and executing the rename operation
    _common.execute([w3wp, "/c", "cmd.exe"], timeout=10)
    _common.remove_file(w3wp)


if __name__ == "__main__":
    exit(main())
