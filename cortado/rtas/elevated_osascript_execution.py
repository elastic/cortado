# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="086c6cae-22ac-47b6-bd24-85b33d8cf3a2",
    platforms=["macos"],
    endpoint_rules=[
        {
            "rule_name": "Elevated Apple Script Execution via Unsigned Parent",
            "rule_id": "f17c8dcf-d65f-479a-b047-3558233f774e",
        }
    ],
    siem_rules=[
        {
            "rule_name": "Apple Scripting Execution with Administrator Privileges",
            "rule_id": "827f8d8f-4117-4ae4-b551-f56d54b9da6b",
        }
    ],
    techniques=["T1078", "T1548", "T1059"],
)


@_common.requires_os(*metadata.platforms)
def main():

    # create masquerades
    masquerade = "/tmp/bash"
    _common.copy_macos_masquerade(masquerade)

    # Execute commands
    _common.log("Launching fake osascript commands to mimic apple script execution")
    command = "osascript with administrator privileges"
    _common.execute([masquerade, "childprocess", command], shell=True, timeout=5, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
