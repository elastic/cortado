# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="2182f7e5-fc4b-4476-86c3-e7128dfcaa7a",
    platforms=["macos"],
    endpoint_rules=[
        {
            "rule_name": "Suspicious File Overwrite and Modification via Echo",
            "rule_id": "cd3a06dc-58c3-4d57-a03a-0d8991f237e7",
        }
    ],
    siem_rules=[],
    techniques=["T1027", "T1059", "T1059.004"],
)


@_common.requires_os(*metadata.platforms)
def main():

    file_path = "/tmp/test"
    masquerade = "/tmp/testbin"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake bash commands to abnormal echo shell commands")
    command = f"bash -c 'echo* > {file_path}'"
    _common.execute([masquerade, "childprocess", command], timeout=10, kill=True, shell=True)

    # cleanup
    _common.remove_file(masquerade)
    _common.remove_file(file_path)


if __name__ == "__main__":
    exit(main())
