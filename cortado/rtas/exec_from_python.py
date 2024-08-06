# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="54041e42-7a4b-417e-ac40-cd50c7085e48",
    platforms=["macos"],
    endpoint_rules=[],
    siem_rules=[
        {
            "rule_name": "Suspicious Python Package Child Process Execution",
            "rule_id": "d8cbba0d-7275-4bcd-be22-79ee6fea2951",
        }
    ],
    techniques=["T1059", "T1059.004", "T1059.006"],
)


@_common.requires_os(*metadata.platforms)
def main():

    # test_file = "/tmp/test.txt"
    masquerade = "/tmp/bash"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching bash commands to mimic python package execution")
    parent_args = "*/lib/python*/site-packages/*"
    _common.execute([masquerade, "childprocess", parent_args, "-c"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
