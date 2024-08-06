# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="2c2c75c0-28cc-4828-b8a4-6b33e027a80a",
    platforms=["macos"],
    endpoint_rules=[
        {
            "rule_name": "Execution of a File Dropped by OpenSSL",
            "rule_id": "d2017990-b448-4617-8d4a-55aa45abe354",
        }
    ],
    siem_rules=[],
    techniques=["T1027", "T1140", "T1204", "T1204.002"],
)


@_common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/testbin"

    # Execute command
    _common.log("Launching bash commands for file creation via openssl")
    _common.execute(["openssl", "rand", "-base64", 2, "-out", masquerade], timeout=10, kill=True)

    _common.create_macos_masquerade(masquerade)
    _common.execute([masquerade, "ls"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
