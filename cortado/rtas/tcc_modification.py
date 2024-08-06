# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="34cddcb3-bd49-4363-8092-677307abaa82",
    platforms=["macos"],
    endpoint_rules=[],
    siem_rules=[
        {
            "rule_name": "Potential Privacy Control Bypass via TCCDB Modification",
            "rule_id": "eea82229-b002-470e-a9e1-00be38b14d32",
        }
    ],
    techniques=["T1562"],
)


@_common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/sqlite"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake plistbuddy command to modify plist files")
    _common.execute(
        [masquerade, "/test/Application Support/com.apple.TCC/TCC.db"],
        timeout=10,
        kill=True,
    )

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
