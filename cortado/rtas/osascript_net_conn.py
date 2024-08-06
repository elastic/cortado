# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="66407efa-a32e-4f4d-b339-def48e23e810",
    platforms=["macos"],
    endpoint_rules=[],
    siem_rules=[
        {
            "rule_name": "Apple Script Execution followed by Network Connection",
            "rule_id": "47f76567-d58a-4fed-b32b-21f571e28910",
        }
    ],
    techniques=["T1105", "T1059"],
)


@_common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/osascript"
    _common.copy_file("/usr/bin/curl", masquerade)

    # Execute command
    _common.log("Launching fake commands to mimic creating a network connection with osascript")
    _common.execute([masquerade, "portquiz.net"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
