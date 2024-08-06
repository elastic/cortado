# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="a18454da-5f28-4223-95d6-5dc1f58c861a",
    platforms=["macos"],
    endpoint_rules=[],
    siem_rules=[
        {
            "rule_name": "Modification of Environment Variable via Launchctl",
            "rule_id": "7453e19e-3dbf-4e4e-9ae0-33d6c6ed15e1",
        }
    ],
    techniques=["T1574"],
)


@_common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/launchctl"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake launchctl command to mimic env variable hijacking")
    _common.execute([masquerade, "setenv"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
