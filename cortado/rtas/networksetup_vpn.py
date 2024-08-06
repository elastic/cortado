# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="f9a34606-863d-46aa-b12d-eeeb68b530e3",
    platforms=["macos"],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="15dacaa0-5b90-466b-acab-63435a59701a", name="Virtual Private Network Connection Attempt")
    ],
    techniques=["T1021"],
)


@_common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/networksetup"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake networksetup commands to connect to a VPN.")
    _common.execute([masquerade, "-connectpppoeservice"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
