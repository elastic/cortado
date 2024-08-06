# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="cc7b01f9-852c-4232-8c70-ada3fb5cc515",
    platforms=["macos"],
    endpoint_rules=[
        {"rule_name": "Potential Credentials Phishing via OSASCRIPT", "rule_id": "318d3d9d-ba60-40e3-bc8c-3d3304209a3c"}
    ],
    siem_rules=[{"rule_name": "Prompt for Credentials with OSASCRIPT", "rule_id": "38948d29-3d5d-42e3-8aec-be832aaaf8eb"}],
    techniques=["T1056"],
)


@_common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/osascript"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake osascript commands to display passwords")
    _common.execute([masquerade, "osascript*display dialog*password*"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
