# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="cf71bf97-e3ba-474c-9b6b-538e5a8008b0",
    platforms=["macos"],
    endpoint_rules=[],
    siem_rules=[{"rule_name": "Attempt to Disable Gatekeeper", "rule_id": "4da13d6e-904f-4636-81d8-6ab14b4e6ae9"}],
    techniques=["T1553"],
)


@_common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/spctl"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Executing fake spctl for Gatekeeper defensive evasion.")
    _common.execute([masquerade, "spctl", "--master-disable"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
