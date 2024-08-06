# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="459d7b3c-2c6d-4101-b830-d6c317d4b355",
    platforms=["macos"],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="080bc66a-5d56-4d1f-8071-817671716db9", name="Suspicious Browser Child Process")],
    techniques=["T1203", "T1189"],
)


@_common.requires_os(*metadata.platforms)
def main():

    # create masquerades
    masquerade = "/tmp/Opera"
    masquerade2 = "/tmp/curl"
    _common.create_macos_masquerade(masquerade)
    _common.create_macos_masquerade(masquerade2)

    # Execute command
    _common.log("Launching fake macOS installer commands to download payload")

    command = f"{masquerade2} test.amazonaws.comtest"
    _common.execute([masquerade, "childprocess", command], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)


if __name__ == "__main__":
    exit(main())
