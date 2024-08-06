# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="633313a4-dbe5-420f-b4ae-90c481a7f881",
    platforms=["macos"],
    endpoint_rules=[],
    siem_rules=[{"rule_name": "Attempt to Install Root Certificate", "rule_id": "bc1eeacf-2972-434f-b782-3a532b100d67"}],
    techniques=["T1553"],
)


@_common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/security"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Executing fake security commands to add a root cert.")
    _common.execute([masquerade, "add-trusted-cert"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
