# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="4843eb25-3579-473a-b309-76d02eda3085",
    platforms=["macos", "linux"],
    endpoint_rules=[{"rule_name": "DARKRADIATION Ransomware Infection", "rule_id": "33309858-3154-47a6-b601-eda2de62557b"}],
    siem_rules=[],
    techniques=["T1486"],
)


@_common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/xargs"
    if _common.CURRENT_OS == "linux":
        source = _common.get_path("bin", "linux.ditto_and_spawn")
        _common.copy_file(source, masquerade)
    else:
        _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake xargs command to execute DARKRADIATION infection")
    _common.execute([masquerade, "openssl", "enc", "test.☢test"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
