# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="d275922f-a702-4668-a77d-c60e8df58646",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="661545b4-1a90-4f45-85ce-2ebd7c6a15d0", name="Attempt to Mount SMB Share via Command Line")
    ],
    techniques=["T1021"],
)
def main():
    masquerade = "/tmp/mount_smbfs"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake mount_smbfs command to mimic mounting a network share.")
    _common.execute([masquerade], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
