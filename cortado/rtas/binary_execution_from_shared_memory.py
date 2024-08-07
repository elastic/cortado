# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys


@register_code_rta(
    id="1b7fe2e7-29c0-4d10-9ced-8b9cd158835d",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        {
            "rule_id": "78ae5dbd-477b-4ce7-a7f7-8c4b5e228df2",
            "rule_name": "Binary Executed from Shared Memory Directory",
        },
    ],
    siem_rules=[
        {
            "rule_id": "3f3f9fe2-d095-11ec-95dc-f661ea17fbce",
            "rule_name": "Binary Executed from Shared Memory Directory",
        },
    ],
    techniques=["T1620"],
)
@_common.requires_os(metadata.platforms)
def main() -> None:
    masquerade = "/dev/shm/test"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    _common.log("Executing Fake binary from Shared Memory")
    _common.execute([masquerade, "test"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
