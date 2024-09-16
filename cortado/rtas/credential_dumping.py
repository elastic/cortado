# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import _common, register_code_rta, OSType, RuleMetadata

@register_code_rta(
    id="43ce7648-d48a-4609-80a5-f68384e498d3",
    name="credential_dumping",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="05f95917-6942-4aab-a904-37c6db906503", name="Potential Linux Credential Dumping via Unshadow"),
    ],
    siem_rules=[],
    techniques=["T1003"],
)
def main() -> None:
    masquerade = "/tmp/unshadow"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    _common.log("Executing Fake commands to test Credential Dumping via Unshadow")
    _common.execute([masquerade, "shadow password"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
