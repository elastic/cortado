# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys


@register_code_rta(
    id="6a5977f6-ed19-446e-a441-e325cff7772b",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="0c188a15-30f5-445c-8655-95c7f93ace88", name="Potential curl CVE-2023-38545 Exploitation"),
    ],
    siem_rules=[
        RuleMetadata(id="f41296b4-9975-44d6-9486-514c6f635b2d", name="Potential curl CVE-2023-38545 Exploitation"),
    ],
    techniques=["T1203"],
)
def main() -> None:
    masquerade = "/tmp/curl"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    payload = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    payload += "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    payload += "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    # Execute command
    _common.log("Launching fake command to simulate a buffer overflow")
    _common.execute([masquerade, "--proxy", payload], timeout=5, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
