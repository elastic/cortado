# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


from pathlib import Path


@register_code_rta(
    id="4693d845-6b2f-435a-92aa-54421071e599",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        {"rule_id": "875b71bb-ef09-46b2-9c12-a95112461e85", "rule_name": "Potential XCSSET Malware Infection"}
    ],
    siem_rules=[],
    techniques=[""],
)
def main():
    masquerade = "/tmp/zip"
    _common.create_macos_masquerade(masquerade)

    # Execute commands
    _common.log("Launching fake XCSSET commands to zip the Group Containers directory")
    _common.execute(
        [masquerade, "-r", f"{Path.home()}/Library/Group Containers/test"], shell=True, timeout=5, kill=True
    )

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
