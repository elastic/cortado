# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="abd56d74-6538-456e-bd2a-42f08d1bac3c",
    platforms=["macos"],
    endpoint_rules=[
        {
            "rule_name": "Reading or Modifying Downloaded Files Database via SQLite Utility",
            "rule_id": "b8fb52cd-5f06-4519-921d-bd1b363dc01b",
        }
    ],
    siem_rules=[],
    techniques=[],
)


@_common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/sqlite3"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake sqlite3 commands")
    _common.execute([masquerade, "test LSQuarantinetest"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
