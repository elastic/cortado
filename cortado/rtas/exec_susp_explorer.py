# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="76050b81-a8da-43d2-8a83-f18b31162b94",
    platforms=["windows"],
    endpoint_rules=[
        {"rule_name": "Suspicious Windows Explorer Execution", "rule_id": "f8ec5b76-53cf-4989-b451-7d16abec7298"}
    ],
    siem_rules=[],
    techniques=["T1055", "T1036"],
)


@_common.requires_os(*metadata.platforms)
def main():
    explorer = "C:\\Windows\\explorer.exe"
    _common.execute([explorer, "easyminerRTA"], timeout=1, kill=True)


if __name__ == "__main__":
    exit(main())
