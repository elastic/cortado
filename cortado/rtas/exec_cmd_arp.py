# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="2a391051-b103-450b-be50-fd133b6d05c3",
    platforms=["windows"],
    endpoint_rules=[],
    siem_rules=[{'rule_id': '0635c542-1b96-4335-9b47-126582d2c19a', 'rule_name': 'Remote System Discovery Commands'}],
    techniques=['T1016', 'T1018'],
)


@_common.requires_os(*metadata.platforms)
def main():
    arp = "C:\\Windows\\System32\\arp.exe"

    # Execute command
    _common.execute([arp, "-a"], timeout=10)


if __name__ == "__main__":
    exit(main())
