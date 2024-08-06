# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata

metadata = RtaMetadata(
    id="2e5d3ddd-6dc4-4ebf-93e3-c32698b8df40",
    platforms=["windows"],
    endpoint_rules=[],
    siem_rules=[{'rule_id': '1327384f-00f3-44d5-9a8c-2373ba071e92', 'rule_name': 'Persistence via Scheduled Job Creation'}],
    techniques=['T1053', 'T1053.005'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")


@_common.requires_os(*metadata.platforms)
def main():
    path = "C:\\Windows\\Tasks\\a.job"
    _common.copy_file(EXE_FILE, path)
    _common.remove_files(path)


if __name__ == "__main__":
    exit(main())
