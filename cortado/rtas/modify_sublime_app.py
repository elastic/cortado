# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path
from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="5fc46f6e-5a2a-4336-98f3-5fdc27db7152",
    platforms=["macos"],
    endpoint_rules=[],
    siem_rules=[
        {
            "rule_name": "Sublime Plugin or Application Script Modification",
            "rule_id": "88817a33-60d3-411f-ba79-7c905d865b2a",
        }
    ],
    techniques=["T1554"],
)


@_common.requires_os(*metadata.platforms)
def main():

    sublime_dir = Path(f"{Path.home()}/Library/Application Support/Sublime Text 4/")
    sublime_packages = sublime_dir.joinpath("Packages")
    sublime_packages.mkdir(parents=True, exist_ok=True)
    sublime_path = str(sublime_packages.joinpath("test.py"))
    _common.log(f"Executing hidden plist creation on {sublime_path}")
    _common.temporary_file_helper("testing", file_name=sublime_path)

    # cleanup
    _common.remove_directory(str(sublime_packages))
    _common.remove_directory(str(sublime_dir))


if __name__ == "__main__":
    exit(main())
