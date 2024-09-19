# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="5fc46f6e-5a2a-4336-98f3-5fdc27db7152",
    name="modify_sublime_app",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="88817a33-60d3-411f-ba79-7c905d865b2a", name="Sublime Plugin or Application Script Modification"
        )
    ],
    techniques=["T1554"],
)
def main():
    sublime_dir = Path(f"{Path.home()}/Library/Application Support/Sublime Text 4/")
    sublime_packages = sublime_dir.joinpath("Packages")
    sublime_packages.mkdir(parents=True, exist_ok=True)
    sublime_path = str(sublime_packages.joinpath("test.py"))
    log.info(f"Executing hidden plist creation on {sublime_path}")
    _common.create_file_with_data(sublime_path, "testing")

    # cleanup
    _common.remove_directory(str(sublime_packages))
    _common.remove_directory(str(sublime_dir))
