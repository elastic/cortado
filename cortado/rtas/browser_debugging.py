# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import platform

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="e061a96e-4c31-4f67-9745-6ff873f7829e",
    name="browser_debugging",
    platforms=[OSType.LINUX, OSType.MACOS, OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="5d7328aa-973b-41e7-a6b3-6f40ea3094f1", name="Potential Cookies Theft via Browser Debugging")
    ],
    siem_rules=[
        RuleMetadata(id="027ff9ea-85e7-42e3-99d2-bbb7069e02eb", name="Potential Cookies Theft via Browser Debugging")
    ],
    techniques=["T1539"],
)
def main():
    param1 = "--remote-debugging-port=9222"
    param2 = "--user-data-dir=remote-profile"
    current_os = _common.get_current_os()
    if current_os == OSType.MACOS:
        if platform.processor() == "arm":
            name = "com.apple.ditto_and_spawn_arm"
        else:
            name = "com.apple.ditto_and_spawn_intel"

        source = _common.get_resource_path(f"bin/{name}")
        chrome = "/tmp/google-chrome"
        _common.copy_file(source, chrome)

        log.info("Starting browser on debug mode")
        _ = _common.execute_command([chrome, param1, param2], timeout_secs=10)

    elif current_os == OSType.LINUX:
        name = "linux.ditto_and_spawn"
        source = _common.get_resource_path(f"bin/{name}")
        chrome = "/tmp/google-chrome"
        _common.copy_file(source, chrome)

        log.info("Starting browser on debug mode")
        _ = _common.execute_command([chrome, param1, param2], timeout_secs=10)
    else:
        EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")
        chrome = "C:\\Users\\Public\\chrome.exe"
        _common.copy_file(EXE_FILE, chrome)

        # Execute command
        log.info("Mimicking the start of a browser on debug mode")
        _ = _common.execute_command([chrome, "/c", "echo", param1, param2], timeout_secs=10)
        _common.remove_file(chrome)
