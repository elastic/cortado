# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: MsBuild with Network Activity
# RTA: msbuild_network.py
# ATT&CK: T1127
# signal.rule.name: Microsoft Build Engine Started an Unusual Process
# signal.rule.name: Trusted Developer Application Usage
# Description: Generates network traffic from msbuild.exe

import logging

from . import OSType, RuleMetadata, _common, _const, register_code_rta

log = logging.getLogger(__name__)


MS_BUILD_EXE = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\msbuild.exe"


@register_code_rta(
    id="022dc249-a496-413a-9355-c37e3ea41dda",
    name="msbuild_network",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="9d110cb3-5f4b-4c9a-b9f5-53f0a1707ae6", name="Microsoft Build Engine Started an Unusual Process"
        )
    ],
    techniques=["T1027"],
    ancillary_files=[MS_BUILD_EXE],
)
def main():
    log.info("MsBuild Beacon")
    server, ip, port = _common.serve_dir_over_http()
    _common.clear_web_cache()

    log.info("Updating the callback http://%s:%d" % (ip, port))
    target_task = "tmp-file.csproj"
    _common.copy_file(_common.get_resource_path("bin/BadTasks.csproj"), target_task)
    new_callback = "http://%s:%d" % (ip, port)
    _common.patch_file_with_regex(target_task, _const.CALLBACK_REGEX, new_callback)

    _ = _common.execute_command([MS_BUILD_EXE, target_task], timeout_secs=30)
    _common.remove_file(target_task)

    server.shutdown()
