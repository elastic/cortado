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

from . import _common



@register_code_rta(
    id="022dc249-a496-413a-9355-c37e3ea41dda",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        {
            "rule_id": "9d110cb3-5f4b-4c9a-b9f5-53f0a1707ae6",
            "rule_name": "Microsoft Build Engine Started an Unusual Process",
        }
    ],
    techniques=["T1027"],
)


MS_BUILD = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\msbuild.exe"



@_common.dependencies(MS_BUILD)
def main():
    _common.log("MsBuild Beacon")
    server, ip, port = _common.serve_web()
    _common.clear_web_cache()

    _common.log("Updating the callback http://%s:%d" % (ip, port))
    target_task = "tmp-file.csproj"
    _common.copy_file(_common.get_path("bin", "BadTasks.csproj"), target_task)
    new_callback = "http://%s:%d" % (ip, port)
    _common.patch_regex(target_task, _common.CALLBACK_REGEX, new_callback)

    _common.execute([MS_BUILD, target_task], timeout=30, kill=True)
    _common.remove_file(target_task)

    server.shutdown()


if __name__ == "__main__":
    exit(main())
