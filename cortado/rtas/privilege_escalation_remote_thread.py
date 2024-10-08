# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import platform

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="e1ff47b2-af5d-4cfc-bd94-e0b86828b241",
    name="privilege_escalation_remote_thread",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="458f0b4b-be9a-45bc-8f19-a26dac267250", name="Potential Code Injection via Remote Thread")
    ],
    techniques=["T1055"],
)
def main():
    if platform.processor() == "arm":
        name = "thread_injector_arm"
        sleep_name = "com.apple.sleep_arm"
    else:
        name = "thread_injector_intel"
        sleep_name = "com.apple.sleep_intel"
    sleep_path = _common.get_resource_path(f"bin/{sleep_name}")
    _ = _common.execute_command(f"{sleep_path} 5000 &", shell=True)

    path = _common.get_resource_path(f"bin/{name}")
    _ = _common.execute_command([f"{path} `pgrep {sleep_name}`"])
