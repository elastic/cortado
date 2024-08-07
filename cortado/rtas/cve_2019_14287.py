# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="df91f5f2-a0a0-47e8-848b-d01526a43d60",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        {
            "rule_name": "Potential Sudo Privilege Escalation via CVE-2019-14287",
            "rule_id": "b382c343-892d-46e1-8fad-22576a086598",
        }
    ],
    siem_rules=[
        {
            "rule_name": "Potential Sudo Privilege Escalation via CVE-2019-14287",
            "rule_id": "8af5b42f-8d74-48c8-a8d0-6d14b4197288",
        }
    ],
    techniques=["T1068"],
)
def main():
    masquerade = "/tmp/sudo"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    _common.log("Launching fake sudo command to simulate CVE-2019-14287")
    _common.execute([masquerade, "-u#-1"], timeout=5, kill=True)

    # cleanup
    _common.remove_file(masquerade)


