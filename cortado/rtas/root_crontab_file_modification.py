# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="f9feed6d-bae3-49c6-8952-7ed8e9b0b9ef",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        {
            "rule_name": "Potential Privilege Escalation via Root Crontab File Modification",
            "rule_id": "31151602-1de1-4301-9b75-215ac8902b75",
        }
    ],
    siem_rules=[
        {
            "rule_name": "Privilege Escalation via Root Crontab File Modification",
            "rule_id": "0ff84c42-873d-41a2-a4ed-08d74d352d01",
        }
    ],
    techniques=["T1053"],
)
def main():
    _common.log("Executing deletion on /private/var/at/tabs/root file.")
    _common.temporary_file_helper("testing", file_name="/private/var/at/tabs/root")


if __name__ == "__main__":
    exit(main())
