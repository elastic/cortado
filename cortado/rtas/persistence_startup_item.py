# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


from pathlib import Path


@register_code_rta(
    id="7a8c8ab6-4994-47d1-b8b6-d1dca4499289",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="eaf68cce-b250-4a17-a3c3-3c9c4cf1ec14", name="Persistence Attempt via StartupItems")
    ],
    siem_rules=[],
    techniques=[""],
)
def main():
    _common.log("Executing creation on temp StartupParameters.plist file.")
    plist = "/Library/StartupItems/test/StartupParameters.plist"
    output_file = Path(plist)
    output_file.parent.mkdir(exist_ok=True, parents=True)
    _common.temporary_file_helper("testing", file_name=str(plist))
    _common.remove_directory("/Library/StartupItems/test/")
