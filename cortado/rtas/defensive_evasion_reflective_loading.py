# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="b023cf4b-2856-4170-9ea0-884041904159",
    platforms=["macos"],
    endpoint_rules=[
        RuleMetadata(id="16fba7a9-f8f6-43ce-ae24-6a392a48e49c", name="MacOS Monterey Reflective Code Loading")
    ],
    siem_rules=[],
    techniques=["T1620", "T1106"],
)


@_common.requires_os(*metadata.platforms)
def main():

    _common.log("Executing deletion on /private/tmp/NSCreateObjectFileImageFromMemory-test file.")
    _common.temporary_file_helper("testing", file_name="/private/tmp/NSCreateObjectFileImageFromMemory-test")


if __name__ == "__main__":
    exit(main())
