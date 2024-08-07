# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from multiprocessing import Process


@register_code_rta(
    id="04361aca-0550-4134-ac21-939bf4a0582f",
    platforms=["macos", "linux"],
    endpoint_rules=[
        RuleMetadata(
            id="41f1f818-0efe-4670-a2ed-7a4c200dd621",
            name="Suspicious Content Extracted or Decompressed via Built-In Utilities",
        )
    ],
    siem_rules=[],
    techniques=["T1059", "T1059.004", "T1027", "T1140"],
)
def test(masquerade, masquerade2):
    _common.execute([masquerade2, "childprocess", masquerade, "testnessus_sutest"], timeout=0.3, kill=True)


def main():
    masquerade = "/tmp/funzip"
    masquerade2 = "/tmp/bash"
    if _common.CURRENT_OS == "linux":
        source = _common.get_path("bin", "linux.ditto_and_spawn")
        _common.copy_file(source, masquerade)
        _common.copy_file(source, masquerade2)
    else:
        _common.create_macos_masquerade(masquerade)
        _common.create_macos_masquerade(masquerade2)

    # Execute command
    _common.log("Launching fake funzip commands to extract suspicious content")
    processes = []

    for i in range(2):
        p = Process(
            target=test,
            args=(
                masquerade,
                masquerade2,
            ),
        )
        processes.append(p)

    for i in processes:
        i.start()

    for i in processes:
        i.join()

    # cleanup
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)
