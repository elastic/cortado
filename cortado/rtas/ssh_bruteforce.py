# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common

from multiprocessing import Process


@register_code_rta(
    id="61369084-af6a-4fd0-903f-b44467f5d6e7",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="ace1e989-a541-44df-93a8-a8b0591b63c0", name="Potential SSH Brute Force Detected")],
    techniques=["T1110"],
)
def test(masquerade, masquerade2):
    _common.execute([masquerade2, "childprocess", masquerade], timeout=0.3, kill=True)


def main():
    masquerade = "/tmp/sshd-keygen-wrapper"
    masquerade2 = "/tmp/launchd"
    _common.create_macos_masquerade(masquerade)
    _common.create_macos_masquerade(masquerade2)

    # Execute command
    _common.log("Launching fake ssh keygen commands to mimic ssh bruteforce")
    processes = []

    for i in range(25):
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


