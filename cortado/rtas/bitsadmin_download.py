# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Suspicious BitsAdmin Download File
# RTA: bitsadmin_download.py
# ATT&CK: T1197
# Description: Runs BitsAdmin to download file via command line.


import subprocess
from pathlib import Path

from . import _common, register_code_rta, OSType, RuleMetadata

@register_code_rta(
    id="aee48793-01ec-428f-9890-c5db9df07830",
    name="bitsadmin_download",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="a624863f-a70d-417f-a7d2-7a404638d47f", name="Suspicious MS Office Child Process")],
    techniques=["T1566"],
)
def main():
    _common.log("Running Windows BitsAdmin to Download")
    server, ip, port = _common.serve_web()
    url = "http://" + ip + ":" + str(port) + "/bin/myapp.exe"
    dest_path = Path("myapp-test.exe").resolve()
    fake_word = Path("winword.exe").resolve()

    _common.log("Emulating parent process: {parent}".format(parent=fake_word))
    _common.copy_file("C:\\Windows\\System32\\cmd.exe", fake_word)

    command = subprocess.list2cmdline(["bitsadmin.exe", "/Transfer", "/Download", url, dest_path])
    _common.execute([fake_word, "/c", command], timeout=15, kill=True)
    _common.execute(["taskkill", "/f", "/im", "bitsadmin.exe"])

    _common.remove_files(dest_path, fake_word)
