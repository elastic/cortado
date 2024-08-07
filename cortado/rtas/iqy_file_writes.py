# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Suspicious IQY/PUB File Writes
# RTA: iqy_file_writes.py
# ATT&CK: T1140, T1192, T1193
# Description: Generates four file writes related to file extensions (PUB, IQY)

from pathlib import Path


@register_code_rta(
    id="71f67037-1df3-4d5f-b8cb-eaf295ad16ed",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[],
    techniques=[],
)
def main():
    _common.log("Suspicious File Writes (IQY, PUB)")
    adobe_path = Path("AcroRd32.exe").resolve()
    msoffice_path = Path("winword.exe").resolve()
    browser_path = Path("iexplore.exe").resolve()
    _common.copy_file(_common.CMD_PATH, adobe_path)
    _common.copy_file(_common.CMD_PATH, msoffice_path)
    _common.copy_file(_common.CMD_PATH, browser_path)
    _common.log("Writing files")

    # write file as adobe, then run it
    _common.log("Creating a 'suspicious' executable")
    bad_path = Path("bad.exe").resolve()

    # PDF writing IQY file
    fake_iqy = Path("test.iqy").resolve()
    _common.execute([adobe_path, "/c", "echo", "test", ">", fake_iqy])

    # PDF writing PUB file
    fake_pub = Path("test.pub").resolve()
    _common.execute([adobe_path, "/c", "echo", "test", ">", fake_pub])

    # Winword writing IQY file
    fake_doc_iqy = Path("test_word.iqy").resolve()
    _common.execute([msoffice_path, "/c", "echo", "test", ">", fake_doc_iqy])

    # Browser writing IQY file
    fake_browser_iqy = Path("test_browser.iqy").resolve()
    _common.execute([browser_path, "/c", "echo", "test", ">", fake_browser_iqy])

    # cleanup
    _common.remove_files(adobe_path, bad_path, fake_iqy)
    _common.remove_files(adobe_path, bad_path, fake_pub)
    _common.remove_files(msoffice_path, bad_path, fake_doc_iqy)
    _common.remove_files(browser_path, bad_path, fake_browser_iqy)
