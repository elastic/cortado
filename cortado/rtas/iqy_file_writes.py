# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Suspicious IQY/PUB File Writes
# RTA: iqy_file_writes.py
# ATT&CK: T1140, T1192, T1193
# Description: Generates four file writes related to file extensions (PUB, IQY)

import logging
from pathlib import Path

from . import OSType, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="71f67037-1df3-4d5f-b8cb-eaf295ad16ed",
    name="iqy_file_writes",
    platforms=[OSType.WINDOWS],
)
def main():
    log.info("Suspicious File Writes (IQY, PUB)")
    adobe_path = Path("AcroRd32.exe").resolve()
    msoffice_path = Path("winword.exe").resolve()
    browser_path = Path("iexplore.exe").resolve()

    cmd_path = _common.get_cmd_path()

    _common.copy_file(cmd_path, adobe_path)
    _common.copy_file(cmd_path, msoffice_path)
    _common.copy_file(cmd_path, browser_path)
    log.info("Writing files")

    # write file as adobe, then run it
    log.info("Creating a 'suspicious' executable")
    bad_path = Path("bad.exe").resolve()

    # PDF writing IQY file
    fake_iqy = Path("test.iqy").resolve()
    _ = _common.execute_command([str(adobe_path), "/c", "echo", "test", ">", str(fake_iqy)])

    # PDF writing PUB file
    fake_pub = Path("test.pub").resolve()
    _ = _common.execute_command([str(adobe_path), "/c", "echo", "test", ">", str(fake_pub)])

    # Winword writing IQY file
    fake_doc_iqy = Path("test_word.iqy").resolve()
    _ = _common.execute_command([str(msoffice_path), "/c", "echo", "test", ">", str(fake_doc_iqy)])

    # Browser writing IQY file
    fake_browser_iqy = Path("test_browser.iqy").resolve()
    _ = _common.execute_command([str(browser_path), "/c", "echo", "test", ">", str(fake_browser_iqy)])

    # cleanup
    _common.remove_files([adobe_path, bad_path, fake_iqy])
    _common.remove_files([adobe_path, bad_path, fake_pub])
    _common.remove_files([msoffice_path, bad_path, fake_doc_iqy])
    _common.remove_files([browser_path, bad_path, fake_browser_iqy])
