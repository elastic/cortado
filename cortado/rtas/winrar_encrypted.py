# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Encrypting files with WinRAR
# RTA: winrar_encrypted.py
# ATT&CK: T1022
# Description: Uses "bin\rar.exe" to perform encryption of archives and archive headers.

import base64
import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


MY_APP_EXE = "bin/myapp.exe"
WINRAR_EXE = "bin/Rar.exe"


def create_exfil(path: Path | None = None) -> Path:
    path = path or Path("secret_stuff.txt").resolve()
    log.info("Writing dummy exfil to %s" % path)
    _ = path.write_bytes(base64.b64encode(b"This is really secret stuff" * 100))
    return path


@register_code_rta(
    id="6d2d3c21-2d71-4395-8ab7-b1d0138d9225",
    name="winrar_encrypted",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="45d273fb-1dca-457d-9855-bcb302180c21", name="Encrypting Files with WinRar or 7z")],
    techniques=["T1560"],
    ancillary_files=[MY_APP_EXE, WINRAR_EXE],
)
def main():

    password = "s0l33t"

    my_app_exe = _common.get_resource_path(MY_APP_EXE)
    winrar_exe = _common.get_resource_path(WINRAR_EXE)

    # Copies of the rar.exe for various tests
    winrar_bin_modsig = _common.get_resource_path("bin/rar_broken-sig.exe")
    _common.patch_file_with_bytes(winrar_exe, b"win.rar GmbH", b"bad.bad GmbH", winrar_bin_modsig)

    # Renamed copies of executables
    winrar_bin_modsig_a = Path("a.exe").resolve()
    winrar_bin_b = Path("b.exe").resolve()

    _common.copy_file(winrar_bin_modsig, winrar_bin_modsig_a)
    _common.copy_file(winrar_exe, winrar_bin_b)

    # Output options for various tests
    rar_file = Path("out.rar").resolve()
    rar_file_jpg = Path("out.jpg").resolve()
    _common.remove_files([rar_file, rar_file_jpg])

    # use case: rar with -hp to generate new rar file w/ .rar

    log.info("Test case 1: Basic use new rar out")
    exfil = create_exfil()
    _ = _common.execute_command([str(winrar_exe), "a", str(rar_file), "-hp" + password, str(exfil)])

    # use case: rar with -hp to add to existing rar file
    # didn't delete rar from previous case
    log.info("Test case 2: Basic use add to existing rar")
    exfil2 = create_exfil(Path("more_stuff.txt"))
    _ = _common.execute_command([str(winrar_exe), "a", str(rar_file), "-hp" + password, str(exfil2)])
    _common.remove_files([exfil2, rar_file])

    #  use case: process_name == "*rar*" - yes
    #            original_file_name == "*rar*" - no
    #            signature_signer == "*win.rar*" - no
    #            output filename == "*.rar" - no
    log.info("Test case 3: *rar* in process name")
    _ = _common.execute_command([str(winrar_bin_modsig), "a", str(rar_file_jpg), "-hp" + password, str(exfil)])
    _common.remove_files([rar_file_jpg])

    #  use case: process_name == "*rar*" - no
    #            original_file_name == "*rar*" - no
    #            signature_signer == "*win.rar*" - yes
    #            output filename == "*.rar" - no
    log.info("Test case 4: Expected WinRar signature")
    _ = _common.execute_command([str(winrar_bin_b), "a", str(rar_file_jpg), "-hp" + password, str(exfil)])
    _common.remove_files([rar_file_jpg])

    #  use case: process_name == "*rar*" - no
    #            original_file_name == "*rar*" - no
    #            signature_signer == "*win.rar*" -no
    #            output filename == "*.rar" - yes
    log.info("Test case 5: *.rar in output filename")
    _ = _common.execute_command([str(winrar_bin_modsig_a), "a", str(rar_file), "-hp" + password, str(exfil)])

    _common.remove_files([rar_file, winrar_bin_modsig_a, winrar_bin_b, exfil])

    #   false positive - should not match signature
    #   use case: process_name == "*rar*" - no
    #            original_file_name == "*rar*" - no
    #            signature_signer == "*win.rar*" -no
    #            output filename == "*.rar" - no
    log.info("Test case 6: FP, shouldn't alert, run with myapp.exe")
    _ = _common.execute_command([str(my_app_exe), "-hpbadargument"])

    log.warning("Cleanup")
    _common.remove_files([winrar_bin_modsig, winrar_bin_modsig_a, winrar_bin_b])
