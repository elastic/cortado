# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="cf5e28a1-0c35-4be1-87ba-381dcdbb2d8b",
    name="potential_injection_via_pyinstaller_executable",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="deb48ee3-8ce0-4ff7-a30b-041c5db024bb", name="Potential Injection via PyInstaller Executable")
    ],
    techniques=['T1055'],
    sample_hash="c081174ab9326b2a9e552dd1b96017b51dd5212a8621d97144b697002baa2ef4",
)
