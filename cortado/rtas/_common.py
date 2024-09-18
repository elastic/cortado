import binascii
import contextlib
import errno
import getpass
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import typing
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Any

from cortado.rtas import OSType
from cortado.rtas._const import (ACCESS_DENIED_RETURNCODE, PS_EXEC_EXE,
                                 REG_HKCR, REG_HKCU, REG_HKLM, REG_HKU,
                                 RTA_SUBPROCESS_TIMEOUT_RETURNCODE)

log = logging.getLogger("cortado.rtas")


# Amount of seconds a command should take at a minimum.
# This can allow for arbitrary slow down of scripts
MIN_EXECUTION_TIME = 0

HOSTS_TO_PROCESS_CAP = 64


class ExecutionError(Exception):
    pass


## OS details


def get_current_user() -> str:
    return getpass.getuser().lower()


def get_current_dir():
    return Path(__file__).resolve().parent


def get_hostname():
    return socket.gethostname()


def get_host_ip() -> str:
    try:
        return socket.gethostbyname(get_hostname())
    except socket.gaierror:
        pass

    return "127.0.0.1"


def is_system() -> bool:
    user_name = get_current_user()
    return user_name == "system" or user_name.endswith("$")


def get_current_os() -> OSType:
    if sys.platform == "darwin":
        return OSType.MACOS
    elif sys.platform.startswith("win"):
        return OSType.WINDOWS
    else:
        return OSType.LINUX


def is_64bit():
    arch_env_var = "PROCESSOR_ARCHITECTURE"
    return os.environ.get(arch_env_var, "") in ("x64", "AMD64")


def get_cmd_path() -> str:
    """Get OS-specific path for a command executable"""
    current_os = get_current_os()
    if current_os == OSType.WINDOWS:
        cmd_path = os.environ.get("COMSPEC")
        if not cmd_path:
            raise ValueError("Can't get COMSPEC env var value")
        return cmd_path

    return "/bin/sh"


def get_current_exec_args():
    script_path = os.path.abspath(sys.argv[0])
    return [sys.executable, script_path] + sys.argv[1:]


def get_winreg():
    try:
        import _winreg as winreg  # type: ignore
    except ImportError:
        import winreg
    return winreg


## Resource utilities


def get_resource_path(path: str | Path) -> Path:
    """Resolve relative path to a resource file into an absolute OS-specific path"""
    return Path(path).resolve()


## File utilities


def create_file_with_data(path: Path | str, data: str | bytes) -> None:
    data_bytes = data.encode("utf-8") if isinstance(data, str) else data
    _ = Path(path).write_bytes(data_bytes)


@contextlib.contextmanager
def file_with_data(path: str, data: str | bytes):
    data_bytes = data.encode("utf-8") if isinstance(data, str) else data

    with open(path, "wb+") as f:
        _ = f.write(data_bytes)
        _ = f.seek(0)
        yield f


def copy_file(source: str | Path, target: str | Path):
    log.info(f"Copying `{source}` to `{target}`")
    shutil.copy(source, target)


def patch_file_with_bytes(source_file: Path, old_bytes: bytes, new_bytes: bytes, target_file: Path | None = None):
    target_file = target_file or source_file
    log.info(
        f"Patching `{source_file}`, replacing `{binascii.b2a_hex(old_bytes)}` bytes with "
        f"`{binascii.b2a_hex(new_bytes)}` bytes, and saving as `{target_file}`"
    )

    source = Path(source_file)
    data = source.read_bytes()
    patched_data = data.replace(old_bytes, new_bytes)

    _ = Path(target_file).write_bytes(patched_data)


def patch_file_with_regex(source_file: Path, regex: bytes | str, new_bytes: bytes, target_file: Path | None = None):
    target_file = target_file or source_file
    log.info(
        f"Patching `{source_file}`, replaving matches to `{regex}` regex with "
        f"`{binascii.b2a_hex(new_bytes)}` bytes, and saving as `{target_file}`"
    )

    regex_bytes = regex if isinstance(regex, bytes) else regex.encode("utf-8")
    contents = Path(source_file).read_bytes()

    matches = re.findall(regex_bytes, contents)
    if not matches:
        log.warning("No regex matches found")
        return

    contents = re.sub(regex_bytes, new_bytes, contents)
    _ = Path(target_file).write_bytes(contents)


# FIXME: might be not needed?
def link_file(source: str | Path, target: str | Path):
    log.info(f"Symlinking `{source}` to `{target}`")
    Path(source).symlink_to(Path(target))


def remove_file(path: str | Path):
    p = Path(path)
    if p.is_file():
        log.info(f"Removing file `{p}`")
        p.unlink()


def remove_files(paths: list[str | Path]):
    for path in paths:
        remove_file(path)


def remove_directory(path: str | Path):
    p = Path(path)
    if p.is_dir():
        log.info(f"Removing directory `{path}`")
        p.rmdir()
    else:
        remove_file(p)


## Process exec utilities


def execute_command(
    command_args: list[str] | tuple[str],
    timeout_secs: int = 30,
    capture_output: bool = True,
    ignore_failures: bool = False,
    ignore_timeout: bool = True,
    shell: bool = False,
    stdin_data: str | bytes | None = None,
    env_vars: dict[str, str] | None = None,
) -> tuple[int, bytes | None, bytes | None]:
    # NOTE: `list2cmdline` is an internal function, so it might break in the future
    # https://github.com/python/cpython/blob/4bb1dd3c5c14338c9d9cea5988431c858b3b76e0/Lib/subprocess.py#L66
    command_str = subprocess.list2cmdline(command_args)

    user_name = get_current_user()
    hostname = get_hostname()
    log.info(f"Executing command as `{user_name}` at `{hostname}`: `{command_str}`")

    stdout = subprocess.PIPE
    stderr = subprocess.STDOUT

    start = time.time()
    try:
        result = subprocess.run(
            command_args,
            input=stdin_data,
            stdout=stdout,
            stderr=stderr,
            timeout_secs=timeout_secs,
            capture_output=capture_output,
            shell=shell,
            env=env_vars,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        log.error(f"Error while executing command in a subprocess: {e}")
        if ignore_failures:
            return e.returncode, e.stdout, e.stderr
        raise ExecutionError("Subprocess command execution failed")
    except subprocess.TimeoutExpired:
        log.error("Subprocess command timed out")
        if ignore_timeout:
            return RTA_SUBPROCESS_TIMEOUT_RETURNCODE, None, None
        raise ExecutionError("Subprocess command timed out")

    run_time = time.time() - start
    log.info(f"Command executed successfully. Return code = {result.returncode}, exec time = {run_time} secs")
    return result.returncode, result.stdout, result.stderr


def create_macos_masquerade(masquerade: str):
    if platform.processor() == "arm":
        name = "com.apple.ditto_and_spawn_arm"
    else:
        name = "com.apple.ditto_and_spawn_intel"
    source = get_resource_path(f"bin/{name}")
    copy_file(source, masquerade)


def clear_web_cache(sleep_secs: int = 1):
    log.info("Clearing temporary web cache files")
    _ = execute_command(["RunDll32.exe", "InetCpl.cpl,", "ClearMyTracksByProcess", "8"])
    time.sleep(sleep_secs)


## HTTP server

def serve_dir_over_http(ip: str | None = None, port: int | None = None, dir_path: Path | None = None) -> tuple[HTTPServer, str, int]:
    handler = SimpleHTTPRequestHandler

    dir_path = dir_path or get_current_dir()
    ip = ip or get_host_ip()

    server = None
    if port:
        server = HTTPServer((ip, port), handler)
    else:
        # Otherwise, try to find a port that's available
        for port in range(8000, 9000):
            try:
                server = HTTPServer((ip, port), handler)
                break
            except socket.error:
                pass

    if not port or not server:
        raise ExecutionError("Can't start a web server")

    def server_thread():
        os.chdir(dir_path)
        log.info(f"Starting web server on http://{ip}:{port:d} for directory {dir_path}")
        server.serve_forever()

    # Start this thread in the background
    thread = threading.Thread(target=server_thread, daemon=True)
    thread.start()

    return server, ip, port


## Unilities


def as_wchar(s: str):
    return s.encode("utf-16le")


def find_writeable_directory(base_dir: str | Path):
    base_dir_path = Path(base_dir)
    for dirpath, dirnames, _ in base_dir_path.walk():
        for subdir_name in dirnames:
            subdir_path = dirpath / subdir_name
            test_file = subdir_path / "test_file"
            try:
                _ = test_file.write_bytes(b"test")
                return subdir_path
            except PermissionError:
                pass
            finally:
                test_file.unlink()


def elevate_to_system(arguments: list[str] | None = None) -> bool:
    if is_system():
        return True

    arguments = arguments or get_current_exec_args()
    ps_exec_path = get_resource_path(PS_EXEC_EXE)

    log.info("Attempting to elevate to SYSTEM using PsExec")

    if not ps_exec_path.is_file():
        log.error("PsExec not found")
        raise ExecutionError(f"PsExec not found at `{ps_exec_path}`")

    returncode, _, _ = execute_command([str(ps_exec_path), "-w", os.getcwd(), "-accepteula", "-s"] + arguments)

    if returncode == ACCESS_DENIED_RETURNCODE:
        log.error("Failed to elevate to SYSTEM")
        return False

    return True


## Registry utilities


def write_to_registry(
    hive: str,
    key: str,
    value: str,
    data: str | int | list[str | int],
    data_type: str | int = "sz",
    restore: bool = True,
    pause: bool = False,
    append: bool = False,
) -> None:
    with temp_registry_value(hive, key, value, data, data_type, restore, pause, append):
        pass


@typing.no_type_check
@contextlib.contextmanager
def temp_registry_value(
    hive_name: str,
    key: str,
    value: str,
    data: str | int | list[str | int],
    data_type: str | int = "sz",
    restore: bool = True,
    pause: bool = False,
    append: bool = False,
):
    winreg = get_winreg()
    pre_restore_sleep_secs = 0.5
    post_changes_pause_sleep_secs = 0.5

    hives: dict[str, Any] = {
        REG_HKLM: winreg.HKEY_LOCAL_MACHINE,
        REG_HKCU: winreg.HKEY_CURRENT_USER,
        REG_HKU: winreg.HKEY_USERS,
        REG_HKCR: winreg.HKEY_CLASSES_ROOT,
    }
    hive = hives[hive_name]

    if isinstance(data_type, str):
        attr = "REG_" + data_type.upper()
        data_type = getattr(winreg, attr)
    else:
        data_type = data_type or winreg.REG_SZ

    key = key.rstrip("\\")
    hkey = winreg.CreateKey(hive, key)

    old_data = None
    old_type = None

    try:
        # check if the key already exists
        old_data, old_type = winreg.QueryValueEx(hkey, value)
    except WindowsError as e:
        # Check if the error is "No such file or directory"
        if e.errno != errno.ENOENT:
            raise

    key_exists = old_type is not None

    if append and key_exists:
        # If appending to the existing REG_MULTI_SZ key, then append to the end
        if not isinstance(data, list):
            data = [data]

        if isinstance(old_data, list):
            data = old_data + data

    data_string = ",".join(data) if isinstance(data, list) else data
    log.info(f"Writing to registry: key=`{key}`, value=`{value}`, data=`{data_string}`")

    winreg.SetValueEx(hkey, value, 0, data_type, data)

    stored_data, _ = winreg.QueryValueEx(hkey, value)

    if data != stored_data:
        log.warning(f"Wrote `{data}` to registry at `{hkey}` but retrieved `{stored_data}`")

    # Allow code to execute within the context manager 'with'
    try:
        yield
    finally:
        if restore:
            time.sleep(pre_restore_sleep_secs)
            if key_exists:
                # Otherwise restore the value
                old_data_string = ",".join(old_data) if isinstance(old_data, list) else old_data
                log.info(f"Restoring registry value to: key=`{key}`, value=`{value}`, data=`{old_data_string}`")
                winreg.SetValueEx(hkey, value, 0, old_type, old_data)
            else:
                # If it didn't already exist, then delete it
                log.info(f"Deleting from registry: key=`{key}`, value=`{value}`")
                winreg.DeleteValue(hkey, value)

        hkey.Close()
        if pause:
            time.sleep(post_changes_pause_sleep_secs)


def enable_logon_audit(host: str = "localhost", verbose: bool = True, sleep_secs: int = 2) -> bool:
    """Enable logon auditing on local or remote system to enable 4624 and 4625 events."""

    if verbose:
        log.info(f"Ensuring audit logging is enabled on {host}")

    auditpol_cmd = "auditpol.exe /set /subcategory:Logon /failure:enable /success:enable"
    enable_logging_cmd = (
        f"Invoke-WmiMethod -ComputerName {host} -Class Win32_process -Name create -ArgumentList '{auditpol_cmd}'"
    )
    command = ["powershell", "-c", enable_logging_cmd]
    retcode, _, stderr = execute_command(command)

    # additional time to allow auditing to process
    time.sleep(sleep_secs)
    if retcode != 0:
        log.error(f"Error while enabling logon audit: `{stderr or ""}`")
        return False
    return True


def print_file(path: str | Path):
    file_path = Path(path)
    if not file_path.is_file():
        print(f"File `{path}` is not found")
        return

    print(f"Contents of `{path}`:")
    data = file_path.read_bytes()
    print(data.rstrip())
