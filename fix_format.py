#!/usr/bin/env python3
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, FrozenSet

CLANG_FORMAT_BIN: str = "clang-format"
PROJECT_PREFIX: str = "//depot/google3/third_party/java/conscrypt/main_src/"
VALID_EXTENSIONS: FrozenSet[str] = frozenset({".java", ".cc", ".h", ".cpp", ".c"})

def get_g4_output() -> str:
    """Runs g4 opened and returns the stdout."""
    try:
        return subprocess.check_output(["g4", "opened"], text=True)
    except subprocess.CalledProcessError as e:
        sys.exit(f"ERROR: Failed to run 'g4 opened'.\nDetails: {e}")

def parse_files(g4_output: str, project_prefix: str, root_dir: Path) -> List[str]:
    """Parses g4 output and returns a list of absolute file paths to format."""
    files_to_format: List[str] = []

    for line in g4_output.splitlines():
        line = line.strip()
        if not line:
            continue

        depot_path = line.split('#')[0]

        if not depot_path.endswith(tuple(VALID_EXTENSIONS)):
            continue

        if not depot_path.startswith(project_prefix):
            continue

        relative_path = depot_path[len(project_prefix):]

        abs_path = root_dir / relative_path
        files_to_format.append(str(abs_path))

    return files_to_format

def get_jj_output() -> str:
    """Runs jj diff and returns the stdout."""
    try:
        return subprocess.check_output(["jj", "diff", "--name-only", "-r", "@"], text=True)
    except subprocess.CalledProcessError as e:
        sys.exit(f"ERROR: Failed to run 'jj diff'.\nDetails: {e}")

def parse_files_jj(jj_output: str, project_prefix: str, root_dir: Path) -> List[str]:
    """Parses jj output and returns a list of absolute file paths to format."""
    files_to_format: List[str] = []

    for line in jj_output.splitlines():
        line = line.strip()
        if not line:
            continue

        if not line.endswith(tuple(VALID_EXTENSIONS)):
            continue

        prefix = project_prefix.removeprefix("//depot/google3/")
        if prefix and not line.startswith(prefix):
            continue

        relative_path = line[len(prefix):]
        abs_path = root_dir / relative_path
        files_to_format.append(str(abs_path))

    return files_to_format

def is_jj_workspace() -> bool:
    if not shutil.which("jj"):
        return False
    return subprocess.run(["jj", "root"], capture_output=True).returncode == 0

def is_g4_workspace() -> bool:
    if not shutil.which("g4"):
        return False
    proc = subprocess.run(["g4", "opened"], capture_output=True, text=True)
    return "unknown" not in proc.stderr and "unknown" not in proc.stdout

def main() -> None:
    script_dir = Path(__file__).resolve().parent
    config_path = script_dir / ".clang-format"

    try:
        if not config_path.is_file():
             raise FileNotFoundError(f"Config file missing at {config_path}")
    except OSError as e:
        sys.exit(f"ERROR: Could not access config file.\nDetails: {e}")

    if not shutil.which(CLANG_FORMAT_BIN):
        sys.exit(f"ERROR: '{CLANG_FORMAT_BIN}' not found in PATH.")

    print("Querying opened files...")

    if is_g4_workspace():
        g4_output = get_g4_output()
        files_to_format = parse_files(g4_output, PROJECT_PREFIX, script_dir)
    elif is_jj_workspace():
        jj_output = get_jj_output()
        files_to_format = parse_files_jj(jj_output, PROJECT_PREFIX, script_dir)
    else:
        sys.exit("ERROR: Could not determine if we are in a g4 or jj workspace.")

    if not files_to_format:
        print(f"No source files under {PROJECT_PREFIX} are currently open.")
        sys.exit(0)

    print(f"Formatting {len(files_to_format)} file(s) with config: {config_path}")

    cmd = [
        CLANG_FORMAT_BIN,
        "-i",
        f"-style=file:{config_path}",
    ] + files_to_format

    try:
        subprocess.run(cmd, check=True)
        print("Done.")
    except subprocess.CalledProcessError as e:
        sys.exit(f"ERROR: clang-format failed.\nDetails: {e}")

if __name__ == "__main__":
    main()