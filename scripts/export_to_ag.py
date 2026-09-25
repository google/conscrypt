#!/usr/bin/env python3
# Copyright (C) 2026 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Automated export tool for Conscrypt: google3 to Android Gerrit.

This script coordinates the end-to-end export process by automating:
1. Pre-export workspace cleanup (git reset --hard & git clean -fd) in local
Android repo.
2. Google3 pre-export clang-formatting via fix_format.py.
3. Auto-discovery or provisioning of Android / Cider-G workspace.
4. Copybara export_to_ag execution.
5. Preserving the genuine Copybara export commit at HEAD (preserving commit
metadata/PiperOrigin-RevId).
6. Android repackaging (via direct currysrc Java transformer into temporary
directories).
7. Android-specific clang-formatting (git-clang-format) on modified and
repackaged files.
8. Git staging, amending the genuine Copybara commit with all repackaged files,
and uploading to Gerrit (refs/for/master).
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import io
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from typing import Dict, List, Optional, Tuple
import urllib.request
import zipfile

DEFAULT_COPYBARA_BIN = "/google/data/ro/teams/copybara/copybara"
GERRIT_SSO_URL = "sso://googleplex-android/platform/external/conscrypt"
GERRIT_HTTPS_GOB_URL = (
    "https://googleplex-android.googlesource.com/platform/external/conscrypt"
)
GERRIT_HTTPS_URL = (
    "https://android.googlesource.com/platform/external/conscrypt"
)
GERRIT_PUSH_URLS = (
    "https://googleplex-android.googlesource.com/a/platform/external/conscrypt",
    "https://googleplex-android-review.googlesource.com/a/platform/external/conscrypt",
    "https://android-review.googlesource.com/a/platform/external/conscrypt",
    GERRIT_SSO_URL,
)
X20_CURRYSRC_RO = pathlib.Path(
    "/google/data/ro/users/mi/miguelaranda/currysrc.jar"
)

# Relative paths where currysrc.jar is located inside an Android checkout.
CURRYSRC_HOST_OUT_JARS = (
    pathlib.Path("out/host/linux-x86/framework/currysrc.jar"),
    pathlib.Path("out/soong/host/linux-x86/framework/currysrc.jar"),
    pathlib.Path(
        "out/soong/.intermediates/external/icu/tools/srcgen/currysrc/currysrc/linux_glibc_common/combined/currysrc.jar"
    ),
)


def get_writable_bin_dir() -> pathlib.Path:
  """Returns a writable directory for wrapper scripts (/tmpfs/bin or tempdir)."""
  for cand in [
      pathlib.Path("/tmpfs/bin"),
      pathlib.Path(tempfile.gettempdir())
      / f"conscrypt_bin_{os.environ.get('USER', 'user')}",
  ]:
    try:
      cand.mkdir(parents=True, exist_ok=True)
      if os.access(cand, os.W_OK):
        return cand
    except OSError:
      continue
  return pathlib.Path(tempfile.mkdtemp(prefix="conscrypt_bin_"))


def setup_kokoro_git_env() -> None:
  """Configures git wrapper and credential helpers for Kokoro environments."""
  real_git = shutil.which("git") or "/usr/bin/git"
  wrapper_dir = get_writable_bin_dir()
  wrapper_path = wrapper_dir / "git"

  # Create a git wrapper that strips --object-format=* and --ref-format=* flags
  # unsupported by Git < 2.36 (e.g. Git 2.25 on Kokoro ubuntu2004).
  if real_git != str(wrapper_path):
    wrapper_path.write_text(
        "#!/bin/bash\n"
        "args=()\n"
        'for arg in "$@"; do\n'
        '  case "$arg" in\n'
        "    --object-format=*|--ref-format=*)\n"
        "      ;;\n"
        "    *)\n"
        '      args+=("$arg")\n'
        "      ;;\n"
        "  esac\n"
        "done\n"
        f'exec "{real_git}" "${{args[@]}}"\n'
    )
    wrapper_path.chmod(0o755)
    current_path = os.environ.get("PATH", "")
    if str(wrapper_dir) not in current_path.split(":"):
      os.environ["PATH"] = f"{wrapper_dir}:{current_path}"

  # Ensure global git identity is configured for Copybara and Git commits
  res_name = subprocess.run(
      [real_git, "config", "--get", "user.name"],
      capture_output=True,
      text=True,
      check=False,
  )
  if res_name.returncode != 0 or not res_name.stdout.strip():
    subprocess.run(
        [real_git, "config", "--global", "user.name", "Conscrypt Team"],
        capture_output=True,
        check=False,
    )
  res_email = subprocess.run(
      [real_git, "config", "--get", "user.email"],
      capture_output=True,
      text=True,
      check=False,
  )
  if res_email.returncode != 0 or not res_email.stdout.strip():
    subprocess.run(
        [real_git, "config", "--global", "user.email", "no-reply@google.com"],
        capture_output=True,
        check=False,
    )

  # If git-remote-sso is missing (e.g. in Kokoro GCP Docker container),
  # set up git-cookie-authdaemon and HTTPS URL rewrites.
  if not shutil.which("git-remote-sso"):
    artifacts_dir = pathlib.Path(
        os.environ.get("KOKORO_ARTIFACTS_DIR", "/tmpfs/src")
    )
    gcompute_dir = artifacts_dir / "gcompute-tools"
    if not gcompute_dir.is_dir():
      subprocess.run(
          [
              real_git,
              "clone",
              "--depth",
              "1",
              "https://gerrit.googlesource.com/gcompute-tools",
              str(gcompute_dir),
          ],
          capture_output=True,
          check=False,
      )
    auth_daemon = gcompute_dir / "git-cookie-authdaemon"
    if auth_daemon.is_file():
      subprocess.run(
          [sys.executable, str(auth_daemon)], capture_output=True, check=False
      )

    subprocess.run(
        [
            real_git,
            "config",
            "--global",
            "url.https://googleplex-android.googlesource.com/.insteadOf",
            "sso://googleplex-android/",
        ],
        capture_output=True,
        check=False,
    )
    subprocess.run(
        [
            real_git,
            "config",
            "--global",
            "url.https://googleplex-android.googlesource.com/.insteadOf",
            "rpc://googleplex-android/",
        ],
        capture_output=True,
        check=False,
    )


def run_cmd(
    cmd: List[str],
    cwd: Optional[pathlib.Path] = None,
    env: Optional[Dict[str, str]] = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
  """Helper to run a subprocess command with logging."""
  print(f"==> Running: {' '.join(cmd)}" + (f" (in {cwd})" if cwd else ""))
  try:
    return subprocess.run(
        cmd, cwd=cwd, env=env, check=check, text=True, capture_output=False
    )
  except subprocess.CalledProcessError as e:
    sys.exit(
        f"ERROR: Command failed with exit code {e.returncode}.\nCommand:"
        f" {' '.join(cmd)}"
    )


def get_copybara_bin(custom_path: Optional[str]) -> str:
  """Finds a valid Copybara executable."""
  if custom_path:
    if shutil.which(custom_path) or pathlib.Path(custom_path).is_file():
      return custom_path
    sys.exit(f"ERROR: Specified Copybara binary not found: {custom_path}")

  candidates = [
      DEFAULT_COPYBARA_BIN,
      "/google/bin/releases/copybara/public/copybara/copybara",
      "/tmpfs/bin/copybara",
  ]
  for cand in candidates:
    if pathlib.Path(cand).is_file():
      return cand

  which_copybara = shutil.which("copybara")
  if which_copybara:
    return which_copybara

  # Check Kokoro MPM location
  artifacts_dir = os.environ.get("KOKORO_ARTIFACTS_DIR", "/tmpfs/src")
  mpm_jar = (
      pathlib.Path(artifacts_dir)
      / "mpm/devtools/copybara/tool_kokoro/copybara_on_kokoro_deploy.jar"
  )
  if mpm_jar.is_file():
    jdk_java = pathlib.Path(artifacts_dir) / "mpm/java/jdk/bin/java"
    java_bin = str(jdk_java) if jdk_java.is_file() else "java"
    wrapper_dir = get_writable_bin_dir()
    wrapper_path = wrapper_dir / "copybara"
    runfiles_path = mpm_jar.parent / "google3"
    wrapper_path.write_text(
        "#!/bin/bash\n"
        f'exec "{java_bin}"'
        f' -Dcom.google.devtools.copybara.runfiles.path="{runfiles_path}"'
        f' -jar "{mpm_jar}" "$@"\n'
    )
    wrapper_path.chmod(0o755)
    return str(wrapper_path)

  sys.exit(
      f"ERROR: Copybara executable not found at '{DEFAULT_COPYBARA_BIN}' or in"
      " PATH."
  )


def get_current_user() -> str:
  """Extracts username using getpass or path fallback."""
  try:
    return getpass.getuser()
  except (KeyError, OSError):
    pass

  parts = pathlib.Path(__file__).resolve().parts
  if "cloud" in parts:
    idx = parts.index("cloud")
    if idx + 1 < len(parts):
      return parts[idx + 1]

  return "miguelaranda"


def find_google3_parent(start_path: pathlib.Path) -> pathlib.Path:
  """Finds the directory containing google3 (client root or artifacts dir)."""
  if "KOKORO_PIPER_DIR" in os.environ:
    p = pathlib.Path(os.environ["KOKORO_PIPER_DIR"])
    if (p / "google3").is_dir():
      return p
  if "KOKORO_ARTIFACTS_DIR" in os.environ:
    p = pathlib.Path(os.environ["KOKORO_ARTIFACTS_DIR"]) / "piper"
    if (p / "google3").is_dir():
      return p

  curr = start_path.resolve()
  while curr != curr.parent:
    if curr.name == "google3":
      return curr.parent
    curr = curr.parent
  return start_path.parents[4]


def find_candidate_android_trees() -> List[pathlib.Path]:
  """Discovers potential Android source checkouts in the user's environment."""
  candidates: List[pathlib.Path] = []
  seen: set[pathlib.Path] = set()

  def add_candidate(path: pathlib.Path) -> None:
    resolved = path.resolve()
    if resolved not in seen and resolved.is_dir():
      seen.add(resolved)
      candidates.append(resolved)

  # 1. Check explicit environment variable
  env_top = os.environ.get("ANDROID_BUILD_TOP")
  if env_top:
    add_candidate(pathlib.Path(env_top))

  # 2. Check current working directory and its parents
  curr = pathlib.Path.cwd()
  while curr != curr.parent:
    if (curr / "build" / "envsetup.sh").is_file() or (curr / ".repo").is_dir():
      add_candidate(curr)
      break
    curr = curr.parent

  # 3. Discover checkouts in user's home directories
  home_bases: List[pathlib.Path] = [pathlib.Path.home()]
  user = get_current_user()
  corp_home = pathlib.Path(f"/usr/local/google/home/{user}")
  if corp_home != pathlib.Path.home() and corp_home.is_dir():
    home_bases.append(corp_home)

  for base in home_bases:
    try:
      for child in base.iterdir():
        if not child.is_dir() or child.is_symlink():
          continue
        # An Android tree typically has build/envsetup.sh, .repo, or
        # external/conscrypt.
        if (
            (child / "build" / "envsetup.sh").is_file()
            or (child / ".repo").is_dir()
            or (child / "external" / "conscrypt").is_dir()
            or (child / "tools" / "currysrc").is_dir()
        ):
          add_candidate(child)
    except (OSError, PermissionError):
      continue

  return candidates


def resolve_android_and_build_top(
    explicit_dir: Optional[str],
) -> Tuple[
    pathlib.Path,
    Optional[pathlib.Path],
    Optional[tempfile.TemporaryDirectory[str]],
]:
  """Resolves Android conscrypt directory and ANDROID_BUILD_TOP."""
  temp_dir_obj = None

  if explicit_dir:
    p = pathlib.Path(explicit_dir).resolve()
    if not p.is_dir():
      sys.exit(
          f"ERROR: Specified Android directory does not exist: {explicit_dir}"
      )

    curr = p
    build_top = None
    while curr != curr.parent:
      if (curr / "build" / "envsetup.sh").is_file() or (
          curr / "tools" / "currysrc"
      ).is_dir():
        build_top = curr
        break
      curr = curr.parent
    return p, build_top, None

  # Check explicit environment variables
  for env_var in ["CONSCYPT_ANDROID_DIR", "ANDROID_BUILD_TOP"]:
    val = os.environ.get(env_var)
    if val:
      p = (
          pathlib.Path(val) / "external" / "conscrypt"
          if not val.endswith("conscrypt")
          else pathlib.Path(val)
      )
      if p.is_dir():
        bt = pathlib.Path(os.environ.get("ANDROID_BUILD_TOP", val))
        return p.resolve(), bt.resolve(), None

  # Check Kokoro Git-on-Borg SCM directory if present
  kokoro_git_conscrypt = (
      pathlib.Path(os.environ.get("KOKORO_ARTIFACTS_DIR", "/tmpfs/src"))
      / "git"
      / "conscrypt"
  )
  if (kokoro_git_conscrypt / ".git").is_dir():
    return kokoro_git_conscrypt.resolve(), None, None

  # Search discovered candidate Android trees in the user's workspace/home
  for tree in find_candidate_android_trees():
    conscrypt_dir = tree / "external" / "conscrypt"
    if (conscrypt_dir / ".git").is_dir():
      return conscrypt_dir.resolve(), tree.resolve(), None

  print("\nCreating temporary clone of Android Gerrit repo...")
  temp_dir_obj = tempfile.TemporaryDirectory(prefix="conscrypt_export_")
  temp_path = pathlib.Path(temp_dir_obj.name)
  clone_urls = [
      GERRIT_SSO_URL,
      GERRIT_HTTPS_GOB_URL,
      GERRIT_HTTPS_URL,
  ]
  cloned = False
  for url in clone_urls:
    res = subprocess.run(
        [
            "git",
            "clone",
            "--branch",
            "master",
            url,
            str(temp_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
      res = subprocess.run(
          [
              "git",
              "clone",
              "--no-single-branch",
              url,
              str(temp_path),
          ],
          capture_output=True,
          text=True,
          check=False,
      )
    if res.returncode == 0:
      cloned = True
      break
    print(f"Clone from {url} failed: {res.stderr.strip()}")
  if not cloned:
    sys.exit("ERROR: Could not clone Android conscrypt repository.")
  return temp_path, None, temp_dir_obj


def step_clean_android_repo(
    android_dir: pathlib.Path,
    is_explicit: bool = False,
    force: bool = False,
) -> None:
  """Resets working tree and cleans untracked files in the local Android repository."""
  if is_explicit and not force and sys.stdin.isatty():
    ans = input(
        "\nWARNING: About to run 'git reset --hard' and 'git clean -fd' in"
        f" {android_dir}.\nAny uncommitted changes in that directory will be"
        " lost.\nContinue? [y/N] "
    )
    if ans.strip().lower() not in ("y", "yes"):
      sys.exit("Aborted by user.")

  print(f"\n--- Cleaning local Android repo working tree at {android_dir} ---")
  run_cmd(["git", "reset", "--hard", "HEAD"], cwd=android_dir, check=False)
  run_cmd(["git", "clean", "-fd"], cwd=android_dir, check=False)


def step_format_google3(script_dir: pathlib.Path) -> None:
  """Runs fix_format.py on google3 workspace opened files."""
  fix_format_script = script_dir / "fix_format.py"
  if not fix_format_script.is_file():
    print(
        f"Warning: {fix_format_script} not found. Skipping google3 format fix."
    )
    return

  print("\n--- Step 1: Formatting google3 source files ---")
  run_cmd([sys.executable, str(fix_format_script)], cwd=script_dir)


def step_copybara_export(
    copybara_bin: str,
    copybara_config: pathlib.Path,
    android_dir: pathlib.Path,
    google3_parent: pathlib.Path,
    cl: Optional[str],
    dry_run: bool,
    use_folder_origin: bool,
    extra_copybara_args: List[str],
    is_kokoro: bool = False,
) -> Optional[str]:
  """Runs Copybara export_to_ag or export_to_ag_folder workflow."""
  workflow_name = "export_to_ag_folder" if use_folder_origin else "export_to_ag"
  print(f"\n--- Step 2: Running Copybara {workflow_name} ---")

  cmd = [
      copybara_bin,
      str(copybara_config),
      workflow_name,
  ]

  temp_origin_obj = None
  if use_folder_origin:
    if is_kokoro:
      cmd.append(str(google3_parent))
    else:
      temp_origin_obj = tempfile.TemporaryDirectory(
          prefix="conscrypt_g3_origin_"
      )
      staged_main_src = (
          pathlib.Path(temp_origin_obj.name)
          / "google3"
          / "third_party"
          / "java"
          / "conscrypt"
          / "main_src"
      )
      staged_main_src.parent.mkdir(parents=True, exist_ok=True)
      src_main_src = (
          google3_parent
          / "google3"
          / "third_party"
          / "java"
          / "conscrypt"
          / "main_src"
      )
      shutil.copytree(src_main_src, staged_main_src, symlinks=True)
      cmd.append(temp_origin_obj.name)
    if cl:
      cmd.append(
          "--force-message=Conscrypt: Automated export from google3 (CL"
          f" {cl})\n\nPiperOrigin-RevId: {cl}"
      )
    cmd.append("--force-author=Conscrypt Team <no-reply@google.com>")
  else:
    if cl:
      cmd.append(cl)

  cmd.extend(["--force", "--init-history", "--ignore-noop", "--verbose"])

  cmd.extend([
      f"--git-destination-url=file://{android_dir}",
      "--git-destination-fetch=master",
      "--git-destination-push=master",
  ])

  if dry_run:
    cmd.append("--dry-run")

  # Determine remote name: goog or origin
  remote_name = "origin"
  for cand in ["goog", "origin"]:
    if (
        subprocess.run(
            ["git", "remote", "get-url", cand],
            cwd=android_dir,
            capture_output=True,
            check=False,
        ).returncode
        == 0
    ):
      remote_name = cand
      break

  remote_ref = f"{remote_name}/master"
  print(f"--- Resetting {android_dir} master branch to {remote_ref} ---")
  fetch_res = subprocess.run(
      [
          "git",
          "fetch",
          remote_name,
          f"+refs/heads/master:refs/remotes/{remote_name}/master",
      ],
      cwd=android_dir,
      capture_output=True,
      text=True,
      check=False,
  )
  if fetch_res.returncode != 0:
    subprocess.run(
        [
            "git",
            "fetch",
            remote_name,
            f"+refs/heads/main:refs/remotes/{remote_name}/master",
        ],
        cwd=android_dir,
        capture_output=True,
        text=True,
        check=False,
    )
  run_cmd(
      ["git", "checkout", "-B", "master", f"refs/remotes/{remote_name}/master"],
      cwd=android_dir,
      check=False,
  )
  run_cmd(
      ["git", "reset", "--hard", f"refs/remotes/{remote_name}/master"],
      cwd=android_dir,
      check=False,
  )
  if (android_dir / ".git" / "shallow").is_file():
    print("--- Unshallowing destination repository for Copybara ---")
    run_cmd(["git", "fetch", "--unshallow"], cwd=android_dir, check=False)
  run_cmd(
      ["git", "config", "receive.denyCurrentBranch", "ignore"],
      cwd=android_dir,
      check=False,
  )

  cmd.extend(extra_copybara_args)
  print(f"==> Running: {' '.join(cmd)}")
  try:
    proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
  finally:
    if temp_origin_obj:
      temp_origin_obj.cleanup()
  if proc.stdout:
    print(proc.stdout)
  if proc.stderr:
    print(proc.stderr, file=sys.stderr)

  if proc.returncode == 4:
    print(
        "Copybara reported NOOP (return code 4): changes are already exported"
        " to destination."
    )
    return "NOOP"
  elif proc.returncode != 0 and not dry_run:
    sys.exit(
        f"ERROR: Copybara export failed with return code {proc.returncode}."
    )

  gerrit_cl = None
  output = (proc.stdout or "") + (proc.stderr or "")
  m = re.search(
      r"https://googleplex-android-review\.git\.corp\.google\.com/c/platform/external/conscrypt/\+/(\d+)",
      output,
  )
  if m:
    gerrit_cl = m.group(1)

  return gerrit_cl


def step_checkout_copybara_commit(
    android_dir: pathlib.Path,
) -> None:
  """Ensures we operate on the genuine local Copybara commit at HEAD."""
  print(
      "\n--- Operating on fresh Copybara export commit at HEAD in"
      f" {android_dir} ---"
  )
  run_cmd(["git", "reset", "--hard", "master"], cwd=android_dir, check=False)
  run_cmd(["git", "log", "-1", "--oneline"], cwd=android_dir)


def find_java_binary(build_top: Optional[pathlib.Path]) -> str:
  """Finds an appropriate Java runtime binary (preferring prebuilt JDK 21)."""
  if build_top:
    jdk21 = (
        build_top / "prebuilts" / "jdk" / "jdk21" / "linux-x86" / "bin" / "java"
    )
    if jdk21.is_file():
      return str(jdk21)

    for candidate in (build_top / "prebuilts" / "jdk").glob("**/bin/java"):
      if candidate.is_file():
        return str(candidate)

  java_home = os.environ.get("JAVA_HOME")
  if java_home:
    jh_java = pathlib.Path(java_home) / "bin" / "java"
    if jh_java.is_file():
      return str(jh_java)

  artifacts_dir = os.environ.get("KOKORO_ARTIFACTS_DIR", "/tmpfs/src")
  kokoro_java = (
      pathlib.Path(artifacts_dir) / "mpm" / "java" / "jdk" / "bin" / "java"
  )
  if kokoro_java.is_file():
    return str(kokoro_java)

  return shutil.which("java") or "java"


def find_javac_binary(build_top: Optional[pathlib.Path]) -> str:
  """Finds an appropriate Java compiler binary (javac)."""
  if build_top:
    jdk21 = (
        build_top
        / "prebuilts"
        / "jdk"
        / "jdk21"
        / "linux-x86"
        / "bin"
        / "javac"
    )
    if jdk21.is_file():
      return str(jdk21)

    for candidate in (build_top / "prebuilts" / "jdk").glob("**/bin/javac"):
      if candidate.is_file():
        return str(candidate)

  java_home = os.environ.get("JAVA_HOME")
  if java_home:
    jh_javac = pathlib.Path(java_home) / "bin" / "javac"
    if jh_javac.is_file():
      return str(jh_javac)

  artifacts_dir = os.environ.get("KOKORO_ARTIFACTS_DIR", "/tmpfs/src")
  kokoro_javac = (
      pathlib.Path(artifacts_dir) / "mpm" / "java" / "jdk" / "bin" / "javac"
  )
  if kokoro_javac.is_file():
    return str(kokoro_javac)

  return shutil.which("javac") or "javac"


def build_currysrc_jar(
    build_top: Optional[pathlib.Path],
) -> Optional[pathlib.Path]:
  """Builds a self-contained currysrc.jar on the fly from Android Gitiles."""
  cached_jar = get_writable_bin_dir() / "currysrc_built.jar"
  if cached_jar.is_file() and cached_jar.stat().st_size > 1_000_000:
    return cached_jar

  print("Building currysrc.jar from Android Gitiles sources...")
  javac_bin = find_javac_binary(build_top)
  hosts = [
      "https://android.googlesource.com",
      "https://googleplex-android.googlesource.com",
  ]

  try:
    with tempfile.TemporaryDirectory(prefix="currysrc_build_") as tmpdir:
      tmp = pathlib.Path(tmpdir)
      curry_dir = tmp / "currysrc"
      curry_dir.mkdir()

      # 1. Download currysrc archive (use revision with module-api-file support)
      archive_data = None
      archive_refs = [
          "25da81f7065b464ca0a2400c21be38a3373f88da",
          "refs/heads/main",
      ]
      for host in hosts:
        for ref in archive_refs:
          url = f"{host}/platform/external/icu/+archive/{ref}/tools/srcgen/currysrc.tar.gz"
          try:
            archive_data = urllib.request.urlopen(url, timeout=30).read()
            if archive_data:
              break
          except Exception:  # pylint: disable=broad-except
            continue
        if archive_data:
          break
      if not archive_data:
        print("Failed to download currysrc.tar.gz from Gitiles.")
        return None

      with tarfile.open(fileobj=io.BytesIO(archive_data), mode="r:gz") as tf:
        if hasattr(tarfile, "data_filter"):
          tf.extractall(curry_dir, filter="data")
        else:
          tf.extractall(curry_dir)

      # Ensure Java 11 source compatibility across all JDK versions
      for jf in (curry_dir / "src" / "main" / "java").glob("**/*.java"):
        txt = jf.read_text()
        modified = False
        if "instanceof Placeholder placeholder" in txt:
          txt = txt.replace(
              "if (value instanceof Placeholder placeholder) {",
              "if (value instanceof Placeholder) { Placeholder placeholder ="
              " (Placeholder) value;",
          )
          modified = True
        if ".getFirst()" in txt:
          txt = txt.replace(".getFirst()", ".get(0)")
          modified = True
        if modified:
          jf.write_text(txt)

      # 2. Download Maven dependencies (jopt-simple, gson, guava)
      deps = [
          (
              "jopt-simple.jar",
              "platform/prebuilts/tools/+/refs/heads/main/common/m2/repository/net/sf/jopt-simple/jopt-simple/4.9/jopt-simple-4.9.jar?format=TEXT",
          ),
          (
              "gson.jar",
              "platform/prebuilts/tools/+/refs/heads/main/common/m2/repository/com/google/code/gson/gson/2.9.1/gson-2.9.1.jar?format=TEXT",
          ),
          (
              "guava.jar",
              "platform/prebuilts/tools/+/refs/heads/main/common/m2/repository/com/google/guava/guava/32.1.1-jre/guava-32.1.1-jre.jar?format=TEXT",
          ),
      ]
      libs_dir = curry_dir / "libs"
      libs_dir.mkdir(exist_ok=True)
      for name, rel_url in deps:
        dep_bytes = None
        for host in hosts:
          try:
            b64_data = urllib.request.urlopen(
                f"{host}/{rel_url}", timeout=30
            ).read()
            dep_bytes = base64.b64decode(b64_data)
            if dep_bytes:
              break
          except Exception:  # pylint: disable=broad-except
            continue
        if not dep_bytes:
          print(f"Failed to download dependency {name} from Gitiles.")
          return None
        (libs_dir / name).write_bytes(dep_bytes)

      # 3. Compile currysrc Java sources
      classes_dir = tmp / "classes"
      classes_dir.mkdir()
      jars = [p for p in libs_dir.glob("*.jar") if ".source_" not in p.name]
      cp = ":".join(str(p) for p in jars)
      java_files = [
          str(p)
          for p in (curry_dir / "src" / "main" / "java").glob("**/*.java")
      ]
      res = subprocess.run(
          [javac_bin, "-cp", cp, "-d", str(classes_dir)] + java_files,
          capture_output=True,
          text=True,
          check=False,
      )
      if res.returncode != 0:
        print(f"javac compilation of currysrc failed:\n{res.stderr}")
        return None

      # 4. Package into a single self-contained fat jar
      seen: set[str] = set()
      with zipfile.ZipFile(cached_jar, "w", zipfile.ZIP_DEFLATED) as zout:
        for p in classes_dir.rglob("*"):
          if p.is_file():
            rel = p.relative_to(classes_dir).as_posix()
            seen.add(rel)
            zout.write(p, rel)
        for j in jars:
          with zipfile.ZipFile(j, "r") as zin:
            for info in zin.infolist():
              if info.is_dir() or info.filename in seen:
                continue
              if info.filename.startswith(
                  "META-INF/"
              ) and info.filename.endswith((".SF", ".DSA", ".RSA")):
                continue
              seen.add(info.filename)
              zout.writestr(info, zin.read(info.filename))

      print(
          f"Successfully built {cached_jar} ({cached_jar.stat().st_size} bytes)"
      )
      return cached_jar
  except Exception as e:  # pylint: disable=broad-except
    print(f"Error building currysrc.jar: {e}")
    return None


def find_currysrc_jar(
    build_top: Optional[pathlib.Path],
) -> Optional[pathlib.Path]:
  """Finds a prebuilt currysrc.jar in the build tree or search locations."""
  # 1. Check explicit environment variable override
  env_jar = os.environ.get("CURRYSRC_JAR")
  if env_jar and pathlib.Path(env_jar).is_file():
    return pathlib.Path(env_jar)

  # 2. Check Kokoro gfile directory
  gfile_dir = os.environ.get("KOKORO_GFILE_DIR")
  if gfile_dir:
    gfile_jar = pathlib.Path(gfile_dir) / "currysrc.jar"
    if gfile_jar.is_file():
      return gfile_jar

  # 3. Check x20 shared location
  if X20_CURRYSRC_RO.is_file():
    return X20_CURRYSRC_RO

  # 4. Check specified build_top and all discovered Android trees
  candidate_trees: List[pathlib.Path] = []
  if build_top:
    candidate_trees.append(build_top)
  for tree in find_candidate_android_trees():
    if tree not in candidate_trees:
      candidate_trees.append(tree)

  found_jar = None
  for tree in candidate_trees:
    for rel_path in CURRYSRC_HOST_OUT_JARS:
      jar = tree / rel_path
      if jar.is_file():
        found_jar = jar
        break
    if found_jar:
      break

  if found_jar:
    return found_jar

  # 5. Build on the fly from Android Gitiles if not found locally
  built_jar = build_currysrc_jar(build_top)
  if built_jar and built_jar.is_file():
    return built_jar

  return None


def run_direct_repackage(
    android_dir: pathlib.Path, build_top: Optional[pathlib.Path]
) -> bool:
  """Runs the currysrc Java repackaging transformation safely into temporary staging directories before copying."""
  currysrc_jar = find_currysrc_jar(build_top)
  if not currysrc_jar:
    return False

  java_bin = find_java_binary(build_top)
  srcgen_dir = android_dir / "srcgen"
  repackaged_dir = android_dir / "repackaged"

  flags = [
      "--package-transformation",
      "org.conscrypt:com.android.org.conscrypt",
      "--tab-size",
      "4",
  ]

  check_files = [
      ("default-constructors.txt", "--default-constructors-file"),
      ("core-platform-api.txt", "--core-platform-api-file"),
      ("stable-core-platform-api.txt", "--stable-core-platform-api-file"),
      ("module-api.txt", "--module-api-file"),
      ("intra-core-api.txt", "--intra-core-api-file"),
      ("unsupported-app-usage.json", "--unsupported-app-usage-file"),
      ("flagged-api.json", "--flagged-api-file"),
  ]
  for fname, flag in check_files:
    fpath = srcgen_dir / fname
    if fpath.is_file() and fpath.stat().st_size > 0:
      flags.extend([flag, str(fpath)])

  modules = ["common", "openjdk", "platform", "testing"]
  source_dirs = ["src/main/java", "src/test/java"]

  total_generated = 0
  for mod in modules:
    for sdir in source_dirs:
      in_dir = android_dir / mod / sdir
      if in_dir.is_dir():
        with tempfile.TemporaryDirectory() as tmp_out:
          cmd = [
              java_bin,
              "-cp",
              str(currysrc_jar),
              "com.google.currysrc.aosp.RepackagingTransform",
              "--source-dir",
              str(in_dir),
              "--target-dir",
              tmp_out,
          ] + flags
          res = subprocess.run(cmd, capture_output=True, text=True, check=False)
          if res.returncode != 0:
            print(f"Error repackaging {mod}/{sdir}: {res.stderr}")
            return False

          out_dir = repackaged_dir / mod / sdir
          out_dir.mkdir(parents=True, exist_ok=True)
          for item in pathlib.Path(tmp_out).glob("**/*"):
            if item.is_file():
              rel = item.relative_to(tmp_out)
              dest = out_dir / rel
              dest.parent.mkdir(parents=True, exist_ok=True)
              shutil.copy2(item, dest)
              total_generated += 1

  removals = [
      repackaged_dir
      / "common/src/test/java/com/android/org/conscrypt/ConscryptSuite.java",
      repackaged_dir
      / "common/src/test/java/com/android/org/conscrypt/ConscryptJava7Suite.java",
      repackaged_dir
      / "common/src/main/java/com/android/org/conscrypt/metrics/ConscryptStatsLog.java",
      repackaged_dir
      / "openjdk/src/main/java/dalvik/annotation/optimization/FastNative.java",
      repackaged_dir
      / "openjdk/src/main/java/dalvik/annotation/optimization/CriticalNative.java",
  ]
  for r in removals:
    if r.is_file():
      r.unlink()

  print(
      f"Direct currysrc repackaging completed successfully ({total_generated}"
      " files generated)."
  )
  return True


def run_generate_android_src(
    android_dir: pathlib.Path, build_top: pathlib.Path
) -> bool:
  """Runs external/conscrypt/srcgen/generate_android_src.sh."""
  script_path = android_dir / "srcgen" / "generate_android_src.sh"
  if not script_path.is_file():
    print(f"Error: {script_path} not found.")
    return False

  env = os.environ.copy()
  env["ANDROID_BUILD_TOP"] = str(build_top)
  env["SKIP_BUILD_CURRYSRC"] = "true"
  env["ANDROID_HOST_OUT"] = str(build_top / "out" / "host" / "linux-x86")

  jdk21_bin = build_top / "prebuilts" / "jdk" / "jdk21" / "linux-x86" / "bin"
  if jdk21_bin.is_dir():
    env["PATH"] = f"{jdk21_bin}:{env.get('PATH', '')}"

  print(f"Executing {script_path}...")
  res = subprocess.run(
      [str(script_path)],
      cwd=android_dir,
      env=env,
      capture_output=True,
      text=True,
      check=False,
  )
  if res.returncode != 0:
    print(
        "generate_android_src.sh failed (exit code"
        f" {res.returncode}):\n{res.stderr}\n{res.stdout}"
    )
    return False

  print("generate_android_src.sh completed successfully.")
  return True


def step_repackage_android(
    android_dir: pathlib.Path,
    build_top: Optional[pathlib.Path],
    is_kokoro: bool = False,
) -> None:
  """Runs currysrc repackaging via generate_android_src.sh or direct repackage."""
  print("\n--- Step 3: Running Android repackaging ---")
  diff_proc = subprocess.run(
      ["git", "diff", "--name-only", "HEAD~1", "HEAD"],
      cwd=android_dir,
      capture_output=True,
      text=True,
      check=False,
  )
  changed_files = [
      f.strip() for f in (diff_proc.stdout or "").splitlines() if f.strip()
  ]
  repackage_prefixes = ("common/", "openjdk/", "platform/", "testing/")
  needs_repackage = any(
      f.startswith(repackage_prefixes) and f.endswith(".java")
      for f in changed_files
  )

  if build_top:
    success = run_generate_android_src(android_dir, build_top)
    if success:
      return
    print(
        "[Notice] generate_android_src.sh failed; falling back to direct"
        " repackaging..."
    )
  success = run_direct_repackage(android_dir, build_top)
  if success:
    return

  if not needs_repackage:
    print(
        "[Notice] No repackageable Java files modified in this change; skipping"
        " currysrc repackaging."
    )
    return

  if is_kokoro:
    sys.exit(
        "ERROR: Repackageable Java source files were modified, but currysrc.jar"
        " was not found or repackaging failed."
    )
  print("[Notice] Could not run currysrc repackaging.")


def step_format_and_commit_android(
    android_dir: pathlib.Path,
    build_top: Optional[pathlib.Path],
    skip_format: bool,
    cl: Optional[str] = None,
) -> None:
  """Stages repackaged files, formats with git-clang-format, and amends the Copybara commit."""
  print(
      "\n--- Step 4 & 5: Formatting and staging Android repository changes ---"
  )

  run_cmd(["git", "add", "-A"], cwd=android_dir)

  if not skip_format:
    git_clang_format = None
    clang_format = None
    candidate_trees: List[pathlib.Path] = []
    if build_top:
      candidate_trees.append(build_top)
    for tree in find_candidate_android_trees():
      if tree not in candidate_trees:
        candidate_trees.append(tree)

    for tree in candidate_trees:
      cand_gcf = (
          tree
          / "prebuilts"
          / "clang"
          / "host"
          / "linux-x86"
          / "clang-stable"
          / "bin"
          / "git-clang-format"
      )
      cand_cf = (
          tree
          / "prebuilts"
          / "clang"
          / "host"
          / "linux-x86"
          / "clang-stable"
          / "bin"
          / "clang-format"
      )
      if cand_gcf.is_file() and not git_clang_format:
        git_clang_format = str(cand_gcf)
      if cand_cf.is_file() and not clang_format:
        clang_format = str(cand_cf)
      if git_clang_format and clang_format:
        break

    if not git_clang_format:
      git_clang_format = shutil.which("git-clang-format")

    if git_clang_format:
      cmd = [git_clang_format]
      if clang_format:
        cmd.extend(["--binary", clang_format])
      cmd.append("HEAD~1")
      run_cmd(cmd, cwd=android_dir, check=False)
      run_cmd(["git", "add", "-A"], cwd=android_dir)
    else:
      print("Warning: git-clang-format not found. Skipping Android formatting.")

  print("Amending Copybara commit with repackaged and formatted changes...")
  # Ensure git user identity is configured in repository (needed in Kokoro VMs)
  subprocess.run(
      ["git", "config", "user.name", "Conscrypt Team"],
      cwd=android_dir,
      check=False,
  )
  subprocess.run(
      ["git", "config", "user.email", "no-reply@google.com"],
      cwd=android_dir,
      check=False,
  )

  msg = subprocess.check_output(
      ["git", "log", "-1", "--format=%B"], cwd=android_dir, text=True
  ).strip()

  # Ensure Gerrit Change-Id footer is present
  if "Change-Id:" not in msg:
    if cl:
      seed = f"conscrypt-export-{cl}"
    else:
      seed = subprocess.check_output(
          ["git", "rev-parse", "HEAD"], cwd=android_dir, text=True
      ).strip()
    change_id = "I" + hashlib.sha1(seed.encode("utf-8")).hexdigest()
    msg = f"{msg}\n\nChange-Id: {change_id}\n"

  run_cmd(
      ["git", "commit", "--amend", "--allow-empty", "-m", msg],
      cwd=android_dir,
      check=False,
  )


def step_upload_gerrit(android_dir: pathlib.Path, upload: bool) -> None:
  """Uploads to Gerrit directly."""
  if upload:
    print("\n--- Step 6: Uploading complete change to Gerrit ---")
    if shutil.which("git-remote-sso"):
      push_urls = [GERRIT_SSO_URL]
    else:
      push_urls = list(GERRIT_PUSH_URLS)

    uploaded = False
    last_err = ""
    for url in push_urls:
      print(f"==> Attempting push to {url}...")
      res = subprocess.run(
          [
              "git",
              "push",
              "-o",
              "nokeycheck",
              url,
              "HEAD:refs/for/master",
          ],
          cwd=android_dir,
          capture_output=True,
          text=True,
          check=False,
      )
      if res.stdout:
        print(res.stdout)
      if res.stderr:
        print(res.stderr, file=sys.stderr)
      if res.returncode == 0:
        uploaded = True
        break
      last_err = res.stderr.strip()

    if not uploaded:
      sys.exit(
          "ERROR: Failed to upload change to Android Gerrit across all"
          f" candidate URLs.\nLast error: {last_err}\nIf running in Kokoro,"
          " ensure the job's service account or git cookies have push access"
          " to googleplex-android/platform/external/conscrypt."
      )
    print(
        "\nSuccessfully uploaded complete (source + repackaged + formatted)"
        " change to Android Gerrit!"
    )
  else:
    print(
        f"\nLocal Android repository at '{android_dir}' is updated, repackaged,"
        " and formatted."
    )
    print("To upload to Gerrit, run:")
    print(
        f"  cd {android_dir} && git push -o nokeycheck {GERRIT_SSO_URL}"
        " HEAD:refs/for/master"
    )


def main() -> None:
  parser = argparse.ArgumentParser(
      description=(
          "Automate exporting Conscrypt changes from google3 to Android Gerrit"
          " with repackaging and clang-formatting."
      )
  )
  parser.add_argument(
      "--android_dir",
      "-a",
      type=str,
      help=(
          "Optional path to local Android external/conscrypt workspace. If"
          " omitted, auto-detects workspaces. WARNING: Unless --skip_clean is"
          " set, this executes 'git reset --hard' and 'git clean -fd' in the"
          " target directory, wiping any uncommitted changes."
      ),
  )
  parser.add_argument(
      "cl_pos",
      nargs="?",
      default=None,
      help=(
          "Optional positional CL number or revision to export (e.g."
          " 123456789)."
      ),
  )
  parser.add_argument(
      "--cl",
      type=str,
      default=None,
      help="Specific Piper CL number or revision to export (e.g. 123456789).",
  )
  parser.add_argument(
      "--copybara_bin",
      type=str,
      help=(
          "pathlib.Path to Copybara binary. Defaults to"
          " /google/data/ro/teams/copybara/copybara."
      ),
  )
  parser.add_argument(
      "--force",
      "-f",
      action="store_true",
      help=(
          "Skip interactive confirmation prompts when cleaning an explicit"
          " --android_dir."
      ),
  )
  parser.add_argument(
      "--skip_clean",
      action="store_true",
      help=(
          "Skip cleaning the local Android git repository working tree before"
          " export."
      ),
  )
  parser.add_argument(
      "--skip_format_g3",
      action="store_true",
      help="Skip running fix_format.py in google3 before export.",
  )
  parser.add_argument(
      "--skip_repackage",
      action="store_true",
      help="Skip running currysrc repackaging in the Android repository.",
  )
  parser.add_argument(
      "--skip_format_ag",
      action="store_true",
      help="Skip running git-clang-format in the Android repository.",
  )
  parser.add_argument(
      "--upload",
      "-u",
      action="store_true",
      help=(
          "Upload / push the complete commit (source + repackaged + formatted)"
          " to Android Gerrit."
      ),
  )
  parser.add_argument(
      "--folder_origin",
      action="store_true",
      default=None,
      help=(
          "Use folder.origin() workflow (export_to_ag_folder) instead of"
          " piper.origin(). Automatically enabled in Kokoro CI mode."
      ),
  )
  parser.add_argument(
      "--dry_run",
      action="store_true",
      help="Run Copybara with --dry-run and display planned actions.",
  )

  args, extra_copybara_args = parser.parse_known_args()

  setup_kokoro_git_env()

  script_path = pathlib.Path(__file__).resolve()
  main_src_dir = (
      script_path.parent.parent
      if script_path.parent.name == "scripts"
      else script_path.parent
  )
  copybara_config = main_src_dir / "copy.bara.sky"

  if not copybara_config.is_file():
    sys.exit(f"ERROR: Copybara config file not found at {copybara_config}")

  copybara_bin = get_copybara_bin(args.copybara_bin)
  target_cl = (
      args.cl
      or args.cl_pos
      or os.environ.get("KOKORO_PIPER_CHANGELIST")
      or os.environ.get("KOKORO_PIPER_CL")
  )

  is_kokoro = bool(
      os.environ.get("KOKORO_JOB_NAME") or os.environ.get("KOKORO_BUILD_NUMBER")
  )
  use_folder_origin = (
      args.folder_origin if args.folder_origin is not None else is_kokoro
  )
  google3_parent = find_google3_parent(script_path)

  print("=======================================================")
  print(" Conscrypt google3 -> Android Gerrit Automated Exporter")
  print("=======================================================")
  print(f"Google3 source dir : {main_src_dir}")
  print(f"Google3 parent dir : {google3_parent}")
  print(f"Copybara config    : {copybara_config}")
  print(
      "CL / Revision      :"
      f" {target_cl if target_cl else '(Latest HEAD / default)'}"
  )
  print(f"Kokoro CI mode     : {is_kokoro}")
  print(f"Folder origin mode : {use_folder_origin}")
  print(f"Upload to Gerrit   : {args.upload}")
  print(f"Dry run mode       : {args.dry_run}")
  print("=======================================================\n")

  android_dir, build_top, temp_dir_holder = resolve_android_and_build_top(
      args.android_dir
  )

  try:
    # Step 0: Clean local Android repo
    if not args.skip_clean:
      step_clean_android_repo(
          android_dir,
          is_explicit=bool(args.android_dir),
          force=args.force,
      )

    # Step 1: Format google3 (skipped in Kokoro as CL is already submitted)
    if not args.skip_format_g3 and not is_kokoro and not args.dry_run:
      step_format_google3(main_src_dir)

    # Step 2: Copybara export
    export_res = step_copybara_export(
        copybara_bin=copybara_bin,
        copybara_config=copybara_config,
        android_dir=android_dir,
        google3_parent=google3_parent,
        cl=target_cl,
        dry_run=args.dry_run,
        use_folder_origin=use_folder_origin,
        extra_copybara_args=extra_copybara_args,
        is_kokoro=is_kokoro,
    )

    if export_res == "NOOP":
      print(
          "\n[NOOP] Changes are already exported to destination. Exiting"
          " cleanly."
      )
      return

    if args.dry_run:
      print("\n[Dry Run] Copybara dry-run completed successfully.")
      return

    # Step 3: Ensure we operate on the fresh Copybara export commit at HEAD
    step_checkout_copybara_commit(android_dir)

    # Step 4: Repackage Android safely
    if not args.skip_repackage:
      step_repackage_android(android_dir, build_top, is_kokoro=is_kokoro)

    # Step 5: Format Android with git-clang-format and Amend Copybara commit
    step_format_and_commit_android(
        android_dir=android_dir,
        build_top=build_top,
        skip_format=args.skip_format_ag,
        cl=target_cl,
    )

    # Step 6: Upload to Gerrit
    step_upload_gerrit(android_dir, upload=args.upload)

  finally:
    if temp_dir_holder:
      temp_dir_holder.cleanup()


if __name__ == "__main__":
  main()
