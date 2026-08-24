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
import getpass
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_COPYBARA_BIN = "/google/data/ro/teams/copybara/copybara"
GERRIT_SSO_URL = "sso://googleplex-android/platform/external/conscrypt"


def run_cmd(
    cmd: List[str],
    cwd: Optional[pathlib.Path] = None,
    env: Optional[Dict[str, str]] = None,
    check: bool = True,
) -> subprocess.CompletedProcess:
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

  if pathlib.Path(DEFAULT_COPYBARA_BIN).is_file():
    return DEFAULT_COPYBARA_BIN

  which_copybara = shutil.which("copybara")
  if which_copybara:
    return which_copybara

  sys.exit(
      f"ERROR: Copybara executable not found at '{DEFAULT_COPYBARA_BIN}' or in"
      " PATH."
  )


def get_current_user() -> str:
  """Extracts username using getpass or path fallback."""
  try:
    return getpass.getuser()
  except Exception:
    pass

  parts = pathlib.Path(__file__).resolve().parts
  if "cloud" in parts:
    idx = parts.index("cloud")
    if idx + 1 < len(parts):
      return parts[idx + 1]

  return "miguelaranda"


def resolve_android_and_build_top(
    explicit_dir: Optional[str],
) -> Tuple[
    pathlib.Path,
    Optional[pathlib.Path],
    Optional[tempfile.TemporaryDirectory],
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

  # Check local home directory checkouts first
  user = get_current_user()
  home_candidates = [
      pathlib.Path(f"/usr/local/google/home/{user}/main/external/conscrypt"),
      pathlib.Path(f"/usr/local/google/home/{user}/external/conscrypt"),
      pathlib.Path.home() / "main" / "external" / "conscrypt",
  ]
  for cand in home_candidates:
    if (cand / ".git").is_dir():
      bt = (
          cand.parent.parent
          if (cand.parent.parent / "tools" / "currysrc").is_dir()
          else None
      )
      return cand.resolve(), bt.resolve() if bt else None, None

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

  print("\nCreating temporary clone of Android Gerrit repo...")
  temp_dir_obj = tempfile.TemporaryDirectory(prefix="conscrypt_export_")
  temp_path = pathlib.Path(temp_dir_obj.name)
  run_cmd(["git", "clone", "--depth", "1", GERRIT_SSO_URL, str(temp_path)])
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
    cl: Optional[str],
    dry_run: bool,
    extra_copybara_args: List[str],
) -> Optional[str]:
  """Runs Copybara export_to_ag workflow and extracts the active Gerrit review URL or CL number."""
  print("\n--- Step 2: Running Copybara export_to_ag ---")

  cmd = [
      copybara_bin,
      str(copybara_config),
      "export_to_ag",
  ]

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

  print(f"--- Resetting {android_dir} master branch to goog/master ---")
  run_cmd(["git", "fetch", "goog", "master"], cwd=android_dir, check=False)
  run_cmd(["git", "checkout", "master"], cwd=android_dir, check=False)
  run_cmd(
      ["git", "reset", "--hard", "goog/master"], cwd=android_dir, check=False
  )
  run_cmd(
      ["git", "config", "receive.denyCurrentBranch", "ignore"],
      cwd=android_dir,
      check=False,
  )

  cmd.extend(extra_copybara_args)
  print(f"==> Running: {' '.join(cmd)}")
  proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
  if proc.stdout:
    print(proc.stdout)
  if proc.stderr:
    print(proc.stderr, file=sys.stderr)

  if proc.returncode == 4:
    print(
        "Copybara reported NOOP (return code 4): changes are already exported"
        " to destination."
    )
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

  return shutil.which("java") or "java"


def find_currysrc_jar(
    build_top: Optional[pathlib.Path],
) -> Optional[pathlib.Path]:
  """Finds a prebuilt currysrc.jar in the build tree if available."""
  if not build_top:
    return None

  paths = [
      build_top / "out" / "host" / "linux-x86" / "framework" / "currysrc.jar",
      build_top
      / "out"
      / "soong"
      / "host"
      / "linux-x86"
      / "framework"
      / "currysrc.jar",
      build_top
      / "out"
      / "soong"
      / ".intermediates"
      / "external"
      / "icu"
      / "tools"
      / "srcgen"
      / "currysrc"
      / "currysrc"
      / "linux_glibc_common"
      / "combined"
      / "currysrc.jar",
  ]
  for p in paths:
    if p.is_file():
      return p

  for p in (build_top / "out").glob("**/currysrc.jar"):
    if p.is_file():
      return p

  return None


def run_direct_repackage(
    android_dir: pathlib.Path, build_top: pathlib.Path
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
    android_dir: pathlib.Path, build_top: Optional[pathlib.Path]
) -> None:
  """Runs currysrc repackaging via generate_android_src.sh."""
  print("\n--- Step 3: Running Android repackaging ---")
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

  print("[Notice] Could not run currysrc repackaging.")


def step_format_and_commit_android(
    android_dir: pathlib.Path,
    build_top: Optional[pathlib.Path],
    skip_format: bool,
) -> None:
  """Stages repackaged files, formats with git-clang-format, and amends the Copybara commit."""
  print(
      "\n--- Step 4 & 5: Formatting and staging Android repository changes ---"
  )

  run_cmd(["git", "add", "-A"], cwd=android_dir)

  if not skip_format:
    git_clang_format = None
    clang_format = None
    if build_top:
      cand_gcf = (
          build_top
          / "prebuilts"
          / "clang"
          / "host"
          / "linux-x86"
          / "clang-stable"
          / "bin"
          / "git-clang-format"
      )
      cand_cf = (
          build_top
          / "prebuilts"
          / "clang"
          / "host"
          / "linux-x86"
          / "clang-stable"
          / "bin"
          / "clang-format"
      )
      if cand_gcf.is_file():
        git_clang_format = str(cand_gcf)
      if cand_cf.is_file():
        clang_format = str(cand_cf)

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
  msg = subprocess.check_output(
      ["git", "log", "-1", "--format=%B"], cwd=android_dir, text=True
  ).strip()
  run_cmd(
      ["git", "commit", "--amend", "--allow-empty", "-m", msg],
      cwd=android_dir,
      check=False,
  )


def step_upload_gerrit(android_dir: pathlib.Path, upload: bool) -> None:
  """Uploads to Gerrit directly."""
  if upload:
    print("\n--- Step 6: Uploading complete change to Gerrit ---")
    run_cmd(
        [
            "git",
            "push",
            "-o",
            "nokeycheck",
            GERRIT_SSO_URL,
            "HEAD:refs/for/master",
        ],
        cwd=android_dir,
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
      help="Optional positional CL number or revision to export (e.g. 123456789).",
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
      "--dry_run",
      action="store_true",
      help="Run Copybara with --dry-run and display planned actions.",
  )

  args, extra_copybara_args = parser.parse_known_args()

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
  android_dir, build_top, temp_dir_holder = resolve_android_and_build_top(
      args.android_dir
  )

  target_cl = args.cl or args.cl_pos

  print("=======================================================")
  print(" Conscrypt google3 -> Android Gerrit Automated Exporter")
  print("=======================================================")
  print(f"Google3 source dir : {main_src_dir}")
  print(f"Copybara config    : {copybara_config}")
  print(
      "CL / Revision      :"
      f" {target_cl if target_cl else '(Latest HEAD / default)'}"
  )
  print(f"Android repo dir   : {android_dir}")
  print(f"Android build top  : {build_top if build_top else '(None)'}")
  print(f"Upload to Gerrit   : {args.upload}")
  print(f"Dry run mode       : {args.dry_run}")
  print("=======================================================\n")

  try:
    # Step 0: Clean local Android repo
    if not args.skip_clean:
      step_clean_android_repo(
          android_dir,
          is_explicit=bool(args.android_dir),
          force=args.force,
      )

    # Step 1: Format google3
    if not args.skip_format_g3 and not args.dry_run:
      step_format_google3(main_src_dir)

    # Step 2: Copybara export
    _ = step_copybara_export(
        copybara_bin=copybara_bin,
        copybara_config=copybara_config,
        android_dir=android_dir,
        cl=target_cl,
        dry_run=args.dry_run,
        extra_copybara_args=extra_copybara_args,
    )

    if args.dry_run:
      print("\n[Dry Run] Copybara dry-run completed successfully.")
      return

    # Step 3: Ensure we operate on the fresh Copybara export commit at HEAD
    step_checkout_copybara_commit(android_dir)

    # Step 4: Repackage Android safely
    if not args.skip_repackage:
      step_repackage_android(android_dir, build_top)

    # Step 5: Format Android with git-clang-format and Amend Copybara commit
    step_format_and_commit_android(
        android_dir=android_dir,
        build_top=build_top,
        skip_format=args.skip_format_ag,
    )

    # Step 6: Upload to Gerrit
    step_upload_gerrit(android_dir, upload=args.upload)

  finally:
    if temp_dir_holder:
      temp_dir_holder.cleanup()


if __name__ == "__main__":
  main()
