---
name: conscrypt-formatting
description: >-
  Automatically formats C++, Java, and C source files in the Conscrypt directory using a project-specific formatting tool. Use when you have modified any C++, Java, or C files under `third_party/java_src/conscrypt/` and need to ensure they comply with project style before committing or submitting. Don't use for general Google3 formatting (use the standard `g4 fix` or `hg fix` instead unless working in Conscrypt).
---

# Conscrypt Formatting

When modifying C++, C, or Java files in the Conscrypt project, you **MUST** run
the project's custom formatting script. The standard `g4 fix` or global
formatters are not sufficient as Conscrypt uses a specific configuration.

## Critical Rules

1.  **Run after modifications**: Always run the formatter *after* making any
    changes to `.java`, `.cc`, `.h`, `.cpp`, or `.c` files in Conscrypt, and
    *before* creating a CL, uploading, or submitting.
2.  **Files must be opened**: The formatting script only processes files that
    are currently **opened for edit** in your VCS (e.g., via `g4 edit`, `hg
    edit`, etc.). Ensure your modified files are opened before running the
    script.

## How to Format

Run the Python script located in the Conscrypt root directory:

```bash
python3 third_party/java_src/conscrypt/fix_format.py
```
