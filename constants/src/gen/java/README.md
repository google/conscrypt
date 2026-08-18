# Updating the blocklist based on Chromium's source code

1. Copy the latest version of `cert_verify_proc_blocklist.inc` from [Chromium's
   repository](https://source.chromium.org/chromium/chromium/src/+/main:net/cert/cert_verify_proc_blocklist.inc)
   into this directory.
2. Build, flash and run: `atest CtsLibcoreTestCases`.

