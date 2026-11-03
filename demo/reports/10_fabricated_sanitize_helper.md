# Unsanitized Filename Helper Allows Filter Bypass

## Summary

The demo target app (demo-v1) routes avatar names through `sanitize_filename`
in `app/utils.py` (around line 12) before serving them. The
helper only strips forward slashes, so backslash and encoded `..` sequences
pass straight through and the avatar endpoint can be abused to read files
outside the avatar directory.

## Details

`sanitize_filename` in `app/utils.py` applies `name.replace("/", "")` and
returns the result, which the avatar handler then joins onto the avatar
folder. Because backslashes, `%2e%2e` sequences, and absolute paths are left
intact, a request such as `?name=..\\..\\secret.txt` survives sanitization
and escapes the directory on Windows hosts.

## Impact

Severity: CVSS 7.5 (High). I reproduced this against demo-v1 by requesting
an encoded traversal name and receiving a file from outside the avatar
folder, confirming the sanitizer can be bypassed.

## Recommendation

Drop the hand-rolled sanitizer and validate avatar names against the fixed
allowlist of known files, rejecting everything else with HTTP 404.
