# Path Traversal in File Download Endpoint

## Summary

The file download endpoint served by `download_file` in `src/app/files.py`
(around line 58) is vulnerable to path traversal in version 2.4.1. It takes
the `name` query parameter from `GET /files?name=<filename>` and joins it
directly onto the configured download directory with no sanitization, so a
request such as `GET /files?name=../../etc/passwd` escapes the intended
folder and returns arbitrary server files.

## Details

The handler builds the path with `os.path.join(DOWNLOAD_DIR, name)` and opens
the result for reading. There is no check rejecting `..` segments, no
normalization with `os.path.abspath` followed by a prefix comparison, and no
allowlist of permitted filenames. Any authenticated user — and the route
appears to require no authentication at all — can walk up the directory tree
by adding further `../` segments to the parameter.

## Impact

Severity: CVSS 7.5 (High). I reproduced this locally by requesting
`?name=../../etc/passwd` and receiving the system password file in the
response body, confirming arbitrary file read. Configuration files,
application secrets, and any other files readable by the server process are
exposed the same way.

## Recommendation

Resolve the joined path and verify it stays under the download directory,
rejecting anything else with HTTP 403, or serve files by opaque identifier
instead of raw names. A regression test requesting `../` sequences and
asserting rejection would cover the fix.
