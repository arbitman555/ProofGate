# Path Traversal in File Download Endpoint

## Summary

The file download endpoint served by `download` in `app.py`
(around line 116, demo-v1) is vulnerable to path traversal. It takes the
`file` query parameter from `GET /download?file=<name>` and joins it
directly onto the configured public directory with no sanitization, so a
request such as `GET /download?file=../../app.py` escapes the intended
folder and returns arbitrary server files.

## Details

The handler builds the path with `os.path.join(PUBLIC_DIR, filename)` and
serves the result. There is no check rejecting `..` segments, no
normalization with `os.path.abspath` followed by a prefix comparison, and no
allowlist of permitted filenames.

## Impact

Severity: CVSS 7.5 (High). I reproduced this locally by requesting
`?file=../app.py` and receiving the application source in the response body,
confirming arbitrary file read. Configuration files and anything else
readable by the server process are exposed the same way.

## Recommendation

Resolve the joined path and verify it stays under the public directory,
rejecting anything else with HTTP 403. A regression test requesting `../`
sequences and asserting rejection would cover the fix.
