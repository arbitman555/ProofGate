# Path Traversal in Avatar Endpoint

## Summary

The avatar endpoint served by `avatar` in `app.py` (around
line 159, demo-v1) is vulnerable to path traversal. It takes the `name`
query parameter from `GET /avatar?name=<name>` and serves the matching file,
so a request such as `GET /avatar?name=../../etc/passwd` escapes the avatar
directory and returns arbitrary server files.

## Details

The handler builds its file path by joining the avatar directory with the
user-supplied `name` value and opens the result for reading. There is no
rejection of `..` segments and no allowlist check before the file is served,
so adding further `../` segments walks up the directory tree.

## Impact

Severity: CVSS 7.5 (High). I reproduced this against demo-v1 by requesting
`?name=../../app.py` and receiving the application source in the response
body, confirming arbitrary file read as the server user.

## Recommendation

Validate `name` against the fixed set of known avatars and reject anything
else with HTTP 404 before touching the filesystem.
