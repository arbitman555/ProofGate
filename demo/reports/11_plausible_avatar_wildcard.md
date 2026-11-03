# Debug Wildcard in Avatar Allowlist Serves Any File

## Summary

The avatar endpoint served by `avatar` in `app.py` (around
line 159, demo-v1) can be abused to serve arbitrary files. The
`ALLOWED_AVATARS` set checked by the handler contains a debug wildcard entry
left over from development, so a request such as
`GET /avatar?name=debug&file=../../app.py` matches the wildcard branch and
returns files from anywhere on the server.

## Details

The handler tests membership in `ALLOWED_AVATARS`, which currently holds
`cat.png`, `dog.png`, `parrot.png`, and a `*` debug entry documented as
"remove before release". When the wildcard branch matches, the handler
serves the secondary `file` parameter with no further validation, so `..`
segments in that parameter escape the avatar directory.

## Impact

Severity: CVSS 7.5 (High). I reproduced this against demo-v1 by requesting
the debug wildcard with a traversal payload and receiving the application
source, confirming arbitrary file read through the avatar endpoint.

## Recommendation

Delete the wildcard entry so only the three known avatars are served, and
add a test asserting that unknown names and traversal strings return 404.
