# Assessment Note: Download Endpoint Already Normalizes Paths

## Summary

I audited the file download endpoint served by `download` in
`app.py` (around line 116, demo-v1) for path traversal and
found it NOT vulnerable. The handler normalizes the joined path with
`os.path.abspath` and verifies the result stays under the public directory
with a `commonpath` prefix comparison, returning HTTP 403 for anything that
escapes.

## Details

Before serving, the code resolves `os.path.abspath(os.path.join(PUBLIC_DIR,
filename))` and compares it against the resolved base directory. Requests
such as `?file=../../app.py` hit the prefix check and are rejected, and only
files physically inside the public folder are ever passed to `send_file`.

## Impact

Severity: none. I verified this against demo-v1 by requesting
`?file=../app.py` and receiving HTTP 403, confirming the escape is blocked.
No further action is needed for this endpoint.

## Recommendation

No fix required. Keep the existing regression test that asserts `../`
sequences are rejected so a future refactor cannot silently drop the check.
