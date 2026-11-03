# Unauthenticated Config Disclosure via Download Parameter

## Summary

Anyone can read the server's own source code through the download feature in
the demo target app (demo-v1). `GET /download?file=` is served by the
`download` function in `app.py`, and because the `file`
value is trusted as a relative path, asking for `..` sequences walks out of
the public folder: `GET /download?file=../app.py` returns the running
application code, no login required.

## Details

The `download` function concatenates the public directory with the raw
`file` argument and hands the result to the file sender. No allowlist, no
`..` rejection, and no post-join containment check stand in the way, so each
additional `../` climbs one more level. Application secrets, the sqlite
database file, and host configuration readable by the process are all
reachable by the same technique.

## Impact

Severity: CVSS 8.6 (High). I confirmed the exposure on a local demo-v1
checkout: requesting `?file=../app.py` returned the full Flask application
source, and `?file=notes.txt` style probes of sibling paths behave the same
way, proving the directory boundary is not enforced.

## Recommendation

Constrain served files to the public directory (normalize plus prefix
check, or serve by opaque id) and deny everything else. Cover it with a
test that climbs with `../` and expects HTTP 403.
