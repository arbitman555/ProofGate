# Missing Authorization on Admin User Export

## Summary

The admin export endpoint served by `admin_export` in
`app.py` (around line 147, demo-v1) performs no
authorization check. A request to `GET /admin/export` with no token,
session, or role returns the full `users` table, including every email
address.

## Details

The handler queries `SELECT id, username, email, bio FROM users` and returns
all rows as JSON. There is no check of an `X-Admin-Token` header, no session
lookup, and no role test anywhere in the function, so any anonymous visitor
can dump the user list.

## Impact

Severity: CVSS 6.5 (Medium). I reproduced this locally by requesting
`/admin/export` with no credentials and receiving all three seeded users
with their emails, confirming unauthenticated bulk data access.

## Recommendation

Require a server-side admin credential (for example an `X-Admin-Token`
header) and return HTTP 403 otherwise. A regression test requesting the
endpoint without the token and asserting rejection would cover the fix.
