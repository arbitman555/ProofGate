# Missing Password-Length Validation in Login Handler

## Summary

The login handler `authenticate_user` in `src/app/auth.py` (around line 142)
does not enforce any minimum password length before checking credentials
against the database in version 2.4.1. A single-character password is passed
straight through to the credential comparison, which means the documented
eight-character minimum policy is never applied at the point of login.

## Details

Registration correctly rejects short passwords, but the login path was
apparently overlooked: `authenticate_user` reads `username` and `password`
from the request body and queries the user store without first validating the
password length. There is no `len(password) < 8` guard anywhere in the
function, so weak or truncated passwords submitted by mistake are processed
as normal login attempts instead of being rejected with a validation error.

## Impact

Severity: CVSS 5.3 (Medium). The practical risk is limited — short passwords
cannot match a stored hash unless the account itself has a weak password —
but the inconsistency undermines the registration policy and generates
misleading audit logs, since failed short-password attempts are recorded as
ordinary authentication failures rather than validation rejections.

## Recommendation

Add the same minimum-length check used at registration to the top of
`authenticate_user`, returning HTTP 400 for passwords shorter than eight
characters. A unit test submitting a one-character password and asserting a
400 response would lock the behavior in place going forward.
