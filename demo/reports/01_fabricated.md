# Critical OAuth Signature Bypass — Immediate Action Required

## Summary

During a routine assessment of the login flow (version 2.4.1), I discovered a
critical authentication bypass in `verify_oauth_signature` inside
`src/auth/oauth_verify.py` (line 87). The function compares the HMAC of the
incoming OAuth callback state parameter against the session value, but it uses
a plain `==` comparison instead of a constant-time compare, and worse, it
returns `True` early when the `state` parameter is absent entirely.

## Impact

Severity: CVSS 9.8 (Critical). An unauthenticated remote attacker can forge an
OAuth callback with an empty `state` field and the function still returns
`True`, granting a fully authenticated session as any user whose email is
known. I confirmed this against the staging deployment by replaying a
callback with `state=` empty and receiving a valid session cookie in return.

## Affected code

`src/auth/oauth_verify.py`, function `verify_oauth_signature`, around line
87, in release 2.4.1. The vulnerable branch is the `if not state: return True`
guard that was apparently added for local development and never removed.

## Recommendation

Replace the comparison with `hmac.compare_digest` and reject missing `state`
values outright. Adding a short regression test that posts a callback with an
empty state and asserts rejection would prevent recurrence. Please prioritize
this before the next release, as exploit code would be trivial to weaponize.
