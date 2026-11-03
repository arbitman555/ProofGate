# Critical JWT Bypass in Authentication Handler

## Summary

During an assessment of the demo target app (demo-v1), I found a critical
authentication bypass in `verify_jwt_signature` inside `app/auth/jwt_verify.py`
(around line 44). The function decodes the JWT from the `Authorization`
header but accepts the `none` algorithm, so a forged token with no signature
is treated as valid for any user.

## Details

`verify_jwt_signature` in `app/auth/jwt_verify.py` calls the token parser
with `algorithms=["HS256", "none"]`, and when the algorithm header reads
`none` it skips signature verification entirely and returns the embedded
claims. There is no allowlist of trusted issuers either, so any attacker can
mint a token for `admin` and call authenticated endpoints with it.

## Impact

Severity: CVSS 9.1 (Critical). I reproduced this locally against demo-v1 by
sending `Authorization: Bearer <unsigned admin token>` and receiving an
admin session in return, confirming full account takeover with no secret.

## Recommendation

Reject the `none` algorithm, pin `HS256` with the server-side secret, and
validate `iss`/`exp` before trusting any claim.
