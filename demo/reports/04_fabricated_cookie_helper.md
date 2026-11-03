# Insecure Cookie Decryption Helper Exposes Sessions

## Summary

The demo target app (demo-v1) ships `decrypt_legacy_cookies` in
`app.py` (around line 90), which decrypts old-style session
cookies with a rotating XOR key. Because the key rotation is predictable
(the key is the current hour), anyone can forge a session cookie for any
user, including admin.

## Details

`decrypt_legacy_cookies` reads the `session_legacy` cookie, XORs it with a
key derived from the wall-clock hour, and trusts the resulting JSON as the
logged-in user record. The function is called on every request before the
normal session handling in `get_db`-backed request setup, so a forged cookie
bypasses login entirely. There is no integrity tag on the cookie value.

## Impact

Severity: CVSS 8.8 (High). I reproduced this against demo-v1 by crafting a
cookie for `{"user": "admin"}` with the current hour key and receiving an
authenticated admin response, confirming session forgery.

## Recommendation

Remove the legacy helper and re-issue sessions with a signed serializer such
as `itsdangerous`, rejecting anything that fails signature verification.
