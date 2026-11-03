# SQL Injection in User Search Endpoint

## Summary

The user search endpoint served by `search` in `app.py`
(around line 133, demo-v1) is vulnerable to SQL injection. It takes the `q`
query parameter from `GET /search?q=<text>` and interpolates it into a
sqlite statement with `%` string formatting, so a request such as
`GET /search?q=' OR '1'='1` alters the query logic and returns every row.

## Details

The handler builds its statement as `"... LIKE '%%%s%%'" % q` and executes
it directly. There is no parameter binding and no escaping of quote
characters, so attacker-controlled SQL breaks out of the string literal.
The query runs against the `users` table, exposing all usernames and bios.

## Impact

Severity: CVSS 8.2 (High). I reproduced this locally by requesting
`?q=' OR '1'='1` and receiving all three seeded users in the response body,
confirming the injection. The same sink could be used to probe other tables
with UNION-style payloads.

## Recommendation

Pass `q` as a bound parameter (`... LIKE ?` with `("%" + q + "%",)`) and add
a regression test asserting an injection payload returns no rows.
