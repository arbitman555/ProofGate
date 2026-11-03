# User Search Endpoint Leaks Email Addresses

## Summary

The user search endpoint served by `search` in `app.py`
(around line 133, demo-v1) leaks email addresses. A query such as
`GET /search?q=ali` returns the full user row, including the `email` field,
so anyone can harvest the registered email of every user by enumerating
single-letter queries.

## Details

The handler runs its username query against the `users` table and serializes
each row with all four columns (`id`, `username`, `email`, `bio`). There is
no projection down to the public fields and no masking of the email column,
so the JSON response body for `?q=a` contains `alice@example.com` and every
other matching address.

## Impact

Severity: CVSS 5.3 (Medium). I reproduced this against demo-v1 by searching
`?q=o` and collecting the emails of both `bob` and `carol` from the
response, confirming bulk address harvesting with no authentication.

## Recommendation

Serialize search results through the public view only (username and bio),
and add a test asserting the `email` key is absent from search responses.
