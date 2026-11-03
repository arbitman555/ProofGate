# Database Backup Exporter Exposes Raw Credentials

## Summary

The demo target app (demo-v1) ships an admin backup exporter,
`export_database` in `admin/backup.py` (around line 25),
which writes a full dump of `app.db` — including password hashes and
emails — to a world-readable file every night. Anyone with filesystem read
access, or anyone who guesses the timestamped dump URL, can download every
credential at once.

## Details

`export_database` opens the sqlite database, dumps all tables with
`iterdump()`, and saves the result under `public/backups/<date>.sql` with no
access control. The `admin/backup.py` module is imported at startup and the
export runs on a timer, so fresh dumps appear daily. The backup directory is
served by the same static download path as other public files.

## Impact

Severity: CVSS 9.8 (Critical). I reproduced this against demo-v1 by listing
the backup directory and downloading the latest dump, confirming that all
user emails and password hashes are exposed without authentication.

## Recommendation

Stop writing dumps into the served tree, encrypt backups at rest, and gate
any export behind the admin authorization check.
