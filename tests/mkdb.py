#!/usr/bin/env python3
"""Create a DCF-ID-shaped identity.db for the tests.

    mkdb.py DB ROW...

ROW is a JSON array: [username, last_ip, last_seen, data_used, balance, is_vip]

  last_ip    a JSON string / number / null, or {"hex": "..."} for a BLOB.
  last_seen  null                    SQL NULL
             "now"                   Utc::now().to_rfc3339(), as DCF-ID writes it:
                                     2026-10-09T01:22:33.123456789+00:00
             "ago:N"                 the same, N seconds ago
             "space_ago:N"           'YYYY-MM-DD HH:MM:SS', N seconds ago (SQLite's own form)
             "offset_now:+05:30"     now, written as local time with that offset
             "sameday_stale"         today 00:00:01 UTC -- more than an hour old yet on
                                     today's date. Exit 77 if the clock makes that false.
             "raw:TEXT"              TEXT verbatim

The schema is the CREATE TABLE in DCF-ID's main.rs.
"""
import datetime
import json
import os
import sqlite3
import sys

SCHEMA = """CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    access_token TEXT UNIQUE NOT NULL,
    discord_id TEXT UNIQUE,
    data_used INTEGER DEFAULT 0,
    account_balance REAL DEFAULT 0.00,
    last_reset_date TEXT DEFAULT '',
    last_ip TEXT,
    last_seen TEXT,
    created_at TEXT,
    is_vip INTEGER DEFAULT 0
)"""


def rfc3339(dt):
    """chrono's to_rfc3339(): nine fractional digits, +00:00."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + ".%09d" % (dt.microsecond * 1000 + 123) + "+00:00"


def seen(spec):
    now = datetime.datetime.now(datetime.timezone.utc)
    if spec is None:
        return None
    if spec == "now":
        return rfc3339(now)
    if spec.startswith("ago:"):
        return rfc3339(now - datetime.timedelta(seconds=int(spec[4:])))
    if spec.startswith("space_ago:"):
        return (now - datetime.timedelta(seconds=int(spec[10:]))).strftime("%Y-%m-%d %H:%M:%S")
    if spec.startswith("offset_now:"):
        off = spec[len("offset_now:"):]
        sign = -1 if off[0] == "-" else 1
        hh, mm = off[1:].split(":")
        delta = datetime.timedelta(hours=int(hh), minutes=int(mm)) * sign
        return (now + delta).strftime("%Y-%m-%dT%H:%M:%S") + ".123456789" + off
    if spec == "sameday_stale":
        midnight = now.replace(hour=0, minute=0, second=1, microsecond=0)
        if (now - midnight).total_seconds() < 3700:
            sys.exit(77)
        return rfc3339(midnight)
    if spec.startswith("raw:"):
        return spec[4:]
    raise SystemExit("mkdb: bad last_seen spec %r" % spec)


def main(argv):
    db = argv[1]
    if os.path.exists(db):
        os.unlink(db)
    con = sqlite3.connect(db)
    con.execute(SCHEMA)
    for i, raw in enumerate(argv[2:]):
        name, ip, ls, used, bal, vip = json.loads(raw)
        if isinstance(ip, dict):
            ip = bytes.fromhex(ip["hex"])
        con.execute(
            "INSERT INTO users(username, password_hash, access_token, data_used, account_balance,"
            " last_ip, last_seen, created_at, is_vip) VALUES (?,?,?,?,?,?,?,?,?)",
            (name, "x", "tok%d" % i, used, bal, ip, seen(ls), seen("now"), vip),
        )
    con.commit()
    con.close()


if __name__ == "__main__":
    main(sys.argv)
