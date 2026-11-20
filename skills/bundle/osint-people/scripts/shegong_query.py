#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本地离线库字段检索（不发网络请求）。

支持：*.sqlite / *.db（自动找表与字段）、*.csv / *.txt（冒号或制表符分隔）。
每次查询追加一行到 ledger.jsonl：时间、字段、值、命中条数、库指纹（不写结果明文）。

用法：
  python shegong_query.py --db SHEGONG_DB --field email --value user@corp.com
  python shegong_query.py --db SHEGONG_DB --field domain --value corp.com --limit 200
  python shegong_query.py --db SHEGONG_DB --dry-run          # 只看结构与字段名
  python shegong_query.py --db SHEGONG_DB --field phone --value 13800000000 --show-keys
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

FIELDS = ["email", "phone", "qq", "weibo", "github", "company", "domain", "name", "hash"]
HEADER_HINTS = {"email": ["email", "mail", "邮箱", "邮件"],
                "phone": ["phone", "mobile", "tel", "手机", "电话"],
                "qq": ["qq"], "weibo": ["weibo", "微博"],
                "github": ["github", "login", "user"],
                "company": ["company", "org", "公司", "单位", "source"],
                "domain": ["domain", "site", "域名"],
                "name": ["name", "realname", "姓名"],
                "hash": ["hash", "passwd", "password", "md5", "sha1"]}


def db_fingerprint(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def find_sqlite(path: Path):
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    tables = [r[0] for r in con.execute(
        "select name from sqlite_master where type='table' and name not like 'sqlite_%'")]
    return con, tables


def columns(con, table: str):
    return [r[1] for r in con.execute(f'pragma table_info("{table}")')]


def pick_column(cols, field: str):
    if not field:
        return None
    names = HEADER_HINTS.get(field, [field])
    low = {c.lower(): c for c in cols}
    for n in names:
        for k, v in low.items():
            if n in k:
                return v
    return None


def query_sqlite(path: Path, field: str, value: str, limit: int, dry: bool, show_keys: bool):
    con, tables = find_sqlite(path)
    report = {"kind": "sqlite", "tables": []}
    hits = 0
    for t in tables:
        cols = columns(con, t)
        col = pick_column(cols, field)
        report["tables"].append({"table": t, "columns": cols, "field_column": col})
        if dry or not col:
            continue
        sql = f'select * from "{t}" where "{col}" = ? limit ?'
        try:
            rows = con.execute(sql, (value, limit - hits)).fetchall()
        except sqlite3.Error as e:
            report.setdefault("errors", []).append(f"{t}: {e}")
            continue
        for r in rows:
            hits += 1
            if show_keys:
                print(json.dumps(dict(zip(cols, r)), ensure_ascii=False, default=str))
            if hits >= limit:
                break
        if hits >= limit:
            break
    report["hits"] = hits
    return report


def sniff_delim(line: str):
    for d in ("\t", ":", "|", ","):
        if d in line:
            return d
    return None


def query_text(path: Path, field: str, value: str, limit: int, dry: bool, show_keys: bool):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        first = f.readline()
        delim = sniff_delim(first)
        f.seek(0)
        header = None
        if delim:
            header = [h.strip().lower() for h in first.split(delim)]
        col_idx = None
        if header:
            for i, h in enumerate(header):
                if any(n in h for n in HEADER_HINTS.get(field, [field])):
                    col_idx = i
                    break
        report = {"kind": "text", "delimiter": delim, "header": header,
                  "field_column_index": col_idx, "hits": 0}
        if dry:
            return report
        hits = 0
        start = 1 if header and col_idx is not None else 0
        for ln, line in enumerate(f, start=start):
            if hits >= limit:
                break
            line = line.rstrip("\n")
            if not line:
                continue
            if delim:
                parts = line.split(delim)
                cand = parts[col_idx] if col_idx is not None and col_idx < len(parts) else line
            else:
                cand = line
            if value and value in cand:
                hits += 1
                if show_keys:
                    print(f"line{ln}: {line[:300]}")
        report["hits"] = hits
    return report


def main():
    ap = argparse.ArgumentParser(description="离线库字段检索（只读本机文件）")
    ap.add_argument("--db", required=True, help="库文件：.sqlite/.db/.csv/.txt")
    ap.add_argument("--field", choices=FIELDS)
    ap.add_argument("--value")
    ap.add_argument("--limit", type=int, default=200)
    ap.add_argument("--dry-run", action="store_true", help="只看结构与字段名，不查值")
    ap.add_argument("--show-keys", action="store_true", help="打印命中行（默认只计数）")
    ap.add_argument("--ledger", default="ledger.jsonl")
    a = ap.parse_args()

    p = Path(a.db).expanduser()
    if not p.exists():
        sys.exit(f"库不存在: {p}")
    if not a.dry_run and (not a.field or not a.value):
        sys.exit("查询需要 --field 与 --value；只看结构用 --dry-run")

    t0 = time.time()
    if p.suffix.lower() in (".sqlite", ".db", ".sqlite3"):
        rep = query_sqlite(p, a.field or "", a.value or "", a.limit, a.dry_run, a.show_keys)
    else:
        rep = query_text(p, a.field or "", a.value or "", a.limit, a.dry_run, a.show_keys)

    rec = {
        "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "db": str(p), "db_fingerprint": db_fingerprint(p),
        "field": a.field, "value": a.value,
        "hits": rep.get("hits", 0), "limit": a.limit,
        "show_keys": bool(a.show_keys), "ms": int((time.time() - t0) * 1000),
    }
    with open(a.ledger, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(json.dumps(rep, ensure_ascii=False, indent=2, default=str))
    print(f"\n命中 {rep.get('hits', 0)} 条（上限 {a.limit}），台账已追加 → {a.ledger}", file=sys.stderr)


if __name__ == "__main__":
    main()
