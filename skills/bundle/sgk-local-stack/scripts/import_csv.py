#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CSV → SQLite 导入（给 SocialRelations_Web / 任意单表检索台用）。

特性：
- 自动建表（表不存在时按 CSV 表头建 TEXT 列），存在则按列名对齐插入
- 列名清洗：中文表头映射成英文（email/phone/qq/weibo/name/company/id_no/ip/addr/source/remark）
- --dry-run 只打印列映射与样本，不写库
- 导入结束打印每列非空计数，便于判断数据质量

用法：
  python import_csv.py --db db/ScocialEngineer.db --csv DATA.csv --table Socialusers --dry-run
  python import_csv.py --db db/ScocialEngineer.db --csv DATA.csv --table Socialusers
"""
from __future__ import annotations

import argparse
import csv
import sqlite3
import sys
from collections import Counter

MAP = {
    "email": "email", "mail": "email", "邮箱": "email", "邮件": "email",
    "phone": "cell_phone", "mobile": "cell_phone", "手机": "cell_phone",
    "手机号": "cell_phone", "电话": "cell_phone", "tel": "cell_phone",
    "qq": "qq", "weibo": "weibo", "微博": "weibo",
    "github": "github", "username": "username", "账号": "username", "用户名": "username",
    "password": "password", "passwd": "password", "密码": "password", "hash": "password",
    "name": "chinesename", "chinesename": "chinesename", "姓名": "chinesename", "真实姓名": "chinesename",
    "id": "identity_number", "id_no": "identity_number", "idcard": "identity_number",
    "身份证": "identity_number", "身份证号": "identity_number",
    "ip": "ip_address", "ip_address": "ip_address",
    "college": "college", "学校": "college",
    "addr": "living_place", "address": "living_place", "住址": "living_place", "地址": "living_place",
    "company": "source", "来源": "source", "source": "source",
    "公司": "source", "单位": "source",
    "remark": "remarks", "remarks": "remarks", "备注": "remarks",
}


def norm(h: str) -> str:
    k = h.strip().lower().replace(" ", "").replace("-", "_")
    return MAP.get(k, k)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--csv", required=True)
    ap.add_argument("--table", default="Socialusers")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--limit", type=int, default=0, help="0 = 全部")
    a = ap.parse_args()

    with open(a.csv, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
        sample = f.readline()
        delim = "\t" if sample.count("\t") > sample.count(",") else ","
        f.seek(0)
        rd = csv.reader(f, delimiter=delim)
        header = [norm(h) for h in next(rd)]
        rows = []
        for i, r in enumerate(rd):
            if a.limit and i >= a.limit:
                break
            rows.append(r[: len(header)])
    print(f"分隔符: {repr(delim)}  列: {header}")
    print(f"行数: {len(rows)}")
    if a.dry_run:
        print("样本首行:", rows[0] if rows else "(空)")
        return

    con = sqlite3.connect(a.db)
    cols = ", ".join(f'"{c}" TEXT' for c in header)
    con.execute(f'create table if not exists "{a.table}" (_rowid INTEGER PRIMARY KEY AUTOINCREMENT, {cols})')
    ph = ", ".join("?" for _ in header)
    sql = f'insert into "{a.table}" ({", ".join(chr(34)+c+chr(34) for c in header)}) values ({ph})'
    con.executemany(sql, rows)
    con.commit()

    cnt = Counter()
    for r in rows:
        for c, v in zip(header, r):
            if v and v.strip():
                cnt[c] += 1
    print("导入完成，非空计数：")
    for c in header:
        print(f"  {c:<16} {cnt[c]}")
    total = con.execute(f'select count(*) from "{a.table}"').fetchone()[0]
    print(f"表内总行数: {total}")
    con.close()


if __name__ == "__main__":
    main()
