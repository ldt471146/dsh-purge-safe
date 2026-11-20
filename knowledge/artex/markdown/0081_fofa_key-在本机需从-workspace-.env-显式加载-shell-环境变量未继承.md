# FOFA_KEY 在本机需从 workspace/.env 显式加载（shell 环境变量未继承）

- **code**: fofa_key-在本机需从-workspace-.env-显式加载-shell-环境变量未继承
- **kind**: script
- **category**: env
- **component**: FOFA API 客户端环境
- **severity**: low
- **language**: powershell
- **source**: self
- **verified**: 1
- **verified_note**: 2026-09-29 在本机（Windows / dsh 会话）实测：直接读 $env:FOFA_KEY 为空（打印 "FOFA_KEY MISSING"）；按上述一行命令从 C:\Users\user\workspace\.env 加载后环境变量存在且可被 FOFA 技能脚本读取。指挥者已复核确认 .env 内有 key。
- **path**: pocs/fofa_key-在本机需从-.dsh-.env-显式加载-shell-环境变量未继承/fofa-key-load.ps1
- **tags**: fofa,环境变量,信息收集,踩坑
- **created_at**: 2026-09-28T21:20:30.181Z
- **found_by**: recon

## 描述

dsh 的 .env 文件里配了 FOFA_KEY，但不会自动注入 shell 环境变量；必须显式读取后赋值给 $env:FOFA_KEY，FOFA 技能脚本才可见。否则每个接手的人都会误判为"缺 key"并白白放弃 FOFA 这条被动源

## 用法

```
开工前跑：Get-Content "$env:USERPROFILE\workspace\.env" | Where-Object { $_ -match '^FOFA_KEY=' } | ForEach-Object { $env:FOFA_KEY = ($_ -split '=',2)[1] }  然后 python runs/fofa_client.py 'domain="x.com"' --pages 2
```

## 正文

```
# 现象：FOFA 技能报 key 缺失，但 key 其实已配置
# 实测：$env:FOFA_KEY 为空，而 C:\Users\user\workspace\.env 内有 FOFA_KEY=...

# ---- 每次开工前先执行这段（PowerShell）----
Get-Content "$env:USERPROFILE\workspace\.env" | Where-Object { $_ -match '^FOFA_KEY=' } | ForEach-Object { $env:FOFA_KEY = ($_ -split '=',2)[1] }

# 验证（只打印长度，不泄露 key）
if ($env:FOFA_KEY) { "FOFA_KEY loaded len=$($env:FOFA_KEY.Length)" } else { "MISSING" }

# ---- 之后即可正常调用 fofa_client.py ----
# python runs/fofa_client.py 'domain="example.com"' --pages 2 --size 100 --interval 2.0

```
