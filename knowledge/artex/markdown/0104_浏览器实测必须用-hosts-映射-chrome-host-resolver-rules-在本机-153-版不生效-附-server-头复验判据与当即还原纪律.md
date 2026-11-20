# 浏览器实测必须用 hosts 映射：Chrome --host-resolver-rules 在本机 153 版不生效（附 Server 头复验判据与当即还原纪律）

- **code**: 浏览器实测必须用-hosts-映射-chrome-host-resolver-rules-在本机-153-版不生效-附-server-头复验判据与当即还原纪律
- **kind**: script
- **category**: env
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 tgt9942-com 靶标实测：Chrome 153.0.8010.53（Windows）用 `--host-resolver-rules="MAP example.com 203.0.113.73"` 启动 headless（进程命令行核实参数已传入），CDP 捕获 `Server: cloudflare` ⇒ 映射失效、仍走 CDN；改为系统 hosts 追加 `203.0.113.73 example.com` 后 `Resolve-DnsName` 返回 203.0.113.73，CDP 复验响应头为 **`Server: Microsoft-IIS/10.0`** ⇒ 确认直连源站。随后按纪律删除映射并复验解析恢复为 203.0.113.21 / 203.0.113.70。
- **path**: pocs/浏览器实测必须用-hosts-映射-chrome-host-resolver-rules-在本机-153-版不生效-附-server-头复验判据与当即还原纪律/chrome-host-resolver-rules-broken-use-hosts.md
- **tags**: 浏览器实测,hosts,cloudflare,源站直连,踩坑,cdp
- **created_at**: 2026-09-28T23:47:03.966Z

## 描述

记录 Chrome 153 上 --host-resolver-rules 失效（仍走 Cloudflare）的实测坑，给出改用系统 hosts 映射的正确姿势、用 Server 响应头复验"源站 vs CDN"的判据，以及"用完当即还原 hosts"的纪律与验证命令。

## 用法

```
1) 需要"只打源站 IP、绕过 CDN 做浏览器实测"时，不要依赖 `--host-resolver-rules`（Chrome 153 实测失效）；2) 改用系统 hosts：备份 → 追加 `源站IP 域名` → `ipconfig /flushdns` → `Resolve-DnsName` 验证指向源站；3) 启动浏览器/CDP 操作；4) 用 CDP `Network.responseReceived` 抓 `Server` 头复验是否为目标中间件（而非 `cloudflare`）；5) 用完**当即**逐行过滤删除该行、`flushdns`、再复验解析已恢复。
```

## 正文

```
# 坑：`--host-resolver-rules` 在 Chrome 153（Windows）上不生效 ⇒ 浏览器实测改用 hosts 映射

## 现象
为"只打源站 IP、不解析域名、不经过 CDN"做浏览器实测时，用 Chrome 官方的域名映射参数启动 headless：

```powershell
$args = '--headless=new --remote-debugging-port=9223 --remote-allow-origins=* ' +
        '--host-resolver-rules="MAP example.com 203.0.113.73" ' +
        '--user-data-dir=C:\runs\chrome-prof about:blank'
Start-Process -FilePath "C:\Program Files\Google\Chrome\Application\chrome.exe" -ArgumentList $args
```

**进程命令行已核实参数确实传进去了**：

```
"C:\Program Files\Google\Chrome\Application\chrome.exe" --headless=new --remote-debugging-port=9223
 --remote-allow-origins=* --host-resolver-rules="MAP example.com 203.0.113.73" ...
```

**但通过 CDP 抓到的响应头是**：

```
Server: cloudflare          ← 说明请求走了 CDN，域名映射没生效
```

**实测环境**：Chrome **153.0.8010.53**（Windows）、`--headless=new`。疑与 Chrome 内置解析器 / Secure DNS（DoH）优先于 `host-resolver-rules` 有关。

## 正确姿势：改用系统 hosts 映射（并且"当即还原"）

```powershell
$hosts = "C:\Windows\System32\drivers\etc\hosts"

# 1) 先备份
Copy-Item $hosts "runs\hosts.bak" -Force

# 2) 追加一行（幂等，别重复加）
$pre = Get-Content $hosts
if(-not ($pre -match "ng-api")){ [target73.example.com.File]::WriteAllLines($hosts, ($pre + "203.0.113.73 example.com")) }
ipconfig /flushdns | Out-Null

# 3) 验证解析确实指向源站
Resolve-DnsName "example.com" -Type A | Where-Object {$_.IPAddress} | Select-Object -ExpandProperty IPAddress
# 期望输出：203.0.113.73

# 4) 浏览器操作（此步才启动 Chrome / CDP）
...

# 5) ⚠️ 用完"当即"删除该行并复验（不要拖到收尾）
$now = Get-Content $hosts
[target73.example.com.File]::WriteAllLines($hosts, ($now | Where-Object { $_ -notmatch "ng-api" }))
ipconfig /flushdns | Out-Null
Get-Content $hosts | Select-String "ng-api"       # 期望：无输出
Resolve-DnsName "example.com" -Type A     # 期望：恢复为 CDN IP
```

## ⭐ 复验判据：靠 `Server` 响应头区分"源站 vs CDN"
**这是判断"到底有没有绕过 CDN"的唯一可靠依据**（页面内容两者相同，肉眼看不出）：

| 响应头 | 结论 |
|---|---|
| `Server: Microsoft-IIS/10.0` / `nginx` / 目标自有中间件 | ✅ **直连源站**（CDN 已绕过） |
| `Server: cloudflare`（或 `cf-ray` 头出现） | ❌ **仍在走 CDN，映射无效** |

**抓法（CDP）**：`Network.enable` 后监听 `Network.responseReceived` 事件的 `response.headers`：

```powershell
Send-Cdp "Network.enable" @{} | Out-Null
Send-Cdp "Page.navigate" @{url="http://<域名>/<路径>"} | Out-Null
# 读消息流，匹配：
#   if($m -match 'Network\.responseReceived' -and $m -match '"Server":"([^"]*)"'){ ... }
```

## 纪律（本机是用户的机器）
- **hosts 是"对用户本机唯一的一处改动"，必须"用完当即还原"**，不要拖到任务收尾（可能忘记）；
- 每次"加→用→删"都要在攻击链里留一条记录，**并在最后核验 `Get-Content $hosts | Select-String "<域名>"` 为空 + `Resolve-DnsName` 已恢复**；
- **不要用 `Set-Content` 整文件重写**（可能改变编码/丢注释），用 `[target73.example.com.File]::WriteAllLines` 逐行过滤；改动前先 `Copy-Item` 备份。
```
