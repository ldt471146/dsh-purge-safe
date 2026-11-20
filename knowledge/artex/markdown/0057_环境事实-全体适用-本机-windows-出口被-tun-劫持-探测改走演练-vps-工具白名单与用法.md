# 环境事实：本机出口走全局代理（127.0.0.1:7892）；仅代理不可用时才改走演练 VPS

- **code**: 环境事实-全体适用-本机-windows-出口被-tun-劫持-探测改走演练-vps-工具白名单与用法
- **kind**: script
- **category**: env
- **component**: 演练环境/出口链路
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: （2026-09-28 补充实测）① 本机与 VPS 双出口对照成立：同一批端口本机全 timeout、VPS 全拿到真实 banner；scp 把 IPv6 目标解析为 0.0.10.42。② fscan.exe 2.2.1 边界实测：本机跑 fscan 成功取回 203.0.113.20:5566 的 squid 400 响应与 203.0.113.110:6379 的 `-NOAUTH Authentication required.`（正向可信），但同一台机 FOFA 明确有 80/443/9527，fscan 一条都没报（负向不可信）。③ 三元对照法（本机 socket / VPS socket / 目标行为）实测可给出"目标侧不可达"的定论：203.0.113.50:27017 两出口均超时 ⇒ 判定目标侧不可达并止损。
- **path**: pocs/环境事实-全体适用-本机-windows-出口被-tun-劫持-探测改走演练-vps-工具白名单与用法/poc.sh
- **tags**: 环境事实,出口链路,TUN,Windows,工具白名单,VPS跳板,nuclei,FOFA_KEY
- **created_at**: 2026-09-28T14:07:34.664Z

## 描述

本机出口现状（2026-10 实测）：全局代理 http://127.0.0.1:7892 可用，经它访问境外目标返回 200；直连仍不可信。演练 VPS 只作为【代理故障时的备用出口】与跳板（反弹监听/frps），不是默认路线。工具白名单、nuclei/FOFA_KEY 位置仍有效。

## 用法

```
1) 任何对境外目标的扫描/探测前，先确认走 VPS 出口；2) 连接 VPS：ssh -i C:\Users\user\workspace\redteam\toolkit\vps\id_rsa -o IdentitiesOnly=yes -o StrictHostKeyChecking=no root@2602:fa59:2:a9b9::1；scp 上传目标写 root@[2602:fa59:2:a9b9::1]:/tmp/x；3) 本机只跑 fscan.exe/gogo.exe/curl.exe/python/nuclei/java。
```

## 正文

```
## 一、当前结论（2026-10-23 修订，优先级最高）

1. **本机出口优先走全局代理**：`http://127.0.0.1:7892`（系统配置 → 全局代理）。
   实测：经该代理访问境外目标 `HTTP 200`；直连仍不可信（timeout/000）。
2. **判断出口是否可用**：`curl -x http://127.0.0.1:7892 https://<目标>/` 返回正常状态码即视为可用；
   返回 000/timeout 才判定为出口故障。
3. **只有代理不可用时才改走演练 VPS**（vps_exec / 出口跳板）。代理正常时不要默认把探测丢到 VPS：
   - 走 VPS 的流量不经过本机任务 MITM，**流量不落库、报告证据链会缺**；
   - VPS 是共享出口，容易被目标按 IP 封。
4. 需要 Linux 专有工具或目标只接受境外出口时，才用 VPS；否则一律本机 + 全局代理。

---

## 二、历史记录（2026-09 旧环境，仅供排查参考）

## 一、本机（Windows）链路事实（实测）
1. **系统级代理/TUN 劫持**：curl/Python 直连境外目标全部 timeout；`curl -v -x http://<ip>:<port>` 连 "Connected to" 都不打印；`scp` 把 IPv6 目标 `2602:...` 误解析成内网地址 `0.0.10.42`（本机 TUN 网关）。⇒ **本机所有直接出网探测的结果不可信（含 nmap 的 "25/110/143 open + 997 filtered"、fscan 的大面积漏报）**。
2. 判据：同一批端口，本机 timeout、VPS 拿到真实 banner；或任何解析结果落在 `0.0.10.0/24`。
3. **不适用**：不要用本机直连结果做「端口关闭」结论（负向结论不可信）；正向拿到 banner 的结论仍可信（如本机 fscan 拿到 squid banner）。

## 一·补 fscan.exe 的实测边界（重要）
本机跑 `fscan.exe -h <ip> -p <ports> -np -nobr -nopoc -noredis -t 2 -time 5`：
- **正向可信**：成功取回 `203.0.113.20:5566` 的 `HTTP/1.1 400 Bad Request / Server: squid`，与 `203.0.113.110:6379` 的 `-NOAUTH Authentication required.`
- **负向不可信**：同一台 `203.0.113.20` 的 80/443/9527（FOFA 明确存在）**一条都没报**；`203.0.113.50` 直接报「0 个开放端口」。
- 用法约束：**必加 `-nobr`（禁爆破）、`-nopoc`、`-noredis`、`-t 2`**；`-time 5` 会被自适应成 Timeout=5000ms。
⇒ 结论：**fscan 报出来的可以信，它没报的不能当成不存在**；要下「端口关闭」结论必须换出口复核。

## 一·补 双出口对照法（判「目标侧不可达」的标准动作）
出现「本机不可达」时不要直接判死，按顺序做两条对照，两条都不通才写「目标侧不可达」：
1. **本机原生 socket**（`socket.create_connection((ip,port), timeout=10)`；**不要用 curl**，它会读 IE/系统代理）：不通只说明本机链路有问题。
2. **VPS 出口 socket**（`timeout 6 bash -c 'cat </dev/null >/dev/tcp/IP/PORT'`）：仍不通 ⇒ 换第三条。
3. **第三方视角**（FOFA 等被动数据 + 目标其它端口行为）：若同机其它端口也不可达、且被动数据陈旧 ⇒ 判「目标侧不可达」并**止损**，不再耗轮次。

## 二、可信跳板（首选）
演练 VPS：`REDTEAM_VPS_HOST=2602:fa59:2:a9b9::1`（IPv6）、`REDTEAM_VPS_USER=root`、`REDTEAM_VPS_KEY=C:\Users\user\workspace\redteam\toolkit\vps\id_rsa`，出口 IPv4 `203.0.113.55`（干净）。Ubuntu 6.8 / 1C / 961MB；自带 curl、wget、python3、nc、jq（**无 nmap/socat**）。
- 连接写法（PowerShell 下必须给 IPv6 加方括号，否则 scp 解析错）：`scp -i $k file "root@[2602:fa59:2:a9b9::1]:/tmp/f"`；`ssh -i $k -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL root@2602:fa59:2:a9b9::1 "<cmd>"`
- upload 后 `sed -i 's/\r$//' /tmp/f`（Windows 换行）。
- 用完清理：`rm -f /tmp/<你的脚本>`，不留持久化。
- 提示：VPS 上已有其它角色留下的文件（`/tmp/api_scan.json`、`b.*` 等），**不要删**。

## 三、Windows 本机可用工具白名单
可用：`C:\Users\user\workspace\redteam\toolkit\fscan.exe`(v2.2.1)、`gogo.exe`、`suo5-windows-amd64.exe`、`java`(`jdk11\`)、`godzilla.jar`、`nuclei` + 模板 `C:\Users\user\nuclei-templates`(13,764 条 / CVE 4,480)、`curl.exe`、`python`(3.13)。
**Linux ELF 二进制在本机不可用**（`dnsx/naabu/katana/httpx/subfinder/ksubdomain/frpc/frps/fscan(无后缀)/gogo(无后缀)/suo5-linux-amd64` 全是 ELF，跑不了）——**要跑就把它们传到 VPS 上跑**，不要在 Windows 上反复试。
`FOFA_KEY` 在 `C:\Users\user\workspace/.env`（也可用 MCP `fofa` 工具）。

## 四、PowerShell 执行远端命令的坑
- 远端命令含 `$var`、单引号、括号时，**写成脚本文件 scp 上去执行**，不要在 ssh 的 inline 字符串里拼（实测多次被 PowerShell 提前展开/截断，导致 exit 1 且无输出）。
- `curl` 在 PowerShell 里是 `Invoke-WebRequest` 别名，**必须写 `curl.exe`**。
- ssh/scp 的 `Warning: Permanently added ...` 会被 PowerShell 当 stderr 报 RemoteException，**不代表命令失败**（用 `2>$null` 或看实际输出判断）。
```
