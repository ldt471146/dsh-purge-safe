# 主域 NXDOMAIN 后从姊妹域证书按机器命名规律挖跨段新资产

- **code**: 主域-nxdomain-后从姊妹域证书按机器命名规律挖跨段新资产
- **kind**: script
- **category**: recon
- **component**: crt.sh（证书透明日志）
- **severity**: low
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 449918 靶标实战验证：example.com 已 NXDOMAIN（crt.sh 71 名全解析失败、rapiddns/hackertarget 返回 invalid host）；改用姊妹域 example.com/example.com/kj5799f.com 拉证书共 122 个唯一子域，解析出 52 条 A 记录，按 IP 分组暴露 4 个机器集群落点，其中 203.0.113.75 与 203.0.113.29 属两个从未出现过的全新 C 段，且实测均命中同款"智讯网站群系统"（X-Powered-By: PHP/8.1.7 + x-is-origin: true）。
- **path**: pocs/主域-nxdomain-后从姊妹域证书按机器命名规律挖跨段新资产/crt-sibling-enum.py
- **tags**: crt.sh,证书透明,子域枚举,站群,被动信息收集,跨段扩面
- **created_at**: 2026-09-28T21:20:40.590Z
- **found_by**: recon

## 描述

主域 NXDOMAIN 时的扩面方法：不要停在"域名死了就放弃"，改从同团伙仍在用的姊妹域名入手拉证书，提取子域命名规律（如 5 字母+2 位编号，每 4 台一组），批量解析后按 IP 分组，即可发现指向全新网段的新机器。本次据此把站群从 6 个网段扩到 8 个，挖出两个从未出现过的 C 段

## 用法

```
替换 DOMAINS 为同团伙在用域名 → bash: python3 crt-sibling-enum.py；再在 Windows/PowerShell 侧用 Resolve-DnsName 批量解析 subs.txt 并按 IP 分组；对分组出的新 IP 发单条只读 GET 验证是否同套系统（比对响应头指纹）
```

## 正文

```
#!/usr/bin/env python3
"""被动找跨段新资产：主域死亡时，用姊妹域的证书 + 机器命名规律反推落点。

适用场景：
  主域名已 NXDOMAIN（被动 DNS 源也查不到历史），但同团伙还有其它在用域名。
  站群/集群类目标的分站子域通常有固定命名规律（例：5 小写字母 + 2 位编号，
  如 cdgpy11-14 / yvrgh01-04 / kabjg51-54），每 4 台一组、每组落到同一 IP。
  把规律提取出来批量解析，就能发现指向新网段的新机器。

流程：
  1) crt.sh 拉证书名（%25 = URL 编码的 '%'，匹配所有子域）
  2) 提取唯一子域，去掉 *. 通配
  3) 批量 A 解析（注意：工具若是 Linux 二进制在 Windows 跑不了，
     直接用 PowerShell 的 Resolve-DnsName）
  4) 按"解析到的 IP"分组 → 每个 IP 就是一台（或一组）机器，
     不在已有资产库里的就是新资产
"""
import json, subprocess, sys, collections

DOMAINS = ["example.com", "example.com", "kj5799f.com"]   # 姊妹域，替换成目标团伙的
PROXY = "socks5-hostname 127.0.0.1:1086"                  # 出口代理（按需）

def crt(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    raw = subprocess.run(["curl.exe", "-s", "--proxy", PROXY, "--max-time", "90", url],
                         capture_output=True, text=True).stdout
    try:
        return {n for row in json.loads(raw or "[]")
                for n in row.get("name_value", "").split("\n") if n and not n.startswith("*")}
    except Exception:
        return set()

# 1) 收集所有子域
subs = sorted({s for d in DOMAINS for s in crt(d)})
print(f"[crt.sh] unique subdomains = {len(subs)}")
open("subs.txt", "w").write("\n".join(subs))

# 2) 解析（PowerShell 侧执行，示例）：
#    $res = foreach ($d in Get-Content subs.txt) {
#      $r = Resolve-DnsName -Name $d -Type A -DnsOnly -EA SilentlyContinue | ? IPAddress
#      if ($r) { foreach ($x in $r) { "$d $($x.IPAddress)" } } }
#    $res | Set-Content dns.txt
# 3) 按 IP 分组：sort -k2 dns.txt | awk '{print $2}' | uniq -c
# 4) 逐 IP 只读验证是否同套系统（响应头指纹，例如 x-is-origin / X-Powered-By）

```
