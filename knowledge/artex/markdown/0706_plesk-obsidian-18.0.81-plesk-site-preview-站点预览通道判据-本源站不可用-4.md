# Plesk Obsidian 18.0.81 /plesk-site-preview 站点预览通道判据：本源站不可用（404/500 结构），不能绕过 vhost 整站 Basic

- **code**: plesk-obsidian-18.0.81-plesk-site-preview-站点预览通道判据-本源站不可用-4
- **kind**: poc
- **category**: auth-bypass
- **component**: Plesk Obsidian 18.0.81（nginx + Apache 7080/7081 后端）站点预览 /plesk-site-preview/
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11T21:3x-21:5xZ 本机 curl 8.5.0 直连源站 92.205.178.49（--noproxy '*'）：阳性对照 /plesk-site-preview/copperline.retro32.com/ 在 443 => 404/990B Plesk 404 页（铜线站正常 Host 为 200/302B），endif.co.uk 同；/plesk-site-preview/old.retro32.com/<7 路径> × Host{IP,zzq-nonexistent.example,old} × 端口{80,443,7080,7081} 共 84 行 + 8443 5 条 + 归一化/steer 20 余条：状态仅 401×11/403×12/404×65/421×7/500×16，0×200。原始 CSV 落盘 /opt/artex/data/tasks/12/i3072/。
- **tags**: plesk,site-preview,basic-bypass,nginx,negative,apache,92.205.178.49,retro32
- **created_at**: 2026-11-11T21:41:34.336Z
- **engine**: old.retro32.com / 92.205.178.49

## 描述

判定 Plesk 站点预览（预览未发布/DNS 未生效站点）能否绕过目标 vhost 的 nginx HTTP Basic（realm="Access to Retro32"）与 Apache deny-all。结论：不能。预览前缀在本源站未生效：阳性对照与目标站点一律落 404/401/403/421/500 基线，无任何站点内容。附带的结构性异常：:80 默认 vhost 存在大小写敏感的 /plesk-site-preview/ location（非预览路径返回 Apache 代理 404/259B，前缀路径返回 nginx 原生 404/548B），但对“域名段后仍有内容”的路径稳定 500/572B，且与域名是否真实、是否 IP 字面量无关（127.0.0.1 / 127.0.0.1:7080 / localhost / userinfo@ / 真实文件路径全 500），疑为配置残留或变量 host 无 resolver 的 500，不可 steer、不映射 docroot、不构成 SSRF。

## 用法

```
复现/判据（替换 IP 与域名）：
1) 阳性对照（必做）：curl -sk --noproxy '*' -H 'Host: <IP>' https://<IP>/plesk-site-preview/<已知存活域名>/  —— 若预览可用应返回该站首页 200；返回 404/990（Plesk "404 Page Not Found"）或其它基线即预览未启用。
2) 目标：对 /plesk-site-preview/<target-domain>/{/, /style.css, /wp-login.php, /wp-json/, /wp-config.php, /wp-content/debug.log, /.git/HEAD} × 端口 {80,443,7080,7081} × Host {IP, 随机不存在域, target-domain} 各 1 次 GET；判据：200+站点特征=绕过成立（继续按应用面打），401 且 realm 不变=Basic 完整，404/500=预览未生效。
3) 结构指纹：若 :80 默认 vhost 上 /plesk-site-preview/ 前缀返回 nginx 原生 404/548B（其它路径返回 Apache 代理 404/259B），说明存在预览 location；其“带内容形态”路径（域名段后 ≥2 段或以 / 结尾）返回 nginx 500/572B 时，可用域名段 IP 字面量、localhost、userinfo@、真实文件路径做 steer 判定——若全部同 500，则该 location 不可利用（无 resolver/重写环），不要继续投入。
4) 归一化：%2e%2e/、..%2f、// 会被 nginx 先归一化并弹出域名段（回到 /plesk-site-preview/ => 404），无跨 vhost docroot 读取。
```
