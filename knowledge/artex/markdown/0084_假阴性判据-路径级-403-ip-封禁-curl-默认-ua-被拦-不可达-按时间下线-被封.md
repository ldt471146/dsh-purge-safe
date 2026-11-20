# 假阴性判据：路径级 403 ≠ IP 封禁 / curl 默认 UA 被拦 ≠ 不可达 / 按时间下线 ≠ 被封

- **code**: 假阴性判据-路径级-403-ip-封禁-curl-默认-ua-被拦-不可达-按时间下线-被封
- **kind**: poc
- **category**: waf
- **component**: [通用方法] 封禁判定 / 假阴性识别
- **severity**: info
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 在 **203.0.113.70（Laravel）** 实测踩坑并纠正：探测 35 个敏感路径（`/admin/logout`、`/admin/user`、`/api/login`、`/uploads/`、`/static/`…）从 404 变 403（552B nginx 层），我据此写了 `blocked=true`；随后**同刻对照**——`/admin/login` 仍 **200/2535B**、`/` 仍 **302**、不存在路径仍 **404/1628B**，且**家宽出口与 VPS 1089 出口表现完全一致**，等待 20 秒后仍正常 ⇒ **确认那批 403 是路径级"防扫描/敏感路径拒绝"规则，与 IP 封禁无关**，已把 asset_test 的 `blocked` 纠正为 false。另两条同源实例（均由本人踩过）：**example.com 段 curl 默认 UA 被拦**（python+Chrome UA 同刻 200）、**站群按时间段运营**（用全新 VPS 出口复测同样 404 才定为"站点侧下线"）。
- **tags**: 假阴性,封禁判定,路径级403,curlUA,关站,对照实验,方法论,全队踩坑
- **created_at**: 2026-09-28T21:36:22.485Z
- **found_by**: exploit

## 描述

判断"目标是否封了我们"时最容易犯的三类**假阴性**（把"我们没打进去"误判成"目标不可达/被封/关站"），以及对应判据：<br>① **路径级 403 ≠ IP 级封禁**：目标常对"敏感路径扫描"返回 403（nginx 层，固定长度），而正常路径不受影响。**判据三要素**：**同刻**发一个**已知可用路径**（如登录页）+ 一个**不存在路径**做对照；若可用路径仍 200、不存在路径仍 404 ⇒ 是路径级规则，不是封禁；**并跨出口复核**（家宽 + VPS 代理各一次）。<br>② **curl 默认 UA 被拦 ≠ 目标不可达**：部分源站按 UA 拦截，`curl/8.x` 直接吃 `000`，而同样的 URL 用 `Chrome UA` 立即 200。**判据**：同 URL 换 UA 复测（python urllib + Chrome UA 或 `curl -A "<Chrome UA>"`）。<br>③ **按时间段运营的站点下线 ≠ 被封**：站点"关站"时所有出口都拿不到内容（含全新未用过的出口）⇒ **必须用一条"从没用过的新出口"复测**：新出口也 404/超时 = 目标侧下线；只有本出口失败而新出口正常 = 才可能是封禁。<br>**通用原则**：任何"不可达/被封/关站"的结论，**必须至少包含一组同刻对照 + 一次异出口复核**，否则只能记为"未验证"。

## 用法

```
```bash
# 判封禁三要素（同刻采集，缺一不可）
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/203.0.113.48 Safari/537.36"
curl -s -k -m 15 -A "$UA" -o /dev/null -w "known-good : %{http_code}\n" "https://TARGET/admin/login"   # 应 200
curl -s -k -m 15 -A "$UA" -o /dev/null -w "not-exist  : %{http_code}\n" "https://TARGET/zzz-rand-9f3a"  # 应 404
curl -s -k -m 15 -A "$UA" -o /dev/null -w "suspect    : %{http_code}\n" "https://TARGET/uploads/"      # 若 403
# 三者同刻成立 ⇒ 403 是路径级规则，不是封禁
# 再用异出口复核一次：
curl -s -k -m 25 --socks5-hostname 127.0.0.1:<port> -A "$UA" -o /dev/null -w "via-proxy  : %{http_code}\n" "https://TARGET/admin/login"
```
```
