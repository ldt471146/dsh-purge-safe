# 代理池可信度判别：伪造 SMTP/IMAP/HTTP 服务指纹的蜜罐代理（DigitalOcean/阿里云段）

- **code**: 代理池可信度判别-伪造-smtp-imap-http-服务指纹的蜜罐代理-digitalocean-阿里云段
- **kind**: script
- **category**: methodology
- **component**: open proxy / CONNECT proxy
- **severity**: low
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 于 shopto.net 任务（ARTEX 意图 #2091）实测：14 条 DigitalOcean 段"代理"（128.199.202.122:8080、134.209.29.120:3128/80、138.68.60.8:3128、139.162.78.109:3128/80/8080、139.59.1.14:3128/8080、159.203.61.169:3128、161.35.70.249:3128/80、198.199.86.11:3128、209.97.150.167:3128）对 smtp.gmail.com:25、mail.example.com:25、8.8.8.8:25、3.8.196.174:25/587、90.152.8.58:25/587 全部返回逐字节相同的 "220 ubuntu ESMTP Postfix (Ubuntu)"，对 90.152.8.58:143 统一返回同一 Dovecot IMAP banner；对 3.8.196.174:80/90.152.8.56:80/90.152.8.58:80/8080 统一返回 "HTTP/1.1 403 Forbidden" 10B，对 3.8.196.174:443 每条给不同自签 CN=* 证书；而同期 130 条真实代理对 3.8.196.174:443 返回真实 Apache 401 + 同一张 dev.shopto.net 证书，15 条真实出口对 90.152.8.56:80 返回真实 IIS 8.5 701B。据此证人已推翻该任务 fact#1995 的 .58 Go/Postfix 服务指纹。
- **tags**: proxy, honeypot, recon, false-positive, methodology
- **created_at**: 2026-11-11T18:41:22.925Z
- **engine**: 90.152.8.58

## 描述

用公共 CONNECT 代理换出口做服务指纹时，代理池里混有伪造服务桩（蜜罐/测试桩）：它们 CONNECT 一律 200，但按端口伪造常见服务 banner，对任意目标返回相同内容。判别核心=「目标特定阳性对照 + 跨目标同一性检验」，不能只看 CONNECT 200 或 HTTP 状态。

## 用法

```
判别步骤（每条结论必须过）：\n1) 同出口阳性对照：对已知特征目标取真实响应（如 3.8.196.174:443 期望 Apache 401 + 真实证书；90.152.8.56:80 期望 IIS 8.5 701B；90.152.8.56:22 期望 OpenSSH banner）。达不到就判该出口不可信。\n2) 跨目标同一性：同一出口对至少 2-3 个互不相干目标（如 smtp.gmail.com:25 与 8.8.8.8:25）取 banner/HTTP 头，逐字节相同即伪造。\n3) 随机性检验：对同一目标重复请求，内容/标题/证书频繁变化=伪造。\n4) 类指纹识别：统一 "Forbidden\n" 10B（Go 风格）、自签 CN=* 证书、随机设备标题（GeoWebServer/Vben Admin/Nextcloud/Elbite/WebSphere 等）、逐字节相同的 Postfix/Dovecot banner → 丢弃该出口所有数据，不得入 fact/finding。
```
