# CDNGreat 缓存/防护层指纹识别与缓存范围、缓存键判定方法

- **code**: cdngreat-缓存-防护层指纹识别与缓存范围-缓存键判定方法
- **kind**: script
- **category**: recon
- **component**: CDNGreat 缓存层
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 https://example.com（回源 203.0.113.49，2026-10-11）实测确认全部指纹：cl-cache-status: HIT 出现在 /url.js 与 /favicon.png、伴随 cache-control: max-age=2592000；/home 与 /xxa/*.json 无该头；Host: poc-canary.evil.com 触发 HTTP/1.1 800 页并反射 Host；CL+TE 冲突触发 400 页含 "DDoS protection by  CDNGreat"；26 个子域 Host 全部被 800 拦截，仅 m./www. 命中 200。
- **path**: pocs/cdngreat-缓存-防护层指纹识别与缓存范围-缓存键判定方法/cdngreat_fingerprint.md
- **tags**: cdngreat,cache,fingerprint,waf,host-header,cl-cache-status
- **created_at**: 2026-10-10T17:12:58.945Z
- **found_by**: vuln-scan

## 描述

识别 CDNGreat 前置缓存/防护层的完整指纹（cl-cache-status 头、800 非标准状态码错误页、max-age=2592000、Vary 重复声明），以及缓存范围/缓存键/归一化/Host 白名单的判定命令与攻防要点。

## 用法

```
遇到带 cl-cache-status 响应头的站点时，按文档第二节命令依次确认：① 缓存生效范围（静态 vs 动态）② query 是否进 key ③ 参数名是否被归一化 ④ Host 白名单边界。据此决定是否值得投入缓存投毒测试。
```

## 正文

```
# CDNGreat 缓存/DDoS 防护层指纹与判定方法（example.com 实测）

## 一、指纹特征
1. 响应头 `cl-cache-status: HIT|MISS`（非标准头，区别于 Cloudflare 的 cf-cache-status / CloudFront 的 x-cache）
2. 被缓存资源附带 `cache-control: max-age=2592000`（30 天，注意：这是缓存层注入的，不是源站配置）
3. 响应头 `Vary: Accept-Encoding, Accept-Encoding`（重复声明，且 gzip 桶的响应只回一个 Vary —— 实现不规范）
4. 校验失败时返回**非标准状态码 `800`**，页内自带：
   `<p>访问代码: 800</p><p>访问编号: <uuid></p><p>访问方法: GET </p><p>访问网址: https://{Host}{path} </p><p>游客地址: {出口IP} </p><p>访问时间: ... </p><p>域名不存在</p>`
5. 报文级校验失败返回 400，页内 `<title>cdngreat.com</title>` 与 `<p>DDoS protection by  CDNGreat</p>`
6. Host 不在白名单时**直接由缓存层响应、不回源**（这也是枚举虚拟主机的快捷手段）

## 二、判定命令
```bash
# 找缓存层生效范围（哪个路径带 cl-cache-status）
curl -s -i -k "https://TARGET/url.js" | grep -iE 'cl-cache-status|age|cache-control|vary'
curl -s -i -k "https://TARGET/home"   | grep -iE 'cl-cache-status|age'   # 动态路由通常无该头

# 确认 query 是否进缓存 key（两次不同随机值都应 MISS，第三次同值 HIT）
curl -s -i -k "https://TARGET/url.js?cb=rand1" | grep -i cl-cache-status
curl -s -i -k "https://TARGET/url.js?cb=rand2" | grep -i cl-cache-status
curl -s -i -k "https://TARGET/url.js?cb=rand1" | grep -i cl-cache-status

# 参数名归一化验证（若下述都 HIT 同一条目，则参数名被丢弃）
for q in "v=VAL" "V=VAL" "=VAL" "v=VAL&&" "v=VAL;x=1"; do
  curl -s -i -k "https://TARGET/url.js?$q" | grep -i cl-cache-status
done

# 枚举虚拟主机（800 = Host 不在白名单；200 = 命中）
curl -s -i -k "https://TARGET/" -H "Host: m.TARGET" | head -1
```

## 三、攻防要点
- 该层**只缓存静态扩展名资源**，`/home`、`/xxa/*.json` 之类动态路由不入缓存 → 传统缓存投毒/缓存欺骗在该架构上通常打不动，务必先用上面命令确认缓存范围再投入时间。
- Host 校验失败页会把 Host 原样写进"访问网址"，属反射型信息泄露（可做钓鱼域名探测/内部域名探测的侧信道），但因状态码 800 不入缓存，无法升级为缓存投毒。
- 参数名归一化（参数名被丢弃、只有参数值进 key）会造成缓存键碰撞；若目标存在任何"按参数名区分业务含义"的可缓存端点，即可尝试跨租户/跨渠道缓存混淆。
- 报文级畸形（CL+TE 冲突、dual-CL、负 CL）都返回 400 而非透传，说明该层做了报文校验，走私风险较低。

```
