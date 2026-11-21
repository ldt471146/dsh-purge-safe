# LLM API key 零消费只读验活（DeepSeek 余额 / OpenRouter 分层 / 通用 /models）

- **code**: llm-api-key-零消费只读验活-deepseek-余额-openrouter-分层-通用-models
- **kind**: script
- **category**: info-leak
- **component**: LLM API Key 只读验活（余额/权限面判定）
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在靶标 aigemini-org（上游渠道快照）上实测：curl -s -x http://127.0.0.1:7892 https://example.com/user/balance -H "Authorization: Bearer sk-19ec..." → 200，is_available=true，CNY total_balance=160.47 / granted=0.00 / topped_up=160.47；https://example.com/api/v1/key → 200 且 is_free_tier=true；https://example.com/v1/models → 200；https://example.com/v1/models → 200；https://example.com/zen/v1/models → 200（模型名带 -free）。对照组：无 Authorization → 401 "Authentication Fails (governor)"、无效 key → 401 "Your api key: ****dead is invalid"，证明读数真实。全程 0 次计费调用。
- **path**: pocs/llm-api-key-零消费只读验活-deepseek-余额-openrouter-分层-通用-models/llm_key_readonly_probe.py
- **tags**: llm,apikey,balance,readonly,zero-cost
- **created_at**: 2026-09-28T04:34:04.901Z
- **found_by**: exploit

## 描述

拿到上游 LLM API key 后，用只读端点判定 key 是否有效、余额多少、属于付费层还是免费层，零消费、不触发计费。DeepSeek /user/balance 是已知唯一能直接读出真金白银余额的官方只读端点；OpenRouter /api/v1/key 可读 is_free_tier 判定免费层；通用 /models 仅判 key 有效性。

## 用法

```
1) 把 KEY 换成待验 key（或从渠道快照抽 key 灌入 KEYS）；2) python llm_key_readonly_probe.py；3) 判读：DeepSeek 看 balance_infos[].total_balance/topped_up_balance（topped_up>0 = 充值真金白银），OpenRouter 看 is_free_tier。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LLM API key 零消费只读验活：判定 key 是否有效 / 余额 / 付费层 or 免费层。

铁律：只允许只读端点，绝不调用 /chat/completions、/messages、/generateContent 等任何计费接口。
已知只读端点：
  DeepSeek    GET https://example.com/user/balance   -> is_available + balance_infos(CNY/USD 余额，唯一能读出真金白银的官方只读端点)
  DeepSeek    GET https://example.com/models
  OpenRouter  GET https://example.com/api/v1/key        -> is_free_tier / limit / usage（判免费层）
  OpenAI 兼容 GET {base_url}/models                       -> 仅判 key 有效性
用法：改 PLAN 与 KEY，或从 channels 快照里抽 key 灌入；每 key 最多 1 请求、间隔 2s。
"""
import json, sys, time, urllib.request, urllib.error

PROXY = 'http://127.0.0.1:7892'          # 出境代理；不需要则设 None
ENDPOINTS = [
    ('deepseek',   'https://example.com/user/balance'),
    ('models',     'https://example.com/models'),
    ('openrouter', 'https://example.com/api/v1/key'),
]
KEYS = ['sk-REPLACE_ME']
TAKE_PER_KEY = 1          # 每个 key 请求数上限
SLEEP = 2.0

opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({'http': PROXY, 'https': PROXY}) if PROXY else urllib.request.BaseHandler())

for key in KEYS:
    for name, url in ENDPOINTS[:TAKE_PER_KEY]:
        req = urllib.request.Request(url, headers={
            'Authorization': 'Bearer ' + key,
            'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json'})
        try:
            with opener.open(req, timeout=25) as r:
                print(name, r.status, r.read().decode('utf-8', 'replace')[:800])
        except urllib.error.HTTPError as e:
            print(name, e.code, e.read().decode('utf-8', 'replace')[:400])
        except Exception as e:
            print(name, 'ERR', repr(e))
        time.sleep(SLEEP)

```
