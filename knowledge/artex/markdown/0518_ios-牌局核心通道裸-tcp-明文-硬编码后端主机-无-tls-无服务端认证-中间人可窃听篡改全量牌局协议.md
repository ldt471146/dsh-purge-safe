# iOS 牌局核心通道裸 TCP 明文 + 硬编码后端主机（无 TLS/无服务端认证）→ 中间人可窃听篡改全量牌局协议

- **code**: ios-牌局核心通道裸-tcp-明文-硬编码后端主机-无-tls-无服务端认证-中间人可窃听篡改全量牌局协议
- **kind**: template
- **category**: info-leak
- **component**: Unity/iOS 客户端自研 Socket 牌局协议（GameSocket → SocketObject → BaseSocket）
- **severity**: high
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: task#614（2026-11-04）双重验证：① 离线静态——从授权域免鉴权下载的 ios.ipa 解出 UnityFramework，反汇编确认 BaseSocket.Async_Connect 用 Socket(AF, Stream=1, Tcp=6)+BeginConnect 建连，全调用链无 SslStream/AuthenticateAsClient/RemoteCertificateValidationCallback/X509Chain/ServicePointManager；AppStoreConfigManager.Init 里 serverip 字段被赋值为编译期字符串常量（后端域:36610），GameSocketInit 由该常量 Split→TryParse→ConnectSocket。② 主动探针——对后端 36610 做 TCP connect 成功但 TLS ClientHello 返回 SSLEOFError(UNEXPECTED_EOF_WHILE_READING)，证明不是 TLS 服务；同批后端 HTTP 口 46750/46712/47000 TLSv1.2 握手成功并返回 403 TEST-ERROR，说明只有牌局数据面未加密。未做真机 MITM，故未取得数据，仅确认缺陷成立。
- **path**: pocs/ios-牌局核心通道裸-tcp-明文-硬编码后端主机-无-tls-无服务端认证-中间人可窃听篡改全量牌局协议/poc.md
- **tags**: ios,ipa,静态逆向,il2cpp,socket,plaintext,no-tls,mitm,hardcoded-host,protocol,sensitive-data-exposure
- **created_at**: 2026-11-04T14:36:04.119Z
- **engine**: www.winners.club（iOS 客户端 com.poker.wsc v1.0.0.8）

## 描述

iOS 客户端的牌局数据面用 System.Net.Sockets.Socket(Stream,Tcp)+BeginConnect 裸建连，服务端地址由 AppStoreConfigManager.Init 硬编码进二进制，全链路无 TLS/证书校验/服务端身份验证。同网段/公共 Wi-Fi/运营商路径上的中间人可完整抓取与篡改登录、改密、进房、发牌、公证数据并冒充服务端。适用于任何 Unity/iOS 自研 Socket 协议 App 的传输层判定（不依赖有 MITM 位置即可完成判定）。

## 用法

```
三步判据，任一步不成立即不能下此结论：
1) 静态定建连原语：在 IPA 解出的托管层（Il2CppDumper 的 dump.cs 或 dnfile/dncil 反汇编）里找 Socket 建连类（本例 BaseSocket.Async_Connect），看 Socket 构造参数是否为 Stream/Tcp、是否调用 BeginConnect；再沿同一调用链 grep 是否存在 SslStream / AuthenticateAsClient / RemoteCertificateValidationCallback / ServerCertificateCustomValidationCallback / X509Chain / ServicePointManager。查不到 = 裸 TCP。
2) 静态定主机：从 GameSocketInit 顺 bl 到 GetServerIp → AppStoreConfigManager.Init，把 ServerConfig 的 serverip/httpip/serverhttpip/maintainip/resip/logwebsocketurl/photoUrl 等字段字面量一次列全（stringliteral.json 交叉核对）。若这些值既不来自服务端下发也不来自 PlayerPrefs，即为编进客户端的常量。
3) 主动证伪"其实有 TLS"：对后端端口做 python 探针（见正文脚本）。判据 = TCP connect 成功 + TLS ClientHello 报 SSLEOFError/UNEXPECTED_EOF_WHILE_READING，且同一批后端的 HTTP 端口能正常 TLS 握手（阳性对照）。只有牌局口是裸 TCP 才成立。

不要做的事：程序集里存在 System.Net.WebSockets / NativeWebSocket 不等于业务走它，必须按 GameSocket 实际继承链确认；连接后服务端不主动发数据是客户端先发 protobuf 的表现，不是端口打错。

利用前置：本漏洞没有"发个包就触发"的接口路径，必须取得受害者网络路径上的中间人位置（同网段/恶意 AP/运营商路径）或能污染其 DNS 解析，才能抓包与冒充服务端。
```

## 正文

```
# iOS 牌局核心通道为裸 TCP 明文 + 硬编码后端主机（无服务端认证）

> 结论类型：客户端传输层缺陷（信息泄露）。静态可判定；实际利用需网络中间人位置。
> 本条与同任务的「Unity/ILRuntime 热更链无签名校验」条目互补：那条讲更新通道被投毒，本条讲牌局数据面本身明文。

## 0. 前置条件

- 能拿到客户端包（免商店分发链的 `ios.ipa` / `apk` 常无需鉴权，`curl -k -o x.ipa <url>` 即可）。
- 解包后能到托管层：
  - Unity iOS：`Payload/<App>.app/Frameworks/UnityFramework`（Mach-O，RVA==文件偏移时可直接算出文件偏移）；
  - 元数据：Il2CppDumper 产出的 `dump.cs`、`script.json`、`stringliteral.json`；
  - 或 UnityFS `Asset.upk` 里 carve 出 `.dll`，用 `dnfile` + `dncil` 逐方法反编译。
- 能出网做一次 TCP/TLS 探针（**不需要** MITM 位置即可完成判定）。

## 1. 静态判据 A：建连原语是裸 TCP，无 TLS

定位建连函数（本例 `BaseSocket.Async_Connect`），看 Socket 构造参数：

```
bl  <IPAddress.Parse>
bl  <new IPEndPoint(ip, port)>
bl  <new Socket(x0=addressFamily, w2=1 /*SocketType.Stream*/, w3=6 /*ProtocolType.Tcp*/)>
bl  <Socket.BeginConnect(endpoint, callback, state)>
... Socket.Poll(timeout)      # 连接超时
```

**阳性判据**：出现 `SocketType.Stream` + `ProtocolType.Tcp` + `BeginConnect`，
且同一调用链（含 `SocketObject.ConnectEX / ConnectSocket / AysConnect` 等封装）中
**没有**以下任一锚点：

- `SslStream`
- `AuthenticateAsClient` / `AuthenticateAsServer`
- `RemoteCertificateValidationCallback`
- `ServerCertificateCustomValidationCallback`
- `X509Chain` / `X509Certificate`（用于校验而非仅打包）
- `ServicePointManager`（.NET Classic 的证书回调）

**易误判**：程序集里存在 `System.Net.WebSockets` / `NativeWebSocket` 不代表业务用它们。
必须按「牌局消息类 → SocketObject → BaseSocket」的实际继承/调用链确认；本例 `wss://...:49104`
字面量仅是日志通道，与牌局数据面无关。

## 2. 静态判据 B：服务端地址是编进客户端的常量

从初始化入口顺调用链找配置赋值点（本例 `GlobalData.GameSocketInit`）：

```
bl  <AppStoreConfigManager.GetServerIp>      # 另一分支 DevelopmentManager.GetServerIp
bl  String.Split
bl  IPAddress.TryParse
bl  Int32.Parse
bl  <SocketObject.ConnectSocket>
```

再看 `AppStoreConfigManager.Init` 对 `ServerConfig` 字段的赋值处，把整批字面量一次列全：

| 字段 | 示例形态 | 说明 |
|---|---|---|
| serverip | `<backend-domain>:36610` | **牌局数据面**（裸 TCP） |
| httpip | `<backend-domain>:46750` | HTTPS / IIS |
| serverhttpip | `<backend-domain>:46712` | HTTPS / IIS |
| maintainip | `<backend-domain>:47000` | HTTPS / IIS |
| resip | `<backend-domain>/v2` | 静态资源 |
| logwebsocketurl | `wss://<backend-domain>:49104` | **仅日志**，不是牌局 |
| photoUrl / postphotoUrl | `<backend-domain>:52315 / :57632` | 图片 |

**阳性判据**：值是编译期常量，**既不来自服务端下发，也不来自 PlayerPrefs**。
若存在本地覆盖类（如 `DevelopmentManager` 读剪贴板 JSON 覆盖 ServerConfig），注意它只在本机生效，
不是远程可控面，不能算作"服务端可下发加密主机"的证伪证据。

## 3. 主动探针：证伪"其实有 TLS"

```python
# probe_plaintext_socket.py  —— 只做 TCP/TLS 探针，不发业务报文
import socket, ssl, sys, time

HOST, PORT = sys.argv[1], int(sys.argv[2])      # 牌局口，例 36610
SNI = sys.argv[3] if len(sys.argv) > 3 else HOST
CTRL = [(46750, 443), (46712, 443), (47000, 443)]  # 同批 HTTP 口做阳性对照

def tls_probe(host, port, sni, timeout=8):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as s:
                return "TLS-OK " + str(s.version())
    except Exception as e:
        return "TLS-FAIL %s: %s" % (type(e).__name__, e)

# 1) 牌局口：TCP 能否连、是否 TLS
try:
    s = socket.create_connection((HOST, PORT), timeout=8)
    s.settimeout(6)
    try:
        data = s.recv(64)
        print("game tcp: connected, server sent %r" % data)
    except socket.timeout:
        print("game tcp: connected, no server-initiated data in 6s (client speaks first)")
    s.close()
except Exception as e:
    print("game tcp: FAIL %s" % e)
print("game tls:", tls_probe(HOST, PORT, SNI))

# 2) 对照：同批 HTTP 口应该 TLS 握手成功
for p, _ in CTRL:
    print("control %d:" % p, tls_probe(HOST, p, SNI))
```

**判据表**（本靶标实测形态）：

| 端口 | 用途 | 结果 | 含义 |
|---|---|---|---|
| 牌局口 | serverip | TCP 通；TLS → `SSLEOFError: UNEXPECTED_EOF_WHILE_READING` | 不是 TLS 服务，裸 TCP |
| HTTP 口 ×3 | httpip/serverhttpip/maintainip | TLSv1.2 握手成功，`GET /` → 403 `<title>TEST-ERROR</title>` | 同批后端其他面已上 TLS |

**"只有牌局口是裸 TCP"就是本条的硬证据**：若连对照口也握手失败，应怀疑探针/网络问题，而不是直接下结论。
牌局口连接后 6s 内无服务端数据是正常的——该协议由客户端先发 protobuf（私有协议，非 HTTP）。

## 4. 影响与边界（不要过度上报）

成立的影响（无需凭据，但需 MITM 位置）：

1. 抓取完整牌局 TCP 会话：登录、改密、进房、发牌、公证数据的全部字段；
2. 篡改/注入报文并冒充服务端（协议无 TLS、无服务端身份校验）。

**未证的部分必须单独标注**：手牌字段中 `handCards` 为明文，`sHandCards` 为
`SecretData{publicKeyId, data[]}` 加密副本。若未验证客户端能否解开**他人**密文，
不得报"全桌手牌透视"，只能列为待证嫌疑。

## 5. 证伪条件 / 常见失败原因

- 反汇编里 `BaseSocket` 之外还有第二套**实际用于牌局**的 TLS/证书钉扎通道 → 本条不成立。
- `GameSocketInit` 在运行时被服务端下发值覆盖到其他加密主机 → 本条不成立（需动态验证）。
- **域名抢注/悬空接管路线先查再否决**：RDAP 查注册/到期/状态/NS，确认无过期、无悬空 CNAME、
  无可认领云资源。若域名可接管，则升级为"全部客户端被指向攻击者"的更严重问题；
  若不可接管（如到期日远在几年后、`client transfer prohibited`），只能在报告中写"DNS 未签名，
  投毒路径存在"，不能当作已利用。
- 探针全部 `TLS-FAIL` 时，先看是不是走了 HTTP 代理/SNI 被中间盒重置（用 `--noproxy`、并用同机已知
  TLS 服务做对照组），再下"目标不支持 TLS"的结论。

## 6. 修复建议

- 牌局通道改 TLS（`SslStream` / 原生 TLS）+ 证书钉扎；至少对登录、改密、公证与手牌报文做应用层
  端到端加密与签名。
- 客户端校验服务端身份（证书或预置公钥），禁止裸 TCP 承载凭据。
- 后端域启用 DNSSEC，降低 DNS 投毒导致整体劫持的风险。
- 评估 `SecretData` 是否按座位独立公钥加密；若客户端可解他人密文，即便上了 TLS 仍需服务端改造。

## 7. 本轮实际执行记录（可照抄）

1. `Resolve-DnsName <backend-domain> -Type A` → 得到 A 记录（存活）。
2. 对 `IP:36610` 发 TLS ClientHello（SNI=域名）→ `SSLEOFError UNEXPECTED_EOF_WHILE_READING`；裸 TCP connect 成功、6s 无服务端数据。
3. 对 `:46750/:46712/:47000` 发 TLS + `GET /` → `HTTP/1.1 403 Forbidden`、`Server: Microsoft-IIS`、正文 `<title>TEST-ERROR</title>`。
4. RDAP 查三个后端域名的注册/到期/NS/状态 → 均未过期、无悬空，排除抢注路线。
5. 结论：漏洞成立；本轮不具备 MITM 位置，未取得任何数据。

> 说明：文中的后端域名与 IP 已按规则以 `<backend-domain>` 占位，复现时从目标二进制
> 的 `AppStoreConfigManager.Init` 字段字面量处取真实值即可；RVA 数值为本样本专用，换样本需重新定位。

```
