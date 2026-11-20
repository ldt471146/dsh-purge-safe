# AG49 会员端 Spring Boot 2.x 框架层 N-day 与反序列化全否（Shiro/Spring4Shell/CVE-2018-1273/Fastjson/actuator/env）

- **code**: ag49-会员端-spring-boot-2.x-框架层-n-day-与反序列化全否-shiro-spring4shel
- **kind**: markdown
- **category**: deserialization
- **component**: Spring Boot 2.x + springfox 2.8.0-SNAPSHOT + openresty 203.0.113.8
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-20 实测：/melody/actuator 返回 application/vnd.spring-boot.actuator.v2+json 且仅 self 链接；env/heapdump 及 ;.json/%3b///..;/大小写全变体 404。test1-admin 同探针 Set-Cookie: rememberMe=deleteMe 作阳对照，AG49 八个路径无 deleteMe。14 个端点的 class.module.classLoader 与 page[#this...] 三轴与基线逐字节相同，form-urlencoded 提交业务参数返回与空 body 相同的参数校验错误（JSON 才进业务）。dnslog 同 session 本地 nslookup 回读 4 条自证后，Fastjson Inet4Address/1.2.47 JdbcRowSetImpl/Jackson @class 共 9 marker 零回连。
- **created_at**: 2026-10-19T22:53:59.905Z

## 描述

结论：该会员 API 的 Java 反序列化/表达式注入面在原理层面不成立，不要在 1273 上重复投入。① 版本：Spring Boot 2.x（actuator v2 media type + springfox.css?v=2.8.0-SNAPSHOT，2018 年代），openresty 203.0.113.8 前置且做严格 location 白名单。② 无 Shiro：全路径 rememberMe 无 deleteMe。③ 无 POJO 绑定：控制器全部 @RequestBody JSON，表单参数不生效，故 Spring4Shell(CVE-2022-22965) 与 CVE-2018-1273 的 PropertyPath SpEL 无触发点。④ 无 Spring Data REST（/profile /browsers code 404）。⑤ 解析器为严格 Jackson（@type/@class 被忽略、非法 JSON 明确报 JSON 解析错误），非 Fastjson、无 default typing；application/xml 的 XStream 与原生序列化字节不被解析。⑥ actuator 仅 self，env/heapdump 不可得，management base-path 变体亦 404。线索：openresty 白名单含 /melody/api/*、/melody/actuator、/melody/swagger-ui.html、/melody/webjars/*、/melody/swagger-resources/* 以及 /lark/*，其余 /melody/* 为 openresty 空体 404；可据此枚举其它可达后端前缀。

## 用法

```
复用判据：1) 先用 GET /melody/actuator 看 media type 定 Spring Boot 世代；2) Shiro 存在性用 `Cookie: rememberMe=1` 看 Set-Cookie 是否 deleteMe（务必带一个已知有 Shiro 的目标做阳对照）；3) 判断是否值得打 Spring4Shell/CVE-2018-1273：用 form-urlencoded 提交业务字段，若返回「参数校验未通过」而 JSON 能进业务，即无 @ModelAttribute 绑定，直接放弃；4) Fastjson 判别：发 {"@type":"target297.example.com.Inet4Address","val":"<rand>.<dnslog域名>"}，被当未知字段忽略与空 body 同响应即 Jackson；5) dnslog 必须用同一 Session 取域名并轮询，否则 getrecords 恒空（本坑已踩）。
```
