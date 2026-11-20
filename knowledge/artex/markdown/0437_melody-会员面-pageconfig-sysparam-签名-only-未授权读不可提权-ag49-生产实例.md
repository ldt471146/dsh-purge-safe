# melody 会员面 pageconfig/sysparam 签名-only 未授权读不可提权（AG49 生产实例）

- **code**: melody-会员面-pageconfig-sysparam-签名-only-未授权读不可提权-ag49-生产实例
- **kind**: poc
- **category**: info-leak
- **component**: melody 会员 API (Spring Boot + openresty)
- **source**: self
- **verified**: 1
- **verified_note**: https://203.0.113.81:1273 实测：伪造 x-auth-uu/x-auth-sign（KEY=9&N4orgck9M!rh2#Wpfyg2Q!teDds8Bl）后空 token 返回 sysparam 97 项/11918B、pageconfig 51 条/54519B；configName 枚举 1000+ 个值仅 000(51)/001(50) 有数据；全量配置无 AK/SK/jdbc/口令；/pageconfig/* 与 /sysparam/* 写方法全 code 404；configName/configKey/orderBy/groupName 注入无真假分叉与 sleep 延迟；203.0.113.81 六端口 + ELB 203.0.113.126/203.0.113.111 的 /melody-admin、/admin、/manage 全 400/404。
- **tags**: melody,pageconfig,sysparam,unauthorized,negative,ag49
- **created_at**: 2026-10-19T20:38:14.601Z

## 描述

已验证的阴性路线：该未授权读仅泄露站点/菜单/运营域名与业务策略，不含可换取后台的凭据，且生产端管理后台在公网不可达。不要在同类 melody 实例上重复投入“由 pageconfig 读提权到后台”的方向；应转向管理端集群（如 target467.example.com 的 /melody-admin）或对象存储里泄露的管理端 DB 凭据。

## 用法

```
仅用于快速判定：若目标同族接口只校验 x-auth-sign 且返回 code 12200，可直接判定为配置泄露，不必在其上继续找写面/注入。
```
