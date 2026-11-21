# 目标站后台 Host 白名单闸门可用「包含白名单串的任意 Host」绕过（大小写敏感子串匹配）

- **code**: 目标站后台-host-白名单闸门可用-包含白名单串的任意-host-绕过-大小写敏感子串匹配
- **kind**: poc
- **category**: auth-bypass
- **severity**: medium
- **source**: manual
- **tags**: auth-bypass
- **created_at**: 2026-10-28T19:41:01.740Z

## 描述

目标 45.151.135.176 的 CommonAction 后台闸门对 Host 做大小写敏感子串匹配：白名单值 usertobbs.thb.mysqbbthisgoodsfor33333user.top（从被 get_html1 覆盖的模板渲染内容中提取）只要出现在 HTTP_HOST 里即放行——前缀加料（evil-…）与挂到攻击者域后缀（…top.attacker604.tld）均返回 200/919B 真实后台登录页，而原域名及另外 9 个候选 Host 一律 302/0B；未登录后台业务页仍 302（第二级登录态校验存在），故本条解开的是"后台入口不可达"，把登录面暴露给在线爆破/撞库。
