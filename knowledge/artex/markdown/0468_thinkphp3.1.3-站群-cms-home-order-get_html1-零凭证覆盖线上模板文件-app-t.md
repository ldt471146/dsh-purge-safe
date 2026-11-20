# ThinkPHP3.1.3 站群 CMS：Home/Order::get_html1 零凭证覆盖线上模板文件（App/Tpl/Home/Index_index.html、Index_indexapp.html）

- **code**: thinkphp3.1.3-站群-cms-home-order-get_html1-零凭证覆盖线上模板文件-app-t
- **kind**: poc
- **category**: unauthorized
- **severity**: high
- **source**: manual
- **tags**: unauthorized-file-write
- **created_at**: 2026-10-28T19:41:01.752Z

## 描述

目标 192.0.2.1（https://target479.example.com，SomCNS/ThinkPHP 3.1.3，docroot /www/wwwroot/thisthbweb_com）Home 组 OrderAction 不继承 CommonAction，零凭证 GET /index.php?g=Home&m=Order&a=get_html1 即让服务端把 /List/index&type=0|1 的渲染结果覆盖写入 App/Tpl/Home/Index_index.html（337099B, md5 8f254016…）与 Index_indexapp.html（337098B, md5 99b803d6…），并以 /Upload/atop/attime3_5.txt 的 time() 推进（1793211399→1793213381→1793213805）作写入铁证；抓取源与文件名均由服务端硬编码，参数 url/ename/domain/tpl/path/content 全惰性，故当前未升级为 RCE，但构成未授权模板文件覆盖，配合任一写库入口即可闭合模板注入 RCE。
