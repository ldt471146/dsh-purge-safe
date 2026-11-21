# ThinkPHP 3.1.3 站群 CMS(166)：Admin/Autoart 控制器零鉴权读取后台并可直接写入开奖数据

- **code**: thinkphp-3.1.3-站群-cms-166-admin-autoart-控制器零鉴权读取后台并可直接写入开奖数
- **kind**: poc
- **category**: unauthorized
- **severity**: critical
- **source**: manual
- **tags**: unauthorized-access
- **created_at**: 2026-10-28T19:41:01.817Z

## 描述

45.151.135.166（SomCNS/ThinkPHP 3.1.3，docroot=/www/wwwroot/kkjjer_com）的 Admin/Autoart 控制器运行期完全不做登录与 Host 校验：零 Cookie 即可访问后台整套开奖管理页（kjer/indexam/catlist/editkjer），读出 100 条开奖记录（ID 6070~6100，期号 2026291~2026301 含码数/特码/生肖/波色），并可通过 POST editkjer 直接向数据库插入记录（实测写入 ID 6101、期号 9996048，随后在 kjer 列表原样回显）。同站同分组的 Index/User/Main/System 均 302，说明 Autoart 自行覆盖 _initialize 跳过了 CommonAction 鉴权。
