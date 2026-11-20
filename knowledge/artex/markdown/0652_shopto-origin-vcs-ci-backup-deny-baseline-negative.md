# Apache 源站的 VCS/CI/备份直读面判据：名称型 403 与扩展名级 404 会把「不存在」伪装成「被保护」（shopto 3.8.196.174 实测阴性）

- **code**: shopto-origin-vcs-ci-backup-deny-baseline-negative
- **kind**: poc
- **category**: info-leak
- **component**: Apache httpd 2.4（.htaccess 名称规则 + RedirectMatch 404）
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 18:20-18:45 GMT，curl 直连 3.8.196.174:443（Host: localhost，--http1.0 --noproxy '*'）对 18 个真实目录 × 36 个 VCS/CI/备份名共约 700 次请求：/.git/HEAD=403/211B 且不存在的 /.git/zzq-nonexist-1138 同为 403/224B；/zzq1138.bak=404/209B（Apache 直答）而 /zzq-nonexist.html=404/1883B（应用页）；跨 pius.tech/www.shopto.de/shopto.com 的 vhost 同样 403；全部变体无 200。
- **tags**: vcs-leak,.git,.svn,.hg,backup,source-leak,apache,htaccess,false-negative,baseline
- **created_at**: 2026-11-11T18:41:25.408Z
- **engine**: https://3.8.196.174（shopto.net 源站，多 vhost）
- **found_by**: recon

## 描述

对 Web 源站做 .git/.svn/.hg/CI/构建清单/备份扫描时，必须先区分三种 404/403 语义，否则会把「规则拦截」误当「文件存在且被保护」，或把「不存在」误当「无泄露」：
1) 应用前端控制器 404（本例 404/1883B，带 CSP/XFO 头）＝请求被 rewrite 进 index.php，文件确实不存在（若存在会被 -f 条件静态服务，例如同目录 installed.json 就 200）。这是最可靠的「不存在」信号。
2) Apache 直接 404（iso-8859-1、正文回显请求路径、字节数=基数+路径长）＝URI 在映射前被 RedirectMatch/rewrite 排除类规则处理，与文件是否真实存在无关（.bak/.old/.orig/.save/.swp/.ini/.log/.sql/.map）。这类扩展名的备份即使存在也不可直读，不必再猜名字。
3) 名称型 403（Apache 默认 Forbidden 页）＝按 URI 名称静态拦截（点段、composer.json/lock、package(-lock).json、yarn.lock、README/CHANGELOG/LICENSE、gulpfile.js 等）。判据：请求一个同形但不存在的名字（如 /.git/zzq-nonexist-1138）也 403，则 403 与存在性无关，不能作为 .git 存在的证据。
可复用探测要点：① 先建三条基线（随机不存在路径、/.git/HEAD、/random.bak）；② 名称规则不可绕过（%2e/%67/双斜杠/尾点/尾斜杠/分号/反斜杠/%00/大小写/HTTP 方法/Accept:text/plain/跨 vhost 均实测无效；%2F 因 AllowEncodedSlashes Off 变 Apache 404）；③ 例外缝：/en/、/pp/ 这类由独立 .htaccess/前端控制器接管的子树可能完全不受根 deny 约束（本例 /pp/.git/HEAD 返回 200 登录页而非 403），以及 /index.php/&lt;PATH_INFO&gt; 可绕过 deny 进入应用（值得转向应用层文件读）；④ 目录存在性用「/dir/ → 403(存在且无索引)」vs「404/1883(不存在)」区分，整目录级 Require all denied 表现为该目录下任意不存在名字也 403。
本例净结论：.git/.svn/.hg/CI/13 种归档备份全部不可读，未取得源码或凭据；唯一可读构建清单是根 /bower.json 与 CKFinder vendor/composer/installed.json（见 finding#151）。
