实测矩阵（guest，无 Cookie，HTTP/1.0 + Host: vip2.hk000999.com.）：
bank      200 26342  title=银行        登录墙
blog      200 26346  title=博客接口    登录墙
rate      200 26318  title=评价管理    登录墙（reason1 固定为「评价参数错误」，补 action=log/show/rate、tid/pid/value 文案不变，非预鉴权处理）
new       200 26328  未安装此插件或此插件无前台显示
passport  200 26333  未安装
toolcenter 302 Location: profile.php?action=toolcenter（action=mytool/user&uid=1/buy&id=1/use 与 POST use 均 302）
负对照 ../../upload、upload、medal、invite、BANK、bank/ → 全部「未安装」，白名单键查表 + is_dir + file_exists 生效，穿越/大小写/尾斜杠无效
写类 POST 直测：bank action=save/virement、blog action=publish → 200 登录墙；toolcenter action=use → 302
结论：guest 侧不存在任何可达的插件页面与写文件/上传/导出动作；插件写逻辑在鉴权之后。延伸面：profile.php?action=* 是独立路由，需单独核查。