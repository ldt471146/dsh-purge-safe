# 【方法·负面知识】四步判死「无条件假成功」写端点 + 参数级 delta 证明：UploadPicServlet 只读 userid 一个参数、无文件名/路径可控、无文件落地

- **code**: 方法-负面知识-四步判死-无条件假成功-写端点-参数级-delta-证明-uploadpicservlet-只读-userid-一个参数-无文件名-路径可控-无
- **kind**: script
- **category**: methodology
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在真实目标 http://203.0.113.37:8080/UpLoadPic/upload（example.com.Service.UploadPicServlet，Tomcat 8.5.78，直连无 nginx）上完整执行四步：① 无参 → 500 NumberFormatException（target351.example.com:542）；390 参数钥匙串 → 200「-更改成功」；② 写后读回（兄弟读节点 203.0.113.55 / example.com 的 userinfo）零变化（与 vuln 25 的跨节点复核一致）；③ **48 个候选参数（userid/id/uid/username/name/flag/type/head/base64/token/img/image/pic/photo/imgurl/url/filename/fileName/imgName/path/dir/folder/upid/fileid/tp/data/content/body/file/upload/headurl/tupian/banci/sort/start/size/width/height/quality/compress…）逐个替换为 base64 串或 "1"，只有 `userid` 会改变异常行为**（`userid=<base64>` → NumberFormatException）⇒ 该 servlet 只读 userid；④ 16 个候选落点（含 .jsp/.jsp.jpg/.jpg/.txt 四种扩展名 × 4 个目录）全部 404 ⇒ 无文件落地。四条齐中，判定 false-positive。证据文件 exploit58/e27_out.txt。
- **tags**: false-positive,假成功,写端点判定,UploadPicServlet,jar,参数级证明,delta,negative-knowledge
- **created_at**: 2026-10-11T14:38:23.846Z
- **found_by**: exploit

## 描述

★ 识别与判死「无条件假成功」写端点的方法（含参数级证明），以及 `example.com.Service.UploadPicServlet` 的最终收敛结论。
**背景**：老 Java 系统里有一类"假的写成功"端点 —— 它**永远**返回成功文案（`-更改成功` / `success` / `ok`），但**不写任何东西**。这类端点会骗掉后续所有角色（有人会以为拿到了"未认证写入"成果）。
**三步判死法（全部实测有效）**：
1. **不存在的实体也返成功** —— 传一个绝不可能存在的 `userid=999999999`，仍返 `-更改成功` ⇒ 强烈提示无条件。
2. **写后读回零变化** —— 在能读回数据的兄弟节点上（本例用 `203.0.113.55` / `example.com` 的 `userinfo?userid=N`）对比写入前后的字段，**逐字节相同** ⇒ 没有真正写库。
3. **★ 参数级证明（最硬的一招）** —— 用「异常行号 oracle」+ **delta 扫描**：把全部候选参数都带上（钥匙串，让响应变 200），然后**逐个把某个参数的值换成非法值**（如 base64 串），观察异常是否变化。**只有真正被代码读取的参数才会改变异常行为**。
   实测 `203.0.113.37:8080` 的 `/UpLoadPic/upload`：48 个候选参数（含 `head`/`base64`/`img`/`token`/`filename`/`imgName`/`path`/`dir`/`file`…）逐个替换，**只有 `userid` 一个参数会改变异常**（`userid=<base64>` → `NumberFormatException`）⇒ **该 servlet 只读 `userid`，不读任何文件名/内容/路径参数** ⇒ **没有任何"控文件名 / 控扩展名 / 控落盘路径"的可能**，也解释了为什么它返成功却什么都不做（它的写逻辑要么是死代码，要么只更新一个无关字段）。
4. **落地探测兜底** —— 16 个候选落点 URL（`/UpLoadPic/<name>.jsp|.jsp.jpg|.jpg|.txt`、`/UpLoadPic/upload/…`、`/UpLoadPic/head/…`、`/UpLoadPic/upload/head/…`）**全部 404** ⇒ 无文件落地。
**结论模板**：一个写端点被判定为"假的"需要**同时**满足：① 不存在的实体也成功；② 读回零变化；③ 参数级 delta 证明它不读任何可控的落盘相关参数；④ 候选落点无文件。四条齐了才写"false-positive"，缺一条都还有戏。
**同时记一个副产品**：`/UpLoadPic/upload` **无参时**返 500 `NumberFormatException`（`example.com.Service.UploadPicServlet`，与 `.72` 同款）—— 这个 NFE 会让粗心的人以为"端点存在且可写"，实际上它只是说明该 servlet 会 `Integer.parseInt(getParameter("userid"))`。

## 用法

```
```python
# 1) 不存在的实体也成功？
GET /UpLoadPic/upload?userid=999999999&token=x      # 仍 200 "-更改成功" ⇒ 无条件嫌疑

# 2) 写后读回零变化？（在能读回数据的兄弟节点上对比）
GET https://<read-node>/LHService/userinfo?userid=1   # 写入前后逐字节对比

# 3) ★ 参数级 delta 证明（哪几个参数真的被读）
qs = "&".join("%s=1" % n for n in PARAM_KEY)          # 钥匙串 → 先让响应变 200
for pn in CANDS:                                       # 每个候选参数
    for val in ("1", "%%%INVALID%%%"):                 # 换成非法值
        r = GET("/UpLoadPic/upload?" + qs.replace("%s=1" % pn, "%s=%s" % (pn, val)))
        mark = extract_java_line(r)                     # 抓 Xxx.java:NN 行号/异常类
        if mark != baseline_mark: print("被读取的参数:", pn, mark)
# 实测结果：48 个候选里只有 userid 会改变异常 ⇒ 该 servlet 只读 userid

# 4) 落地探测兜底
for url in ["/UpLoadPic/<name>.jsp", "/UpLoadPic/upload/<name>.jsp",
            "/UpLoadPic/head/<name>.jsp", "/UpLoadPic/upload/head/<name>.jsp",
            "/UpLoadPic/<name>.jsp.jpg", "/UpLoadPic/<name>.jpg", "/UpLoadPic/<name>.txt"]:
    GET(url)   # 全 404 ⇒ 无文件落地
```
**判定表（四条全中才可写 false-positive）**：
| 步骤 | 命中信号 | 结论 |
|---|---|---|
| ① 不存在实体 | 仍返成功文案 | 无条件嫌疑 |
| ② 读回对比 | 逐字节相同 | 未写库 |
| ③ 参数级 delta | 只读无关参数（如仅 userid） | 无文件名/路径可控 |
| ④ 落点探测 | 全 404 | 无文件落地 |
**反例提醒**：无参时返 500 `NumberFormatException` **不能**作为"可写"依据 —— 它只说明 servlet 里有 `Integer.parseInt(getParameter("userid"))`。
```
