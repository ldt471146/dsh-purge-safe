# Algolia 非 admin key 写/控制面 ACL 判定（阴性）与伪阳性陷阱

## 结论
前端泄露的 32hex 非 secured key（本例已具 search + listIndexes + settings 读）并不自动带任何写 ACL。逐端点实测全部被拒：

| 操作 | 请求 | 本靶标结果 | 判据 |
|---|---|---|---|
| addObject | POST /1/indexes/{temp} body={objectID,marker} | 403 {"message":"Method not allowed with this API key"} | 无 addObject |
| addOrUpdateObject | PUT /1/indexes/{temp}/{objectID} | 403 同文 | 无 addObject |
| deleteObject | DELETE /1/indexes/{temp}/{objectID} | 403 同文 | 无 deleteObject |
| deleteIndex | DELETE /1/indexes/{temp} | 403 同文 | 无 deleteIndex |
| clearIndex | POST /1/indexes/{temp}/clear | 403 同文 | 无 clearIndex |
| editSettings | PUT /1/indexes/{temp}/settings（非法/合法 body 两测） | 403 同文 | 无 editSettings；此端点 ACL 先于 body 校验 |
| copy/move index | POST /1/indexes/{temp}/operation {operation:copy/move,destination} | 403 同文 | 无 operation 权限 |
| addApiKey | POST /1/keys | 403 {"message":"Invalid Application-ID or API key"} | 非 admin |
| listApiKeys | GET /1/keys | 403 同文 | 非 admin |
| logs | GET /1/logs | 403 Method not allowed | 无 logs |
| browse | GET /1/indexes/{index}/browse?params= | 403 Method not allowed | 无 browse（独立 ACL） |

## 两个伪阳性陷阱（关键，别误报）
1) `POST /1/indexes/{temp}/operation` 传**非法** operation 值会返回 **400** `{"message":"Invalid value 'xxx' Expected: move, copy"}`——该端点 body 枚举校验先于 ACL，400 不代表"有权"。只有**合法 copy/move payload** 的 403 才是 ACL 拒。
2) `POST /1/indexes/{temp}/batch` 传**空** `{"requests":[]}` 返回 **200** `{"taskID":0,"objectIDs":[]}`——batch 逐动作鉴权，空请求无动作故放行。带动作时：addObject → 400 `Not enough rights to add an object`，deleteObject → 400 `Not enough rights to delete an object`。
3) `PUT /1/indexes/{temp}` 裸路由 → 404 `Path not supported by Algolia REST API`，不是权限判据。

## 验证命令
```bash
APP=<APPID>; KEY=<key>; IDX=zzq_acl_$(date +%s); BASE=https://$APP.algolia.net
H=(-H "X-Algolia-Application-Id: $APP" -H "X-Algolia-API-Key: $KEY" \
   -H "Referer: https://<target>/" -H "Content-Type: application/json")
curl -s "${H[@]}" -X POST --data '{"objectID":"zzq1","marker":"m"}' "$BASE/1/indexes/$IDX" -w '\n%{http_code}\n'
curl -s "${H[@]}" -X PUT  --data '{"hitsPerPage":20}'                "$BASE/1/indexes/$IDX/settings" -w '\n%{http_code}\n'
curl -s "${H[@]}" -X POST --data "{\"operation\":\"copy\",\"destination\":\"${IDX}_dst\"}" "$BASE/1/indexes/$IDX/operation" -w '\n%{http_code}\n'
curl -s "${H[@]}" -X POST --data '{"requests":[{"action":"addObject","body":{"objectID":"z","marker":"m"}}]}' "$BASE/1/indexes/$IDX/batch" -w '\n%{http_code}\n'
curl -s "${H[@]}"                                  "$BASE/1/keys" -w '\n%{http_code}\n'
# 清理/复核：临时索引应恒 404，最终 GET /1/indexes 与基线逐名一致
```

## 清理与无副作用判据
- 探后 `POST /1/indexes/{temp}/query` 恒 404 `Index ... does not exist`（从未创建任何索引）；
- 最终 `GET /1/indexes` 与基线集合逐名比对 added=[] removed=[]，总数不变。

## 误判提醒
- key 无 restrictIndices 时（listIndexes 返回全部命名空间、可查询任意索引），上述 403 是真实 ACL 拒绝而非索引白名单效应；
- 不要把 403 `Method not allowed with this API key` 当成 key 失效——它与 403 `Invalid Application-ID or API key`（key 管理端点）语义不同：前者=key 有效但该操作无 ACL。