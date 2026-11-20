# greenmangaming.com 官方 GitHub 成员公开 gist 泄露 Keystone 密钥服务内网架构（未认证 thrift proxy proxy.keystore.<env>.gmgfarm.com:9010 + PATCH /api/keys/{key_group}/extract/）

- **code**: gist-org-member-leak-keystone-thrift-proxy-internal-topology
- **kind**: script
- **category**: info-leak
- **component**: GitHub 公开 gist（企业官方组织成员账号）/ Keystone 密钥管理服务 / fenix 订单服务 / crt.sh / 公共 DNS
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: task#6 / finding_id=126（finding_checks.verdict=verified，status=confirmed）。2026-11-11 于 ARTEX 执行机复测（curl + jq + getent）：① GET https://gist.githubusercontent.com/ljennia/23ff7f65a3a5e4801d0247fb8905d55a/raw/ → HTTP 200、17731 B，正文含 "unauthenticated thrift proxy at proxy.keystore.<env>.gmgfarm.com:9010"、GET /api/keys/{key_group}/、PATCH /api/keys/{key_group}/extract/（200 返回 {"extracted_key":{"game_key":...}}）、celery-worker-<env> 需 roles/run.invoker、KEYSTONE_API_HOST、deploy/Pulumi.dev.yaml / Pulumi.prod.yaml；② 同刻 GET leepa gist raw → HTTP 200、25200 B，"Key Per Tier Fufilment" 含 fenix/store/models/bundle_config.py、fenix/orders/services/order/service.py、OrderKey = GameKey | CouponKey | TierKey、MongoDB/Protobuf；③ crt.sh ?q=%25.gmgfarm.com → HTTP 200、62 条证书，name_value 含 api.keystone.gmgfarm.com、api.keystone.dev.gmgfarm.com、comms[.dev].gmgfarm.com、*.gmgfarm.com；④ getent hosts → 10.236.0.5 / 10.246.0.49（均 RFC1918）。判据成立原因：四处来源均匿名可达且内容/解析结果与泄露文本互相印证。边界：仅确认信息公开泄露，未取得 gmgfarm.com 内网访问，未实际调用 thrift/REST 提取真实密钥。
- **path**: pocs/gist-org-member-leak-keystone-thrift-proxy-internal-topology/gist_ct_dns_internal_recon.sh
- **tags**: info-leak,recon,github-gist,官方成员泄露,crt.sh,证书透明,被动-dns,rfc1918,keystone,thrift,thriftpy2,game-key,internal-topology,greenmangaming,gmgfarm
- **created_at**: 2026-11-11T17:24:49.887Z
- **engine**: greenmangaming.com / gmgfarm.com（api.keystone.gmgfarm.com→10.236.0.5，api.keystone.dev.gmgfarm.com→10.246.0.49）
- **found_by**: recon

## 描述

企业官方 GitHub 组织成员的公开 gist 常含内部迁移/设计文档（本案例为 Keystone 密钥服务 thrift→REST 迁移方案与 fenix 订单服务实现计划），可直出内网域名、未认证 thrift proxy 主机:端口、内部 REST 密钥提取端点与 GCP IAM 服务账号命名；再用 crt.sh 与公共 DNS 把该内部域扩展成子域清单和 RFC1918 地址。全程零凭据只读，无直接密钥，价值在于为内网横向与密钥库存验证提供精确入口情报。

## 用法

```
1) 从目标公司 GitHub 组织/官网团队页拿成员 handle 并核对 profile 的 company 字段；2) 对每个 handle 拉 https://api.github.com/users/<handle>/gists?per_page=100，再取 https://gist.githubusercontent.com/<handle>/<gist_id>/raw/，grep 内部域名/端口/端点/IAM 关键词；3) 用泄露出的内部域查 crt.sh 与公共 DNS（本案例得 4 个子域 + 2 个 RFC1918 IP）；4) 反向核对泄露的 S3 桶是否匿名可读（403 AccessDenied=桶存在但拒绝匿名，属阴性对照，别当泄露点）；5) 只有拿到目标内网出口（VPN/SSRF/隧道/立足点）后才打 proxy.keystore.&lt;env&gt;.&lt;domain&gt;:9010（thriftpy2 + TBinaryProtocol/TFramedTransport，KeystoneService）或 PATCH /api/keys/{key_group}/extract/。GitHub 匿名 API 60 次/小时，crt.sh 常 502（备用 certspotter），内部域多 split-horizon（公网 NXDOMAIN 不代表不存在）。
```

## 正文

```
# 公开 gist → 内部密钥服务架构泄露：侦察与验证流程

## 0. 适用面与前置条件
- 目标企业有 GitHub 组织 / 官方成员账号，成员曾把内部迁移方案、设计文档、SRE runbook 贴进**公开 gist**。
- 攻击机可出网（HTTPS + DNS），**无需任何账号 / Cookie / Token**；GitHub 匿名 API 限 60 次/小时。
- 本流程只证明「信息暴露」。真正提取密钥（thrift `getKeys` 或 REST `/api/keys/.../extract/`）需要目标内网访问（VPN / SSRF / 隧道 / 内网立足点），否则只能拿到情报。
- 判据要交叉印证：gist 正文 + CT 日志 + 公共 DNS 三者互相命中才算成立；单靠 gist 只能说明"文档存在"，不能说明域名/IP 仍有效。

## 1. 组织成员与 gist 枚举
```bash
# 公开组织成员（部分企业关闭成员公开，则从官网团队页 / LinkedIn / 提交记录找 handle）
curl -sS "https://api.github.com/orgs/<ORG>/members?per_page=100" | jq -r '.[].login'

# 核对 handle 归属（看 company / blog 字段）
curl -sS -H 'Accept: application/vnd.github+json' "https://api.github.com/users/<HANDLE>" \
  | jq -r '[.login,.name,(.company//""),(.blog//"")]|@tsv'

# 该成员的 gist 列表
curl -sS -H 'Accept: application/vnd.github+json' \
  "https://api.github.com/users/<HANDLE>/gists?per_page=100" \
  | jq -r '.[] | [.id,(.description//""),.updated_at]|@tsv'
```
gist 标题/描述里出现 `migration plan`、`design doc`、`runbook`、`deploy`、`infra`、`<内部服务名>` 的优先拉。

## 2. 拉 raw 正文并筛关键词
```bash
curl -sS -m 30 "https://gist.githubusercontent.com/<HANDLE>/<GIST_ID>/raw/" -o g.raw -w '%{http_code}\n'
# 也可用 API 拿固定 revision：GET /gists/<GIST_ID> → files[].raw_url

grep -niE 'unauthenticated|thrift|proxy\.|:9010|/api/keys|/extract|roles/run\.invoker|service[_ -]?account|Pulumi\.(dev|prod)|KEYSTONE|mongodb|\.internal|\.corp|\.local' g.raw
```
命中特征示例（来自真实泄露文档）：
- `unauthenticated thrift proxy at proxy.keystore.<env>.<internal-domain>:9010`，`thriftpy2` + `TBinaryProtocol`/`TFramedTransport`
- thrift `KeystoneService`：`findKeyGroup` → `GET /api/keys/{key_group}/`；`getKeys` → `PATCH /api/keys/{key_group}/extract/`
- `PATCH .../extract/` 成功返回 `200 {"extracted_key":{"game_key":"<string>","metadata":{...}}}`，`204`=无库存，`404`=key group 不存在
- GCP 服务账号 `celery-worker-<env>` 需要 `roles/run.invoker`（Cloud Run IAM），`KEYSTONE_API_HOST` 走 Google OIDC
- `deploy/Pulumi.dev.yaml` / `Pulumi.prod.yaml` 的 `keystoneHost` / `keystonePort` 配置项

## 3. 用泄露的内部域查证书透明日志
```bash
curl -sS -m 60 "https://crt.sh/?q=%25.<INTERNAL_DOMAIN>&output=json" -o crtsh.json
jq -r '.[].name_value' crtsh.json | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sort -u
# crt.sh 502/超时时备用：
curl -sS "https://api.certspotter.com/v1/issuances?domain=<INTERNAL_DOMAIN>&include_subdomains=true&expand=dns_names" \
  | jq -r '.[].dns_names[]' | sort -u
```
优先看 `api.*`、`comms.*`、`*.dev.*` 以及带环境名的子域——内部 API 与消息面通常在这类命名下。

## 4. 公共 DNS 解析 + RFC1918 判定
```bash
for sub in $(cat subdomains.txt); do
  echo -e "$sub\t$(dig +short A "$sub" @8.8.8.8 | paste -sd, -)"
done | tee dns_map.tsv
awk -F'\t' '$2 ~ /(^|,)(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/ {print "RFC1918\t"$0}' dns_map.tsv
```
判定：公共递归解析器返回 RFC1918（10/8、172.16/12、192.168/16）地址 = 企业把内网记录发布到了公网 DNS，泄露内网网段与 IP，且可据此推断环境拓扑（生产/dev 各一段）。`NXDOMAIN` 不代表不存在（split-horizon）。

## 5. 阴性对照与伤害评估（必须做）
```bash
# 从 gist / 公开仓库里 grep 出的 S3 桶做匿名可达性对照
curl -sS -o /dev/null -w '%{http_code}\n' "https://<bucket>.s3.amazonaws.com/?list-type=2"
# 403 AccessDenied = 桶存在但拒绝匿名（阴性，不可当泄露点）
# 404 NoSuchBucket = 桶不存在
```
同理对泄露出的任何外部存储/端点做一次实测，避免把"名字"当"可访问"。

## 6. 拿到内网出口后的后续验证（本次未执行）
1. `proxy.keystore.<env>.<internal-domain>:9010` 是文档明示的**未认证** thrift 代理，TBinaryProtocol/TFramedTransport；用 `thriftpy2` 加载 `KeystoneService` 定义，先调 `findKeyGroup` 枚举 key group，再调 `getKeys` 取单 key。
2. 或走 REST：`GET /api/keys/{key_group}/` 枚举；`PATCH /api/keys/{key_group}/extract/` 提取（返回 `game_key`）。REST 侧需要 Cloud Run OIDC（`roles/run.invoker`），这也是文档泄露的 IAM 信息用途。
3. 该目标文档同时泄露订单侧 `fenix`：`OrderKey = GameKey | CouponKey | TierKey`、MongoDB 订单、Protobuf/BigQuery 回流，可用于判断密钥被消耗后的履约链路与影响面。

## 7. 失败时的常见原因
- gist 已删除/转为 secret → `404`；用 Wayback Machine / GitHub API 的 fork / 引用该 gist 的仓库找副本。
- GitHub API `403` 且 `X-RateLimit-Remaining: 0` → 匿名配额耗尽（60/h），改用 raw 端点（不占 API 配额）或稍后重试。
- crt.sh `502`/超时 → 换 certspotter / hostsearch / rapiddns。
- 公共 DNS 返回 `NXDOMAIN` → 内部域只存在于 split-horizon DNS；不代表记录不存在，需从 gist 或内部泄漏的 resolv.conf 找内网 DNS。
- 只拿到 gist 文档就下"可提取密钥"结论 → 错误。必须区分「文档声称未认证」与「实测可达」；没有内网出口时结论只能写到情报层。

## 8. 来源案例（2026-11-11 实测，greenmangaming.com / gmgfarm.com）
- 成员 `ljennia`（profile company=@greenmangaming）、`leepa`。
- gist `23ff7f65a3a5e4801d0247fb8905d55a`（"EPS Worker: Thrift Proxy to Keystone REST API Migration Plan"）raw → 200 / 17731 B，含上述 thrift proxy、REST 端点、`celery-worker-<env>` + `roles/run.invoker`、`deploy/Pulumi.*.yaml`、`KEYSTONE_API_HOST`。
- gist `0a35abffd295107f0809e9458ed44772`（"Key Per Tier Fufilment"）raw → 200 / 25200 B，含 `fenix/store/models/bundle_config.py`、`fenix/orders/services/order/service.py`、`BundleTierConfig`/`ProductKeyGroupMappingConfig`、`OrderKey` union、MongoDB/Protobuf。
- crt.sh `%25.gmgfarm.com` → 200 / 62 条证书：`api.keystone.gmgfarm.com`、`api.keystone.dev.gmgfarm.com`、`comms.gmgfarm.com`、`comms.dev.gmgfarm.com`、`*.gmgfarm.com`（Google Trust Services）。
- 公共 DNS：`api.keystone.gmgfarm.com → 10.236.0.5`；`api.keystone.dev.gmgfarm.com → 10.246.0.49`（均 RFC1918）。
- 阴性对照：`gmg-general-dev-test.s3.amazonaws.com` 匿名列举 → `403 AccessDenied`（桶存在但不可匿名访问，来自公开仓库 `greenmangaming/validation-code`），不能算泄露点。
- 结论边界：仅确认信息公开泄露；未取得 gmgfarm.com 内网访问，未实际调用 thrift/REST 提取真实密钥。若后续取得内网出口，按第 6 节 host:port + 端点继续。
```
