# 悬空 CNAME 子域接管面：批量枚举与判据

## 前置条件
- 能发公共 DNS 查询（8.8.8.8 / 1.1.1.1 / 9.9.9.9 可达）
- 只读操作，无需目标凭据
- 工具：dnsx (ProjectDiscovery) + nslookup + curl

## 批量枚举（核心流水线）
```
# 1) 子域清单 subs.txt
cat subs.txt
# 2) 取每条子域的 CNAME 目标
dnsx -l subs.txt -cname -resp -silent > cname.txt
# 3) 抽出唯一 CNAME 目标并解析
awk '{print $NF}' cname.txt | sed 's/\.$//' | sort -u > cname_targets.txt
dnsx -l cname_targets.txt -a -resp -silent > resolved.txt     # 能解析出 IP 的目标
# 4) 未解析(NXDOMAIN) = 悬挂目标
comm -23 <(sort -u cname_targets.txt) <(awk '{print $1}' resolved.txt | sort -u) > dangling_targets.txt
```

## 单条复核（多解析器一致性）
```
nslookup -type=CNAME api-cn.<target> 8.8.8.8       # 看 CNAME 指向
nslookup api-cn.<target> 8.8.8.8                   # 期望 NXDOMAIN（悬挂）
nslookup api-cn.<target> 1.1.1.1
nslookup api-cn.<target> 9.9.9.9                   # 三个解析器结论一致才采信
curl -sS -o /dev/null -w '%{http_code}\n' https://api-cn.<target>/   # 期望 000
```

## 判据
- 子域存在 CNAME 记录，且 CNAME 目标对 8.8.8.8/1.1.1.1/9.9.9.9 均返回 NXDOMAIN → 悬挂
- 子域本身解析失败(NXDOMAIN) / HTTP 000 → 无活跃后端
- 认领可行性：厂商侧资源名可被外部注册/认领（SoloCDN 自定义子域、Heroku、S3、部分 ELB 命名）→ 可接管；AWS API Gateway 的 `d-xxxxxxxx` 随机名、F5 XC 的 `ves-io-<UUID>` 名外部不可复刻 → 仅记风险面

## 实测实例（target = greenmangaming.com，2026-11-11 14:44-14:50 UTC）
批量：`dnsx -l subs.txt -cname -resp -silent` → 38 条 CNAME / 25 个唯一目标；`dnsx -l cname_targets.txt -a` 后 `comm -23` → 7 个未解析（悬挂）目标，逐条三解析器复核一致：

| 子域 | CNAME 目标 | 目标状态 | 厂商 |
|---|---|---|---|
| api-cn | api-cn.greenmangaming.com.lxcvc.com | NXDOMAIN | SoloCDN（命名可控，唯一具备认领可能） |
| email-prod | d-gagbjg3yxc.execute-api.us-east-1.amazonaws.com | NXDOMAIN | AWS API Gateway（d- 随机名，不可复刻） |
| email-staging | d-ez8ebkwgof.execute-api.us-east-1.amazonaws.com | NXDOMAIN | AWS API Gateway |
| secure | secure-022014-1254520137.us-east-1.elb.amazonaws.com | NXDOMAIN | AWS ELB |
| team17 | soupkitchenwebfe-2018403816.us-east-1.elb.amazonaws.com | NXDOMAIN | AWS ELB |
| neom | neofrontal-1025432939.us-east-1.elb.amazonaws.com | NXDOMAIN | AWS ELB |
| machine-f5.ddp | ves-io-388e0a56-3387-4781-93ee-15f189b96c5b.ac.vh.ves.io | NXDOMAIN | F5 Distributed Cloud |

子域侧 HTTP 佐证：`curl https://<任一悬空子域>/` → HTTP 000（无法解析，与目标 NXDOMAIN 一致）。

原始回显样例：
```
$ nslookup -type=CNAME api-cn.greenmangaming.com 8.8.8.8
  api-cn.greenmangaming.com canonical name = api-cn.greenmangaming.com.lxcvc.com.
$ nslookup api-cn.greenmangaming.com 8.8.8.8
  ** server can't find api-cn.greenmangaming.com: NXDOMAIN
```

## 影响
能在对应厂商注册/认领同名资源者，即可用受控内容响应目标子域 → 钓鱼、Cookie 作用域滥用、邮件域信任滥用。本例中 AWS 生成名与 F5 UUID 类认领不可行，风险主要落在 api-cn(SoloCDN) 一条。

## 证伪条件
若这 7 个 CNAME 目标解析得到有效 IP（非 NXDOMAIN），或云厂商回显该资源名归属其它活跃账户且拒绝外部认领，则本判断不成立。

## 失败常见原因
- 用本地/运营商 DNS 缓存 → 必须显式指定 8.8.8.8/1.1.1.1/9.9.9.9 再判
- 泛解析域名：根域无 A 但随机子域有 A，会误判；先确认是否存在泛解析
- CNAME 目标已解析出 IP（资源仍活）→ 不是悬挂，仅是新版云边缘
- 命名不可控的厂商无法实际认领，只能定性为风险面
