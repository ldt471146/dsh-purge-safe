# 判定某域名是否有官方 iOS/macOS/桌面客户端产物（五源交叉，5 分钟）

## 1) iTunes Search API（官方，权威）
```bash
UA="$ARTEX_UA"
for term in "GreenManGaming" "Green Man Gaming" "GMG" "greenmangaming" "Playfire"; do
  for cc in us gb de jp cn ca au fr; do
    curl -s -A "$UA" "https://itunes.apple.com/search?term=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$term")&entity=software&limit=50&country=$cc" \
      | python3 -c "import json,sys;d=json.load(sys.stdin);print('$term/$cc',d['resultCount'],[(r.get('trackName'),r.get('bundleId'),r.get('sellerName')) for r in d['results'] if 'brand' in str(r).lower()])"
  done
done
# macOS 同样跑 entity=macSoftware
```

## 2) bundleId lookup（枚举猜测）
```bash
for b in com.brand.ios com.brand.app com.brand.android com.brand.client com.brand.mobile com.brand.apps com.brand.store; do
  printf "%-40s " "$b"; curl -s -A "$UA" "https://itunes.apple.com/lookup?bundleId=$b" | python3 -c "import json,sys;d=json.load(sys.stdin);print(d['resultCount'],[r.get('trackName') for r in d['results']])"
done
```
resultCount=0 → 该 bundleId 从未上架/已下架（App Store 不保留下架记录，只能靠 archive 复核）。

## 3) Universal Links / App Links 权威声明（站点侧）
```bash
for h in www.example.com api.example.com; do for p in /.well-known/apple-app-site-association /apple-app-site-association /.well-known/assetlinks.json; do
  printf "%-30s %-42s " "$h" "$p"; curl -s -A "$UA" -o /tmp/a -w "%{http_code} %{size_download} %{content_type}\n" "https://$h$p"
done; done
```
两条都 404 → 站点未与任何 app 建立关联（有 app 但不下发 AASA 也可能存在，所以只作辅证）。

## 4) 官方分发渠道
- Google Play: `https://play.google.com/store/apps/details?id=<pkg>&hl=en_US` → 404=已下架；`/store/apps/developer?id=<厂商>` 404=无该开发者。
- 微软商店: `https://storeedgefd.dsx.mp.microsoft.com/v9.0/search?query=<name>&market=US&locale=en-US&mediaType=Apps&deviceFamily=Windows.Desktop`（加 --compressed，解析 Payload.SearchResults[].Title）。
- Chrome Web Store: `https://chromewebstore.google.com/search/<name>`（须排除第三方）。
- 官网 /download /client /app /mobile /desktop：注意区分 200+Forbidden 页面 与真下载页。

## 5) 代码托管/制品
GitHub org repos（`api.github.com/orgs/<org>/repos?per_page=100`）里找 client/launcher/electron/mobile 仓库；仓库不存在即无开源产物。

## 结论口径（greenmangaming 实测）
五源全空 → 目标没有可获取的官方 iOS/macOS/桌面客户端，不要在这条路上继续花预算；移动端凭据载体只在 Android 第三方镜像（com.greenmangaming.android v1.6.4，已逆向）存在，且该包内无 GMG 自有 OIDC 的 client_id/client_secret。