# vhost 真伪判定（SNI 双置位法）：curl --resolve 同时置位 SNI+Host + 逐 SNI 证书对比

- **code**: vhost-真伪判定-sni-双置位法-curl-resolve-同时置位-sni-host-逐-sni-证书对比
- **kind**: script
- **category**: recon
- **versions**: IIS 8+/nginx/apache 通用
- **severity**: info
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-09-29 在 tgt9942-com 靶标 203.0.113.72:443 上实测：9 组 Host（example.com、h5./admin./cdn.example.com、target69.example.com、target71.example.com、target72.example.com、target62.example.com、localhost）经 --resolve 双置位后响应均为 200/1204B 且 sha256 完全一致；6 组 SNI 握手均返回 CN=*.target69.example.com（Certum DV，2026-12-24 到期）。据此确认该机为「单默认站点、单一证书绑定、无 vhost」，并修正了此前「只改 Host 头不改 SNI」的取证缺陷。同时该脚本第 3 步暴露了一个真实配置问题：SNI=example.com 时返回的是 *.target69.example.com 证书（域名不匹配，已落 vuln_id=54）。
- **path**: pocs/vhost-真伪判定-sni-双置位法-curl-resolve-同时置位-sni-host-逐-sni-证书对比/vhost-true-check.ps1
- **tags**: vhost,sni,iis,方法论,避坑
- **created_at**: 2026-09-28T23:33:28.329Z
- **found_by**: vuln-scan

## 描述

用 curl --resolve 同时置位 SNI 与 Host 来判定 vhost 真伪，避免「只改 Host 头不改 SNI」导致的误判；并逐 SNI 对比证书数量。本队此前对 203.0.113.72 的 vhost 结论即由该方法修正后加固。

## 用法

```
pwsh .\vhost-true-check.ps1 -Ip 203.0.113.72 -Port 443 -Hosts "example.com,h5.example.com,target69.example.com,localhost"
# 判读：① 所有 Host 响应 sha256 相同 ⇒ 无 vhost；② 所有 SNI 返回同一 Subject ⇒ 只有一份证书绑定。
# 反例（曾误判的场景）：只发 `curl -H "Host: admin.x.com" https://IP/`，SNI 仍是 IP，
#   若目标按 SNI 绑定多站点，会漏掉所有非默认站点。
```

## 正文

```
#!/usr/bin/env pwsh
# vhost-true-check.ps1 —— 判定目标「是否真的没有 vhost 分流」的严谨方法
# 背景：本队历史上用 `curl -H "Host: xxx" https://IP/` 测 vhost，**只改了 Host 头，TLS 层的 SNI 仍是 IP**。
#       IIS 站点可以按 SNI 绑定（同一 IP 多证书），此时「Host 改了但 SNI 没改」会得到错误结论。
#       2026-09-29 对 203.0.113.72 复核时发现该缺陷，遂固化为脚本。
#
# 用法: .\vhost-true-check.ps1 -Ip 203.0.113.6 -Port 443 -Hosts host1,h host2,host3

param(
  [Parameter(Mandatory=$true)][string]$Ip,
  [int]$Port = 443,
  [Parameter(Mandatory=$true)][string[]]$Hosts
)

$ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/203.0.113.48 Safari/537.36"

Write-Host "=== 第 1 步：SNI + Host 同时置位（curl --resolve 一步到位） ==="
$sigs = @{}
foreach ($h in $Hosts) {
  # --resolve 让 curl 用 $h 做 SNI，同时把 Host 头也设成 $h —— 这才是「真 vhost 请求」
  $out  = "$env:TEMP\vhost_$($h -replace '[^a-zA-Z0-9]','_').html"
  $r = & curl.exe -k -s -A $ua --resolve "${h}:${Port}:${Ip}" `
        -o $out -w "%{http_code} %{size_download}" "https://${h}/" --max-time 15
  $sha = (Get-FileHash $out -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
  $sigs[$h] = "$r|$sha"
  Write-Host ("{0,-40} -> {1} sha256={2}" -f $h, $r, ($sha -replace '^(.{16}).*','$1'))
}

Write-Host "`n=== 第 2 步：判定 —— 所有响应签名是否完全一致 ==="
$uniq = $sigs.Values | Sort-Object -Unique
if ($uniq.Count -eq 1) {
  Write-Host "所有 Host 响应逐字节相同 ⇒ 单默认站点，确无 vhost 分流" -ForegroundColor Green
} else {
  Write-Host "存在不同响应 ⇒ 有 vhost 分流，逐条对比下列差异：" -ForegroundColor Yellow
  $sigs.GetEnumerator() | Group-Object Value | Where-Object Count -lt $Hosts.Count |
    ForEach-Object { Write-Host ("  [{0}] {1}" -f $_.Count, (($_.Group | ForEach-Object { $_.Key }) -join ", ")) }
}

Write-Host "`n=== 第 3 步：证书按 SNI 对比（有几张证书 = 有几个绑定） ==="
foreach ($h in $Hosts) {
  try {
    $tcp = New-Object target70.example.com.Sockets.TcpClient; $tcp.Connect($Ip, $Port)
    $ssl = New-Object target70.example.com.Security.SslStream($tcp.GetStream(),$false,([target70.example.com.Security.RemoteCertificateValidationCallback]{$true}))
    $ssl.AuthenticateAsClient($h)
    $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
    Write-Host ("SNI={0,-40} => {1} (NotAfter {2:yyyy-MM-dd})" -f $h, $c.Subject, $c.NotAfter)
    $ssl.Close(); $tcp.Close()
  } catch { Write-Host ("SNI={0,-40} => ERR {1}" -f $h, $_.Exception.Message.Split([char]10)[0]) }
}
Write-Host "`n判读：全部 SNI 返回同一张证书 ⇒ 机器上只有一份证书绑定（通常 = 只有一个站点）。"
Write-Host "      一张证书对应多个 Host 时，仍需看第 1/2 步的响应体是否一致才能下 vhost 结论。"

```
