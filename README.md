# netmap（代理路径可视化）

本机只读页面，把每一类程序的流量经过哪些代理、最后从哪个 IP 出去画成一行一行的路径。只看不改，不碰任何系统设置。

## 打开

- pi 里输入 `/net`
- 或者双击 `open.command`

两种方式都会在后台没运行时先启动 `server.py`，再用 Chrome 独立窗口打开 `http://127.0.0.1:18320/`。页面关掉 10 分钟后，后台自动退出。

## 画了哪几条路径

| 路径 | 经过 |
|---|---|
| pi · GPT 模型 | SSH 隧道 :18318 → VPS 网关 :8318 → CLIProxyAPI :8317 → 住宅代理（VPS 侧） |
| 公网调用 · $GATEWAY_PUBLIC_HOST（默认 api.example.com） | DNS → Caddy :443（证书剩余天数）→ VPS 网关 :8318 → CLIProxyAPI :8317 → 住宅代理（VPS 侧） |
| Antigravity | Antigravity Tools :8045 → 住宅代理（本机直连过去） |
| AdsPower | 每个环境自己的代理（未读取，需要 AdsPower API key） |
| 普通程序（Claude、Chrome、ChatGPT） | 系统代理（Misty）→ VPN（QuickFox） |

网关和 VPS 的细节见 `../api/README.md`。

## 数据从哪来（全部只读）

| 内容 | 来源 | 频率 |
|---|---|---|
| 系统代理 | `scutil --proxy` | 10 秒 |
| QuickFox / Tailscale | `scutil --nc status` | 10 秒 |
| Misty、隧道、Antigravity 是否在跑 | `lsof` 监听端口（1084/1089、18318、8045） | 10 秒 |
| 程序是否在跑、启动时间 | `ps` | 10 秒 |
| 网关和 VPS 侧代理 | `http://127.0.0.1:18318/__stats` | 10 秒 |
| Antigravity 的代理地址 | `~/.antigravity_tools/gui_config.json` | 10 秒 |
| 各出口 IP、国家、运营商 | `curl` 经对应代理请求 `ip-api.com` | 60 秒；系统代理一变就立刻重测 |
| 域名 DNS、证书、入口状态 | 解析 `$GATEWAY_PUBLIC_HOST（默认 api.example.com）`，TLS 握手读证书到期时间，不带 key 请求 `/v1/models`（返回 401 说明整条链路通） | 60 秒 |

## 文件

| 文件 | 说明 |
|---|---|
| `server.py` | 后台：检测和接口，只用 Python 标准库，端口 18320 |
| `index.html` | 页面 |
| `open.command` | 启动器 |
| `~/.pi/agent/extensions/netmap.ts` | pi 的 `/net` 命令 |
