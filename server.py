import json
import os
import re
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

PORT = 18320
HERE = os.path.dirname(os.path.abspath(__file__))
GATEWAY = "http://127.0.0.1:18318/__stats"
AG_CONFIG = os.path.expanduser("~/.antigravity_tools/gui_config.json")
DOMAIN = os.environ.get("GATEWAY_PUBLIC_HOST", "api.example.com")
VPS_IP = os.environ.get("GATEWAY_VPS_IP", "")
ADS_EXIT_IP = os.environ.get("ADSPOWER_EXIT_IP", "")
# 绕过系统代理，免得 Misty 开着时检测结果被它带偏
DIRECT = urllib.request.build_opener(urllib.request.ProxyHandler({}))
IDLE_EXIT = 600
TUNNEL_PORT = int(os.environ.get("NETMAP_TUNNEL_PORT", "18318"))

# 主动探测目标：海外 CDN / 海外 AI / 国内基准。回国节点劫持海外流量时，海外项 TTFB 会暴涨或失败而国内项正常
PROBE_TARGETS = {
    "youtube": "https://www.youtube.com/generate_204",
    "claude": "https://claude.ai/favicon.ico",
    "cloudflare": "https://www.cloudflare.com/cdn-cgi/trace",
    "baidu": "https://www.baidu.com/favicon.ico",
}
TTFB_OK_MS, TTFB_WARN_MS = 800, 2000
CN_TARGETS = {"baidu"}  # 其余目标都视为海外
SLOW_RATIO = 3.0  # 经代理 TTFB >= 直连 * SLOW_RATIO 判定为“被绕远”
CURL_FMT = "%{http_code} %{time_namelookup} %{time_connect} %{time_appconnect} %{time_starttransfer} %{remote_ip}"

state = {"checked": 0, "routes": [], "top": []}
last_seen = time.time()
proxy_changed_at = None
ips = {}
dom = {}


def sh(argv, timeout=8):
    try:
        env = dict(os.environ, LC_ALL="C")
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env).stdout.strip()
    except Exception:
        return ""


def geo(proxy=None, ip=""):
    # ip-api 一次返回 IP、国家、运营商；proxy 为空时 --noproxy 保证不走系统代理
    argv = ["curl", "-s", "-m", "10"] + (["-x", proxy] if proxy else ["--noproxy", "*"])
    out = sh(argv + [f"http://ip-api.com/json/{ip}?fields=query,countryCode,isp"], 14)
    try:
        d = json.loads(out)
        return {"ip": d["query"], "cc": d.get("countryCode", ""), "isp": d.get("isp", "")}
    except Exception:
        return None


def system_proxy():
    d = {}
    for ln in sh(["scutil", "--proxy"]).splitlines():
        if " : " in ln:
            k, v = ln.strip().split(" : ", 1)
            d[k] = v
    if d.get("ProxyAutoConfigEnable") == "1":
        return {"mode": "pac", "addr": d.get("ProxyAutoConfigURLString", "")}
    if d.get("HTTPSEnable") == "1" or d.get("HTTPEnable") == "1":
        p = "HTTPS" if d.get("HTTPSEnable") == "1" else "HTTP"
        return {"mode": "http", "addr": f"{d.get(p + 'Proxy')}:{d.get(p + 'Port')}"}
    if d.get("SOCKSEnable") == "1":
        return {"mode": "socks", "addr": f"{d.get('SOCKSProxy')}:{d.get('SOCKSPort')}"}
    return {"mode": "off", "addr": ""}


def listening():
    ports = {}
    for ln in sh(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"]).splitlines()[1:]:
        m = re.search(r":(\d+) \(LISTEN\)", ln)
        if m:
            ports[int(m.group(1))] = ln.split()[1]
    return ports


def processes():
    procs = {}
    for ln in sh(["ps", "-axo", "pid=,lstart=,comm="]).splitlines():
        parts = ln.split()
        if len(parts) < 7:
            continue
        try:
            start = time.mktime(time.strptime(" ".join(parts[1:6]), "%a %b %d %H:%M:%S %Y"))
        except ValueError:
            continue
        procs.setdefault(os.path.basename(" ".join(parts[6:])), start)
    return procs


def tunnel_remote(pid):
    out = sh(["lsof", "-nP", "-a", "-p", pid, "-iTCP", "-sTCP:ESTABLISHED"])
    m = re.search(r"->([\d.]+):22", out)
    if not m:
        return "未连上"
    return "加密 · 经 Tailscale " + m.group(1) if m.group(1).startswith("100.") else "加密 · 经公网 " + m.group(1)


def gateway_stats():
    try:
        with DIRECT.open(GATEWAY, timeout=6) as r:
            return json.loads(r.read())
    except Exception:
        return None


def domain_check():
    r = {"dns": None, "cert_days": None, "code": None}
    try:
        r["dns"] = socket.gethostbyname(DOMAIN)
        with socket.create_connection((DOMAIN, 443), timeout=6) as raw:
            with ssl.create_default_context().wrap_socket(raw, server_hostname=DOMAIN) as t:
                r["cert_days"] = int((ssl.cert_time_to_seconds(t.getpeercert()["notAfter"]) - time.time()) / 86400)
        DIRECT.open(f"https://{DOMAIN}/v1/models", timeout=8)
        r["code"] = 200
    except urllib.error.HTTPError as e:
        r["code"] = e.code
    except Exception:
        pass
    return r


def antigravity_proxy():
    try:
        up = json.load(open(AG_CONFIG))["proxy"]["upstream_proxy"]
    except Exception:
        return None
    u = urlsplit(up.get("url", ""))
    return {"enabled": up.get("enabled"), "url": up.get("url"), "addr": f"{u.hostname}:{u.port}"}


def parse_curl_metrics(out):
    """curl -w CURL_FMT 输出 -> 各阶段毫秒数；http_code 为 000 或格式坏视为失败。"""
    parts = (out or "").strip().split()
    if len(parts) < 5:
        return None
    try:
        code = int(parts[0])
        dns, conn, tls, ttfb = (round(float(x) * 1000, 1) for x in parts[1:5])
    except ValueError:
        return None
    if code == 0:
        return None
    return {"code": code, "dns_ms": dns, "connect_ms": conn, "tls_ms": tls, "ttfb_ms": ttfb,
            "remote_ip": parts[5] if len(parts) > 5 else ""}


def grade(ms):
    if ms is None:
        return "bad"
    return "ok" if ms < TTFB_OK_MS else "warn" if ms < TTFB_WARN_MS else "bad"


def curl_argv(url, proxy=None, timeout=8):
    # proxy=None 强制直连（--noproxy），避免环境变量里的代理污染"直连"基线
    argv = ["curl", "-s", "-o", "/dev/null", "-m", str(timeout), "-w", CURL_FMT]
    argv += ["-x", proxy] if proxy else ["--noproxy", "*"]
    return argv + [url]


def ttfb(url, proxy=None, timeout=8, run=None):
    run = run or sh
    m = parse_curl_metrics(run(curl_argv(url, proxy, timeout), timeout + 4))
    return {"url": url, "status": grade(m and m["ttfb_ms"]), **(m or {"code": None, "ttfb_ms": None})}


def resolve_system_proxy(sp, ports):
    if sp["mode"] == "http":
        return "http://" + sp["addr"]
    if sp["mode"] == "socks":
        return "socks5h://" + sp["addr"]
    if sp["mode"] == "pac" and 1089 in ports:
        return "http://127.0.0.1:1089"
    return None


def probe_paths(sys_proxy, tunnel_up):
    """返回 [(path, target, url, proxy)]。SSH 隧道只测本地端点到 VPS 网关的往返。"""
    jobs = [("direct", t, u, None) for t, u in PROBE_TARGETS.items()]
    if sys_proxy:
        jobs += [("system", t, u, sys_proxy) for t, u in PROBE_TARGETS.items()]
    if tunnel_up:
        jobs.append(("tunnel", "gateway", f"http://127.0.0.1:{TUNNEL_PORT}/__stats", None))
    return jobs


def probe_matrix(sys_proxy, tunnel_up, workers=12, run=None):
    """并发执行全部探测，结果 {path: {target: metrics}}；单项异常不拖垮整轮。"""
    jobs = probe_paths(sys_proxy, tunnel_up)
    out = {}
    with ThreadPoolExecutor(max(1, min(workers, len(jobs)))) as pool:
        futs = [(p, t, pool.submit(ttfb, u, x, run=run)) for p, t, u, x in jobs]
        for p, t, f in futs:
            try:
                out.setdefault(p, {})[t] = f.result()
            except Exception as e:
                out.setdefault(p, {})[t] = {"status": "bad", "ttfb_ms": None, "error": str(e)}
    return out


def _ms(m):
    return (m or {}).get("ttfb_ms")


def diagnose(probes, sys_exit_cc=""):
    """纯函数：探测矩阵 + 系统代理出口国家 -> 分流故障告警列表（按严重度排序）。

    规则（只用直连作对照组，排除本机网络整体坏掉的情况）：
      R1 split_hijack   海外目标经系统代理失败/超慢，而同目标直连正常 -> 海外流量被回国节点劫持
      R2 cn_exit        系统代理出口在 CN，但海外目标确实走了它 -> 分流规则缺失（与 R1 合并为证据）
      R3 cn_detour      国内目标经代理明显慢于直连 -> 国内流量被绕到海外
      R4 congestion     海外目标在直连与代理两条路径都慢（但不失败）-> 上游拥塞（晚高峰）
      R5 tunnel_down    SSH 隧道到 VPS 网关探测失败
    """
    alerts = []
    direct, system = probes.get("direct") or {}, probes.get("system") or {}
    overseas = [t for t in direct if t not in CN_TARGETS]

    def worse(t):
        d, s = direct.get(t), system.get(t)
        if not d or not s or d.get("status") == "bad":
            return False
        return _ms(s) is None or s["status"] == "bad" or _ms(s) >= _ms(d) * SLOW_RATIO

    hijacked = [t for t in overseas if worse(t)]
    if hijacked:
        cn = sys_exit_cc == "CN"
        alerts.append({
            "level": "bad", "code": "split_hijack", "targets": hijacked,
            "title": "海外流量被系统代理拖垮" + ("（出口在中国，疑似回国节点）" if cn else ""),
            "detail": f"{', '.join(hijacked)} 直连正常、经系统代理失败或慢 {SLOW_RATIO:g}x 以上；"
                      + ("Misty 当前节点出口在 CN，请把海外域名分流到直连/海外节点，或切换节点"
                         if cn else "检查代理分流规则是否把这些域名送进了错误的节点"),
        })
    elif sys_exit_cc == "CN" and system and any(t in system for t in overseas):
        alerts.append({
            "level": "warn", "code": "cn_exit", "targets": [],
            "title": "系统代理出口在中国",
            "detail": "海外目标暂时可达，但走的是回国节点，晚高峰极易拥塞，建议为海外域名单独分流",
        })

    cn_slow = [t for t in CN_TARGETS if worse(t)]
    if cn_slow:
        alerts.append({
            "level": "warn", "code": "cn_detour", "targets": cn_slow,
            "title": "国内流量被绕到代理",
            "detail": f"{', '.join(cn_slow)} 经代理明显慢于直连，分流规则可能没有把国内域名设为 DIRECT",
        })

    congested = [t for t in overseas if t not in hijacked and direct.get(t, {}).get("status") == "warn"
                 and system.get(t, {}).get("status", "warn") == "warn"]
    if congested:
        alerts.append({
            "level": "warn", "code": "congestion", "targets": congested,
            "title": "海外链路拥塞",
            "detail": f"{', '.join(congested)} 各路径 TTFB 都在 {TTFB_OK_MS}-{TTFB_WARN_MS}ms，属于上游拥塞（常见于晚高峰），非本机配置问题",
        })

    tun = (probes.get("tunnel") or {}).get("gateway")
    if tun and tun.get("status") == "bad":
        alerts.append({
            "level": "bad", "code": "tunnel_down", "targets": ["gateway"],
            "title": "SSH 隧道到 VPS 网关不通",
            "detail": f"本地 :{TUNNEL_PORT} 在监听但 /__stats 无响应，pi 的 GPT 模型会失败，重启隧道",
        })
    return sorted(alerts, key=lambda a: a["level"] != "bad")


def hop(label, sub, status):
    return {"label": label, "sub": sub, "status": status}


def exit_node(g, expect=""):
    if not g:
        return {"label": expect or "测不到", "sub": "", "status": "bad" if not expect else "off"}
    return {"label": g["ip"], "sub": f"{g['cc']} · {g['isp']}", "status": "ok"}


def collect(full):
    global proxy_changed_at
    sp = system_proxy()
    if state.get("sp") and state["sp"] != sp:
        proxy_changed_at = time.time()
        full = True
    ports = listening()
    procs = processes()
    quickfox = sh(["scutil", "--nc", "status", "QuickFox"]).split("\n")[0] or "未安装"
    tailscale = sh(["scutil", "--nc", "status", "Tailscale"]).split("\n")[0] or "未安装"
    ts_exit = '"ExitNodeStatus"' in sh(["tailscale", "status", "--json"])
    misty_on = 1089 in ports or 1084 in ports
    ag = antigravity_proxy()
    stats = gateway_stats()

    if full:
        sys_proxy = resolve_system_proxy(sp, ports)
        vps_ip = ((stats or {}).get("network", {}).get("vps", {}) or {}).get("proxy")
        jobs = {
            "direct": (None, ""),
            "system": (sys_proxy, "") if sys_proxy else None,
            "residential": (ag["url"], "") if ag and ag["enabled"] else None,
            "vps": (None, vps_ip) if vps_ip else None,
        }
        with ThreadPoolExecutor(6) as pool:
            futs = {k: pool.submit(geo, *v) for k, v in jobs.items() if v}
            dfut = pool.submit(domain_check)
            pfut = pool.submit(probe_matrix, sys_proxy, TUNNEL_PORT in ports)
            state["probes"] = pfut.result()
            for k in jobs:
                ips[k] = futs[k].result() if k in futs else None
            dom.update(dfut.result())

    qf_on = quickfox == "Connected"
    qf_warn = "QuickFox 已连接：到住宅代理这一段可能绕经 QuickFox，用这条线时建议断开" if qf_on else ""
    routes = []

    # 1. pi 的 GPT 模型：本地隧道 → VPS 网关 → CLIProxyAPI → 住宅代理
    tun_pid = ports.get(18318)
    vps = (stats or {}).get("network", {}).get("vps", {}) or {}
    routes.append({
        "name": "pi · GPT 模型",
        "note": "走你自己的网关，最后从 VPS 那边的住宅代理出去",
        "app": hop("pi", "运行中" if "pi" in procs else "未运行", "ok" if "pi" in procs else "off"),
        "hops": [
            hop("SSH 隧道 :18318", tunnel_remote(tun_pid) if tun_pid else "隧道没起来", "ok" if tun_pid else "bad"),
            hop("VPS 网关 :8318", "看板 / 记账", "ok" if stats else "bad"),
            hop("CLIProxyAPI :8317", "Codex Plus 账号", "ok" if stats and stats["gateway"]["online"] else "bad"),
            hop("住宅代理（VPS 侧）", "SOCKS5", "ok" if vps.get("proxy") else "bad"),
        ],
        "exit": exit_node(ips.get("vps")),
        "dest": "chatgpt.com",
        "warn": "" if vps.get("proxy") or not stats else "VPS 上代理不通，CLIProxyAPI 可能在用机房 IP 直连",
    })

    # 2. 公网域名：Caddy 443 → 网关 8318（只监听本机）→ CLIProxyAPI
    code, days = dom.get("code"), dom.get("cert_days")
    gw_ok = bool(stats)
    cp_ok = bool(stats and stats["gateway"]["online"])
    routes.append({
        "name": "公网调用 · " + DOMAIN,
        "note": "给其他设备和外部程序用：HTTPS 加密，公网只开放 /v1/*，看板路径一律 404",
        "app": hop("其他设备 / 外部程序", f"https://{DOMAIN}/v1", "off"),
        "hops": [
            hop("DNS 解析", dom.get("dns") or "解析失败", "ok" if dom.get("dns") and (not VPS_IP or dom["dns"] == VPS_IP) else "bad"),
            hop("Caddy :443", f"证书剩余 {days} 天" if days is not None else "连不上",
                "bad" if days is None or code is None else "warn" if days < 14 else "ok"),
            hop("VPS 网关 :8318", "只监听本机", "ok" if gw_ok else "bad"),
            hop("CLIProxyAPI :8317", "校验 API key", "ok" if cp_ok else "bad"),
            hop("住宅代理（VPS 侧）", "SOCKS5", "ok" if vps.get("proxy") else "bad"),
        ],
        "exit": exit_node(ips.get("vps")),
        "dest": "chatgpt.com",
        "warn": "" if not dom or code in (200, 401) else "域名入口连不上" if code is None
        else f"域名入口返回 {code}，没有走到 CLIProxyAPI 的鉴权",
    })

    # 3. Antigravity Tools：本机 8045 → 住宅代理
    ag_run = 8045 in ports
    ag_ok = ag and ag["enabled"] and ips.get("residential")
    routes.append({
        "name": "Antigravity（pi 的 antigravity 模型也走这里）",
        "note": "Antigravity Tools 自己配了住宅代理，不受系统代理影响",
        "app": hop("Antigravity Tools", ":8045 " + ("运行中" if ag_run else "未运行"), "ok" if ag_run else "off"),
        "hops": [
            hop("住宅代理（本机直连过去）", ag["addr"] if ag else "读不到配置",
                "ok" if ag_ok else "bad" if ag and ag["enabled"] else "warn"),
        ],
        "exit": exit_node(ips.get("residential")) if ag and ag["enabled"] else hop("本机网络", "没启用代理", "warn"),
        "dest": "Google",
        "warn": qf_warn if ag_run else "",
    })

    # 4. AdsPower：每个浏览器环境自己的代理，未读取
    ads_run = "AdsPower Global" in procs
    routes.append({
        "name": "AdsPower 浏览器环境",
        "note": "每个环境单独配代理，不受系统代理影响；需要 AdsPower API key 才能读出实际配置",
        "app": hop("AdsPower", "运行中" if ads_run else "未运行", "ok" if ads_run else "off"),
        "hops": [hop("环境自己的代理", "未读取", "off")],
        "exit": hop(f"应为 {ADS_EXIT_IP}" if ADS_EXIT_IP else "未配置 ADSPOWER_EXIT_IP", "按知识库记录，未实测", "off"),
        "dest": "网站",
        "warn": qf_warn if ads_run else "",
    })

    # 5. 普通程序：跟系统代理走，再经过 VPN 层
    apps = [n for n in ("Claude", "Google Chrome", "ChatGPT") if n in procs]
    if sp["mode"] == "off":
        sp_hop = hop("系统代理", "未开启，直连", "off")
    else:
        to_misty = "127.0.0.1:108" in sp["addr"] or (sp["mode"] == "pac" and misty_on)
        sp_hop = hop("系统代理 · " + {"http": "全局", "socks": "全局", "pac": "按规则分流"}[sp["mode"]],
                     ("→ Misty " if to_misty else "") + sp["addr"],
                     "ok" if ips.get("system") else "bad")
    vpn_sub = "已连接，按它的规则分流" if qf_on else "未连接"
    if ts_exit:
        vpn_sub += "；Tailscale 出口节点已开启"
    warn = ""
    claude_start = procs.get("Claude")
    if claude_start and proxy_changed_at and claude_start < proxy_changed_at:
        warn = "系统代理在 Claude 启动后改过，Claude 可能还在用旧代理，建议完整退出再打开"
    if sp["mode"] != "off" and not misty_on and "127.0.0.1" in sp["addr"]:
        warn = "系统代理指向本机端口，但 Misty 没在运行：跟系统代理走的程序会连不上"
    routes.append({
        "name": "普通程序",
        "note": "没有自己代理设置的程序都跟系统代理走",
        "app": hop(" / ".join(apps) or "无", "运行中" if apps else "", "ok" if apps else "off"),
        "hops": [sp_hop, hop("VPN · QuickFox", vpn_sub, "warn" if qf_on or ts_exit else "off")],
        "exit": exit_node(ips.get("system") if sp["mode"] != "off" else ips.get("direct")),
        "dest": "网站",
        "warn": warn,
    })

    direct = ips.get("direct")
    top = [
        hop("本机直连出口", f"{direct['ip']} · {direct['cc']}" if direct else "测不到", "ok" if direct else "bad"),
        hop("系统代理", {"off": "关", "http": "全局", "socks": "全局", "pac": "按规则分流"}[sp["mode"]],
            "warn" if sp["mode"] != "off" else "off"),
        hop("Misty", "运行中" if misty_on else "未运行", "warn" if misty_on else "off"),
        hop("QuickFox", "已连接" if qf_on else "未连接", "warn" if qf_on else "off"),
        hop("Tailscale", "已连接" if tailscale == "Connected" else tailscale, "ok" if tailscale == "Connected" else "off"),
        hop("SSH 隧道", "正常" if tun_pid else "断开", "ok" if tun_pid else "bad"),
    ]
    sys_g = ips.get("system") if sp["mode"] != "off" else None
    alerts = diagnose(state.get("probes") or {}, (sys_g or {}).get("cc", ""))
    state.update({"checked": time.time(), "routes": routes, "top": top, "sp": sp, "alerts": alerts})


def loop():
    n = 0
    while True:
        if time.time() - last_seen > IDLE_EXIT:
            os._exit(0)
        try:
            collect(full=n % 6 == 0)
        except Exception as e:
            print("collect failed:", e, flush=True)
        n += 1
        time.sleep(10)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        global last_seen
        if self.path == "/api/state":
            last_seen = time.time()
            body = json.dumps({k: v for k, v in state.items() if k != "sp"}).encode()
            ctype = "application/json"
        elif self.path == "/":
            body = open(os.path.join(HERE, "index.html"), "rb").read()
            ctype = "text/html; charset=utf-8"
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    threading.Thread(target=loop, daemon=True).start()
    print(f"netmap on http://127.0.0.1:{PORT}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
