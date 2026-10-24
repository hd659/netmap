import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import server  # noqa: E402


def test_parse_curl_metrics_converts_seconds_to_ms():
    m = server.parse_curl_metrics("204 0.012 0.050 0.120 0.345 142.250.1.1")
    assert m == {"code": 204, "dns_ms": 12.0, "connect_ms": 50.0, "tls_ms": 120.0,
                 "ttfb_ms": 345.0, "remote_ip": "142.250.1.1"}


def test_parse_curl_metrics_failure_cases():
    assert server.parse_curl_metrics("") is None
    assert server.parse_curl_metrics("000 0 0 0 0") is None
    assert server.parse_curl_metrics("abc x y z w") is None


def test_grade_thresholds():
    assert server.grade(None) == "bad"
    assert server.grade(100) == "ok"
    assert server.grade(server.TTFB_OK_MS) == "warn"
    assert server.grade(server.TTFB_WARN_MS) == "bad"


def test_curl_argv_direct_vs_proxy():
    d = server.curl_argv("https://x", None)
    assert "--noproxy" in d and "-x" not in d and d[-1] == "https://x"
    p = server.curl_argv("https://x", "http://127.0.0.1:1089")
    assert p[p.index("-x") + 1] == "http://127.0.0.1:1089" and "--noproxy" not in p


def test_resolve_system_proxy_modes():
    assert server.resolve_system_proxy({"mode": "http", "addr": "127.0.0.1:1089"}, {}) == "http://127.0.0.1:1089"
    assert server.resolve_system_proxy({"mode": "socks", "addr": "127.0.0.1:1084"}, {}) == "socks5h://127.0.0.1:1084"
    assert server.resolve_system_proxy({"mode": "pac", "addr": "u"}, {1089: "Misty"}) == "http://127.0.0.1:1089"
    assert server.resolve_system_proxy({"mode": "pac", "addr": "u"}, {}) is None
    assert server.resolve_system_proxy({"mode": "off", "addr": ""}, {}) is None


def test_probe_paths_cover_direct_system_tunnel():
    jobs = server.probe_paths("http://127.0.0.1:1089", True)
    paths = {j[0] for j in jobs}
    assert paths == {"direct", "system", "tunnel"}
    assert sum(1 for j in jobs if j[0] == "direct") == len(server.PROBE_TARGETS)
    assert all(j[3] is None for j in jobs if j[0] != "system")
    assert {j[0] for j in server.probe_paths(None, False)} == {"direct"}


def test_probe_matrix_detects_proxy_hijack_and_isolates_errors():
    # 模拟回国节点：经系统代理访问海外目标超时，国内目标正常
    def fake_run(argv, timeout):
        url, proxied = argv[-1], "-x" in argv
        if "baidu" in url and proxied:
            raise RuntimeError("boom")
        if proxied and "baidu" not in url:
            return "000 0 0 0 0"
        return "200 0.01 0.02 0.05 0.150 1.2.3.4"

    r = server.probe_matrix("http://127.0.0.1:1089", True, run=fake_run)
    assert all(v["status"] == "ok" for v in r["direct"].values())
    assert r["system"]["youtube"]["status"] == "bad" and r["system"]["youtube"]["ttfb_ms"] is None
    assert r["system"]["baidu"]["status"] == "bad" and "boom" in r["system"]["baidu"]["error"]
    assert r["tunnel"]["gateway"]["ttfb_ms"] == 150.0


def test_probe_matrix_runs_concurrently():
    lock, live, peak = threading.Lock(), [0], [0]

    def slow_run(argv, timeout):
        with lock:
            live[0] += 1
            peak[0] = max(peak[0], live[0])
        time.sleep(0.1)
        with lock:
            live[0] -= 1
        return "200 0 0 0 0.1"

    t0 = time.time()
    r = server.probe_matrix("http://p:1", True, run=slow_run)
    n = sum(len(v) for v in r.values())
    assert n == 2 * len(server.PROBE_TARGETS) + 1
    assert peak[0] > 1 and time.time() - t0 < 0.1 * n / 2


def test_no_private_endpoints_hardcoded():
    src = open(server.__file__, encoding="utf-8").read()
    assert "831800" not in src and "149.28." not in src
    assert server.DOMAIN == os.environ.get("GATEWAY_PUBLIC_HOST", "api.example.com")


def _m(status, ms):
    return {"status": status, "ttfb_ms": ms}


def test_diagnose_flags_split_hijack_via_cn_exit():
    probes = {
        "direct": {"youtube": _m("ok", 120), "claude": _m("ok", 200), "baidu": _m("ok", 300)},
        "system": {"youtube": _m("bad", None), "claude": _m("ok", 700), "baidu": _m("ok", 40)},
    }
    a = server.diagnose(probes, "CN")
    assert a[0]["code"] == "split_hijack" and a[0]["level"] == "bad"
    assert set(a[0]["targets"]) == {"youtube", "claude"} and "CN" in a[0]["detail"]
    assert not any(x["code"] == "cn_detour" for x in a)


def test_diagnose_ignores_when_direct_also_broken_and_flags_congestion():
    probes = {
        "direct": {"youtube": _m("bad", None), "claude": _m("warn", 1200), "baidu": _m("ok", 30)},
        "system": {"youtube": _m("bad", None), "claude": _m("warn", 1500), "baidu": _m("ok", 35)},
    }
    codes = [x["code"] for x in server.diagnose(probes, "JP")]
    assert codes == ["congestion"]


def test_diagnose_cn_detour_cn_exit_and_tunnel():
    probes = {
        "direct": {"youtube": _m("ok", 100), "baidu": _m("ok", 30)},
        "system": {"youtube": _m("ok", 150), "baidu": _m("ok", 400)},
        "tunnel": {"gateway": _m("bad", None)},
    }
    a = server.diagnose(probes, "CN")
    codes = [x["code"] for x in a]
    assert codes[0] == "tunnel_down" and set(codes) == {"tunnel_down", "cn_exit", "cn_detour"}
    assert server.diagnose({"direct": {"youtube": _m("ok", 100)}}, "") == []
