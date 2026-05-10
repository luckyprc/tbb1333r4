#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Daily yoyapai converter:
1. Fetch today's (fallback to yesterday) yoyapai txt
2. Parse Trojan / Vmess / VLESS / SS
3. Force scv=true (tls.insecure + utls.chrome) for sing-box JSON
4. HTTP probe: TCP connect + HTTP status check (keep 200/204/301/302/400/404/101)
5. Output: nodes.txt (base64), raw.txt (plain URI), singbox.json
"""
import base64, json, urllib.parse, urllib.request, socket, ssl, os, sys
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

OUTPUT_DIR = "output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ==================== 解析函数 ====================

def parse_trojan(uri):
    p = urllib.parse.urlparse(uri)
    pw = urllib.parse.unquote(p.username or '')
    host = p.hostname
    port = p.port or 443
    name = urllib.parse.unquote(p.fragment) if p.fragment else f"Trojan-{host}"
    qs = urllib.parse.parse_qs(p.query)
    node = {
        "type": "trojan", "tag": name, "server": host,
        "server_port": port, "password": pw,
        "_uri": uri
    }
    net = qs.get('type', ['tcp'])[0]
    if net == 'ws':
        node["transport"] = {
            "type": "ws",
            "path": urllib.parse.unquote(qs.get('path', ['/'])[0]),
            "headers": {}
        }
        if 'host' in qs:
            node["transport"]["headers"]["Host"] = qs['host'][0]
    if qs.get('security', [''])[0] == 'tls':
        sni = qs.get('sni', [host])[0]
        node["tls"] = {
            "enabled": True, "server_name": sni,
            "insecure": True,
            "utls": {"enabled": True, "fingerprint": "chrome"}
        }
    return node

def parse_vless(uri):
    p = urllib.parse.urlparse(uri)
    uuid = p.username
    host = p.hostname
    port = p.port or 443
    name = urllib.parse.unquote(p.fragment) if p.fragment else f"VLESS-{host}"
    qs = urllib.parse.parse_qs(p.query)
    node = {
        "type": "vless", "tag": name, "server": host,
        "server_port": port, "uuid": uuid,
        "_uri": uri
    }
    net = qs.get('type', ['tcp'])[0]
    if net == 'ws':
        node["transport"] = {
            "type": "ws",
            "path": urllib.parse.unquote(qs.get('path', ['/'])[0]),
            "headers": {}
        }
        if 'host' in qs:
            node["transport"]["headers"]["Host"] = qs['host'][0]
    if qs.get('security', [''])[0] == 'tls':
        sni = qs.get('sni', [host])[0]
        fp = qs.get('fp', ['chrome'])[0]
        node["tls"] = {
            "enabled": True, "server_name": sni,
            "insecure": True,
            "utls": {"enabled": True, "fingerprint": fp}
        }
    return node

def parse_vmess(uri):
    b64 = uri.replace('vmess://', '').strip()
    b64 = b64.replace('-', '+').replace('_', '/')
    pad = 4 - len(b64) % 4
    if pad != 4:
        b64 += '=' * pad
    try:
        raw = base64.b64decode(b64).decode('utf-8', errors='ignore')
        obj = json.loads(raw)
    except Exception:
        return None
    host = obj.get('add', '')
    port = int(obj.get('port', 0))
    if not host or not port:
        return None
    name = obj.get('ps', f"Vmess-{host}").replace('\r', '').replace('\n', '').strip()
    node = {
        "type": "vmess", "tag": name, "server": host,
        "server_port": port, "uuid": obj.get('id', ''),
        "alter_id": int(obj.get('aid', 0)),
        "security": obj.get('scy', 'auto') or 'auto',
        "_uri": uri
    }
    net = obj.get('net', 'tcp')
    if net == 'ws':
        node["transport"] = {"type": "ws"}
        path = obj.get('path', '/')
        if path:
            node["transport"]["path"] = path
        if obj.get('host'):
            node["transport"]["headers"] = {"Host": obj['host']}
    if obj.get('tls') == 'tls':
        sni = obj.get('sni') or obj.get('host') or host
        node["tls"] = {
            "enabled": True, "server_name": sni,
            "insecure": True,
            "utls": {"enabled": True, "fingerprint": "chrome"}
        }
    return node

def parse_ss(uri):
    try:
        p = urllib.parse.urlparse(uri)
        name = urllib.parse.unquote(p.fragment) if p.fragment else f"SS-{p.hostname}"
        if p.username and p.password:
            method = urllib.parse.unquote(p.username)
            password = urllib.parse.unquote(p.password)
            host = p.hostname
            port = p.port
        else:
            b64 = p.path.replace('/', '')
            pad = 4 - len(b64) % 4
            if pad != 4:
                b64 += '=' * pad
            decoded = base64.b64decode(b64).decode('utf-8')
            if '@' in decoded:
                method_pw, server_port = decoded.rsplit('@', 1)
                method, password = method_pw.split(':', 1)
                host, port_str = server_port.rsplit(':', 1)
                port = int(port_str)
            else:
                return None
        return {
            "type": "shadowsocks", "tag": name, "server": host,
            "server_port": port, "method": method, "password": password,
            "_uri": uri
        }
    except Exception:
        return None

def parse_text(text):
    nodes = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        node = None
        if line.startswith('trojan://'):
            node = parse_trojan(line)
        elif line.startswith('vmess://'):
            node = parse_vmess(line)
        elif line.startswith('vless://'):
            node = parse_vless(line)
        elif line.startswith('ss://'):
            node = parse_ss(line)
        if node:
            nodes.append(node)
    return nodes

# ==================== 抓取（含回退） ====================

def fetch_yoyapai():
    for i in range(3):
        d = datetime.now() - timedelta(days=i)
        url = f"https://freenode.yoyapai.com/{d.strftime('%Y/%m/%d')}-yoyapai.com-ssr-v2rayvpn-mianfeijiedian.txt"
        print(f"[Fetch] Trying {url}")
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            with urllib.request.urlopen(req, timeout=60) as resp:
                text = resp.read().decode('utf-8', errors='ignore')
                if len(text) > 100 and ('trojan://' in text or 'vmess://' in text or 'vless://' in text or 'ss://' in text):
                    print(f"[Fetch] Success using {d.strftime('%Y/%m/%d')}")
                    return text, d.strftime('%Y%m%d')
        except Exception as e:
            print(f"[Fetch] Failed {url}: {e}")
            continue
    
    cache_raw = os.path.join(OUTPUT_DIR, "raw.txt")
    if os.path.exists(cache_raw):
        print("[Fetch] All remote failed, using cached raw.txt")
        with open(cache_raw, 'r', encoding='utf-8') as f:
            return f.read(), "cached"
    return "", "failed"

# ==================== 探活 ====================

def probe_tcp(host, port):
    try:
        socket.create_connection((host, port), timeout=5)
        return True
    except Exception:
        return False

def probe_http(node):
    transport = node.get('transport', {})
    if transport.get('type') != 'ws':
        return 200
    path = transport.get('path', '/')
    host = node['server']
    port = node['server_port']
    sni = node.get('tls', {}).get('server_name', host)
    try:
        if node.get('tls', {}).get('enabled'):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            url = f"https://{host}:{port}{path}"
            req = urllib.request.Request(url, headers={'Host': sni, 'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                return resp.status
        else:
            url = f"http://{host}:{port}{path}"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None

def probe_node(node):
    host = node['server']
    port = node['server_port']
    if not probe_tcp(host, port):
        return node, False, None
    status = probe_http(node)
    if status is None:
        return node, False, None
    if status in (200, 204, 301, 302, 400, 404, 101):
        return node, True, status
    return node, False, status

def filter_alive(nodes, max_workers=40):
    alive = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(probe_node, n): n for n in nodes}
        for future in as_completed(futures):
            node, is_alive, status = future.result()
            tag = node.get('tag', '')
            if is_alive:
                alive.append(node)
                print(f"  [Alive] {tag} (HTTP {status})")
            else:
                print(f"  [Dead]  {tag} (HTTP {status})")
    return alive

# ==================== 输出 ====================

def to_raw(nodes):
    lines = [n['_uri'] for n in nodes if '_uri' in n]
    return '\n'.join(lines)

def to_base64(nodes):
    raw = to_raw(nodes)
    if not raw:
        return ""
    return base64.b64encode(raw.encode('utf-8')).decode('utf-8')

def to_singbox(nodes):
    outbounds = [
        {"tag": "direct", "type": "direct"},
        {"tag": "block", "type": "block"},
        {"tag": "dns-out", "type": "dns"},
    ]
    for n in nodes:
        clean = {k: v for k, v in n.items() if not k.startswith('_')}
        outbounds.append(clean)
    
    node_tags = [n['tag'] for n in nodes]
    if node_tags:
        outbounds.append({
            "tag": "auto",
            "type": "urltest",
            "outbounds": node_tags,
            "url": "http://www.google.com/generate_204",
            "interval": "1m",
            "tolerance": 50
        })
    
    return {
        "log": {"level": "warn"},
        "dns": {
            "servers": [
                {"tag": "local", "address": "local"},
                {"tag": "google", "address": "https://dns.google/dns-query", "address_resolver": "local"}
            ]
        },
        "inbounds": [],
        "outbounds": outbounds,
        "route": {
            "auto_detect_interface": True,
            "final": "direct",
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"}
            ]
        }
    }

def main():
    print("=" * 50)
    print(f"Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)
    
    text, src_date = fetch_yoyapai()
    if not text:
        print("[Error] No data fetched and no cache available.")
        sys.exit(1)
    
    nodes = parse_text(text)
    print(f"[Parse] Total nodes: {len(nodes)}")
    
    print(f"[Probe] Testing {len(nodes)} nodes (TCP + HTTP)...")
    alive = filter_alive(nodes)
    print(f"[Probe] Alive: {len(alive)} / {len(nodes)}")
    
    if not alive:
        print("[Warning] All nodes dead. Keeping previous cache.")
        sys.exit(0)
    
    raw_content = to_raw(alive)
    b64_content = to_base64(alive)
    sb_config = to_singbox(alive)
    
    with open(os.path.join(OUTPUT_DIR, "raw.txt"), 'w', encoding='utf-8') as f:
        f.write(raw_content)
    
    with open(os.path.join(OUTPUT_DIR, "nodes.txt"), 'w', encoding='utf-8') as f:
        f.write(b64_content)
    
    with open(os.path.join(OUTPUT_DIR, "singbox.json"), 'w', encoding='utf-8') as f:
        json.dump(sb_config, f, ensure_ascii=False, indent=2)
    
    stats = {}
    for n in alive:
        t = n['type']
        stats[t] = stats.get(t, 0) + 1
    print(f"[Output] raw.txt / nodes.txt / singbox.json -> {OUTPUT_DIR}/")
    print(f"[Stats]  Source: {src_date}, Alive: {len(alive)}, Types: {stats}")
    print("Done.")

if __name__ == "__main__":
    main()
