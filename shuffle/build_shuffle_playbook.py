#!/usr/bin/env python3
"""Build the 'Wazuh Alert Triage' playbook in Shuffle via its REST API.

Graph:
  Webhook (Wazuh integratord, level>=10)
    -> parse_alert   (Shuffle Tools / execute_python)
    -> wazuh_auth    (http POST, raw token)
    -> enrich_ip     (execute_python: RDAP org, Tor exits, Spamhaus DROP, Wazuh CDB list, FireHOL level1,
                      abuse.ch SSLBL, Shodan InternetDB, OTX; AbuseIPDB + VirusTotal (+ GreyNoise) when keys are
                      set, behind a per-IP 24h cache, a cheap-gate, per-replica daily budgets, a VT per-minute
                      throttle and a 15 min cooldown after any 429)
    -> score_verdict (execute_python: allowlist, out-of-state check, scoring -> block/close/escalate)
    -> [verdict == block]    block_via_wazuh     (http POST /events -> rule 100530 -> pfsense-block AR)
    -> [verdict == close]    auto_close          (http POST /events -> rule 100531, audit only)
    -> [verdict == block]    -> iris_record_block  (IRIS /alerts/add, status Closed, severity High)
    -> [verdict == escalate] iris_open_alert     (IRIS /alerts/add, status New, severity Medium)
                             -> escalate_to_analyst (Telegram, with the IRIS alert link and the n8n approve link)
                             -> log_escalation   (http POST /events -> rule 100532)
"""
import json, uuid, sys, copy, http.cookiejar, urllib.request

BASE = "http://10.0.0.30:3001"
WF_ID = "<your-workflow-id>"
COOKIE_FILE = "/tmp/shf_cj.txt"

cj = http.cookiejar.MozillaCookieJar(COOKIE_FILE)
cj.load(ignore_discard=True, ignore_expires=True)
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

def api(method, path, body=None):
    req = urllib.request.Request(BASE + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
    with opener.open(req, timeout=60) as r:
        return json.loads(r.read().decode() or "{}")

wf = api("GET", f"/api/v1/workflows/{WF_ID}")
tmpl = wf["actions"][0]                       # existing Shuffle Tools echo node = template
env = tmpl.get("environment", "Shuffle")
tools_id, tools_ver = tmpl["app_id"], tmpl["app_version"]
HTTP_ID, HTTP_VER = "f6513e13-ea02-4017-80fc-538b98aa5efc", "1.4.0"
trigger_id = wf["triggers"][0]["id"]

def uid(): return str(uuid.uuid4())

def action(app, name, label, params, x, y):
    a = copy.deepcopy(tmpl)
    a["id"] = uid(); a["name"] = name; a["label"] = label
    a["position"] = {"x": x, "y": y}
    a["is_valid"] = True; a["isStartNode"] = False; a["environment"] = env
    if app == "http":
        a["app_name"] = "http"; a["app_id"] = HTTP_ID; a["app_version"] = HTTP_VER
        a["large_image"] = ""
    else:
        a["app_name"] = "Shuffle Tools"; a["app_id"] = tools_id; a["app_version"] = tools_ver
    a["parameters"] = [{"name": k, "value": v, "id": uid(), "variant": "STATIC_VALUE",
                        "required": k in ("code", "url", "call"), "multiline": k in ("code", "body", "headers"),
                        "description": "", "example": "", "schema": {"type": "string"}, "options": None,
                        "configuration": False, "tags": None} for k, v in params.items()]
    return a

def cond(source_val, dest_val):
    return [{"source": {"name": "source", "value": source_val, "variant": "STATIC_VALUE", "id": uid()},
             "condition": {"name": "condition", "value": "equals", "variant": "STATIC_VALUE", "id": uid()},
             "destination": {"name": "destination", "value": dest_val, "variant": "STATIC_VALUE", "id": uid()}}]

def branch(src, dst, conditions=None):
    return {"id": uid(), "source_id": src, "destination_id": dst, "label": "",
            "has_error": False, "conditions": conditions or [], "decorator": False}

# ---------------------------------------------------------------- python nodes
PARSE = r'''
import json, re
raw = r"""$exec"""
try:
    a = json.loads(raw)
except Exception:
    a = {"raw": raw}
af = a.get("all_fields") or {}
data = af.get("data") or {}
rule = af.get("rule") or {}
srcip = data.get("srcip") or data.get("src_ip") or ""
if not srcip:
    m = re.search(r"(\d{1,3}\.){3}\d{1,3}", a.get("title", "") or "")
    srcip = m.group(0) if m else ""
out = {
    "srcip": srcip,
    "srcport": str(data.get("srcport", "")),
    "dstip": data.get("dstip", ""),
    "dstport": str(data.get("dstport", "")),
    "direction": data.get("pf_direction", ""),
    "iface": data.get("pf_interface", ""),
    "rule_id": str(rule.get("id") or a.get("rule_id", "")),
    "rule_level": rule.get("level", 0),
    "rule_desc": rule.get("description") or a.get("title", ""),
    "agent": (af.get("agent") or {}).get("name", ""),
    "alert_id": af.get("id", ""),
    "timestamp": af.get("timestamp", ""),
    "has_ip": bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", srcip)),
}
print(json.dumps(out))
'''

LISTS = r'''
ALLOW_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
              "198.41.128.0/17", "172.64.0.0/13",          # Cloudflare
              "192.200.0.0/24", "199.165.136.0/24", "185.40.234.0/24", "199.38.182.118/32",  # Tailscale ctl/DERP
              "203.0.113.0/24",                            # Anthropic (Claude Code) per existing AR guard
              "198.51.100.10/32", "198.51.100.11/32", "100.64.0.7/32"]  # own Linodes, media-server tailnet
ALLOW_ORGS = ["google", "meta platforms", "facebook", "microsoft", "amazon", "fastly", "cloudflare", "akamai",
              "apple", "linode", "tailscale", "netflix", "edgecast", "level 3", "lumen", "at&t", "comcast"]
RESIDENTIAL_ORGS = ["charter", "spectrum", "spinco", "rrwe", "road runner", "comcast", "xfinity", "at&t", "sbcis", "sbc internet", "frontier",
                    "verizon", "cellco", "wirelessdatanetwork", "t-mobile", "tmobile", "metronet", "brightspeed", "cox comm", "windstream",
                    "centurylink", "mediacom", "altice", "optimum", "suddenlink", "wide open west", "cable one", "sparklight", "google fiber",
                    "starlink", "us cellular", "altafiber", "cincinnati bell", "tds telecom", "consolidated comm", "rise broadband", "viasat",
                    "hughes", "ziply", "astound", "wave broadband", "breezeline", "armstrong", "comporium"]
SCANNER_ORGS = ["censys", "shodan", "stretchoid", "internet measurement", "palo alto networks", "cortex xpanse",
                "shadowserver", "binaryedge", "onyphe", "leakix", "netsystems research", "alpha strike"]
'''

ENRICH_HEAD = r'''
import json, ipaddress, requests, os, time, hashlib
requests.packages.urllib3.disable_warnings()
p = json.loads(r"""$parse_alert.message""")
ip = p.get("srcip", "")
token = r"""$wazuh_auth.body""".strip().strip('"')
abuse_key = r"""$abuseipdb_key""".strip()
vt_key = r"""$virustotal_key""".strip()
gn_key = r"""$greynoise_key""".strip()
otx_key = r"""$otx_key""".strip()
def keyed(k): return bool(k) and not k.startswith("$")
e = {"ip": ip, "org": "", "rdap_name": "", "country": "", "tor_exit": False, "spamhaus_drop": False,
     "wazuh_cdb": False, "cdb_source": "", "abuseipdb_confidence": None, "abuseipdb_reports": None,
     "vt_malicious": None, "greynoise": None, "internetdb": None, "otx_pulses": None,
     "sources_checked": [], "skipped": [], "cached": [], "errors": []}
try:
    ipo = ipaddress.ip_address(ip)
    e["is_private"] = ipo.is_private or ipo.is_loopback or ipo.is_link_local or ipo.is_reserved
except Exception:
    e["is_private"] = True
    e["errors"].append("bad ip")
    print(json.dumps(e)); raise SystemExit
'''

ENRICH_BODY = r'''
# ---------------------------------------------------------------------------------------------
# Quota protection. /tmp persists per Shuffle Tools replica (three replicas run), so every budget
# below is PER REPLICA and set to roughly a third of the free tier with headroom.
#   AbuseIPDB free: 1,000 checks/day. VirusTotal public: 4 req/min, 500/day.
# Order of defence: per-IP result cache (24 h) -> cheap-gate (do not spend quota on traffic the
# scorer will close anyway) -> daily budget -> per-minute throttle (VT) -> 429 cooldown (15 min).
# Anything skipped is recorded in e["skipped"] so the verdict reason can say the run was degraded.
# ---------------------------------------------------------------------------------------------
BUDGET = {"abuseipdb": 250, "virustotal": 120, "greynoise": 15, "otx": 250, "internetdb": 300}
VT_PER_MIN = 3
COOLDOWN = 900
def _q(name): return "/tmp/q_" + name
def _read(path, default):
    try: return open(path).read()
    except Exception: return default
def budget_left(src):
    day = time.strftime("%Y%m%d", time.gmtime())
    try: n = int(_read(_q(src + "_" + day), "0") or 0)
    except Exception: n = 0
    return BUDGET.get(src, 0) - n
def budget_take(src):
    day = time.strftime("%Y%m%d", time.gmtime()); path = _q(src + "_" + day)
    try: n = int(_read(path, "0") or 0)
    except Exception: n = 0
    try: open(path, "w").write(str(n + 1))
    except Exception: pass
def cooling(src):
    path = _q(src + "_cooldown")
    return os.path.exists(path) and time.time() - os.path.getmtime(path) < COOLDOWN
def cool(src):
    try: open(_q(src + "_cooldown"), "w").write(str(time.time()))
    except Exception: pass
def minute_ok(src, limit):
    path = _q(src + "_minute"); now = time.time()
    try: stamps = [float(x) for x in _read(path, "").split() if x]
    except Exception: stamps = []
    stamps = [s for s in stamps if now - s < 60]
    if len(stamps) >= limit: return False
    stamps.append(now)
    try: open(path, "w").write(" ".join("%.0f" % s for s in stamps))
    except Exception: pass
    return True
def ip_cache_get(src, ttl=86400):
    path = _q(src + "_ip_" + hashlib.sha1(ip.encode()).hexdigest()[:16])
    try:
        if os.path.exists(path) and time.time() - os.path.getmtime(path) < ttl:
            return json.loads(open(path).read())
    except Exception: pass
    return None
def ip_cache_put(src, data):
    path = _q(src + "_ip_" + hashlib.sha1(ip.encode()).hexdigest()[:16])
    try: open(path, "w").write(json.dumps(data))
    except Exception: pass
def get(url, **kw):
    r = requests.get(url, timeout=12, **kw); r.raise_for_status(); return r
def keyed_get(src, url, **kw):
    """GET against a quota'd feed. A 429 (or 403 from AbuseIPDB, which it uses for exhausted quota)
    starts a cooldown so the next runs skip the feed instead of burning the timeout."""
    r = requests.get(url, timeout=12, **kw)
    if r.status_code == 429 or (src == "abuseipdb" and r.status_code == 403):
        cool(src); raise RuntimeError("HTTP %d, cooling %ds" % (r.status_code, COOLDOWN))
    r.raise_for_status(); return r
def cached_text(url, ttl=3600, **kw):
    """Fetch a feed at most once per ttl seconds; the Shuffle Tools container persists /tmp between runs."""
    path = "/tmp/feed_" + hashlib.sha1(url.encode()).hexdigest()[:12]
    try:
        if os.path.exists(path) and time.time() - os.path.getmtime(path) < ttl:
            return open(path, encoding="utf-8", errors="ignore").read()
    except Exception: pass
    r = requests.get(url, timeout=25, **kw); r.raise_for_status()
    try: open(path, "w", encoding="utf-8").write(r.text)
    except Exception: pass
    return r.text
def spend(src, fn, per_minute=None):
    """Run fn() against a quota'd feed only if the cache, budget, throttle and cooldown all allow it."""
    hit = ip_cache_get(src)
    if hit is not None:
        e["cached"].append(src); return hit
    if cooling(src):
        e["skipped"].append(src + ": cooling after rate limit"); return None
    if budget_left(src) <= 0:
        e["skipped"].append(src + ": daily budget spent"); return None
    if per_minute and not minute_ok(src, per_minute):
        e["skipped"].append(src + ": per-minute throttle"); return None
    budget_take(src)
    data = fn()
    ip_cache_put(src, data)
    return data
# RDAP: organisation and netname (free, no key, but cache per IP for a day so repeats cost nothing)
try:
    d = ip_cache_get("rdap")
    if d is None:
        d = get("https://rdap.org/ip/" + ip, headers={"Accept": "application/rdap+json"}).json()
        ip_cache_put("rdap", d)
    else:
        e["cached"].append("rdap")
    e["rdap_name"] = d.get("name", "")
    e["country"] = d.get("country", "")
    orgs = []
    def walk(ents):
        for en in ents or []:
            v = en.get("vcardArray")
            if v and len(v) > 1:
                for item in v[1]:
                    if item and item[0] == "fn" and item[3]:
                        orgs.append(item[3])
            walk(en.get("entities"))
    walk(d.get("entities"))
    e["org"] = " | ".join(dict.fromkeys(orgs))[:200]
    e["sources_checked"].append("rdap")
except Exception as ex:
    e["errors"].append("rdap: " + str(ex)[:80])
# Tor exit nodes
try:
    exits = set(cached_text("https://check.torproject.org/torbulkexitlist").split())
    e["tor_exit"] = ip in exits
    e["sources_checked"].append("tor")
except Exception as ex:
    e["errors"].append("tor: " + str(ex)[:80])
# Spamhaus DROP
try:
    nets = [l.split(";")[0].strip() for l in cached_text("https://www.spamhaus.org/drop/drop.txt", ttl=21600).splitlines() if l and not l.startswith(";")]
    e["spamhaus_drop"] = any(ipaddress.ip_address(ip) in ipaddress.ip_network(n, strict=False) for n in nets if n)
    e["sources_checked"].append("spamhaus_drop")
except Exception as ex:
    e["errors"].append("drop: " + str(ex)[:80])
# Wazuh malicious-ip CDB (blocklist.de, CINS Army, ...) via the manager API
try:
    cdb_text = cached_text("https://10.0.0.20:55000/lists/files/malicious-ip?raw=true", ttl=3600,
                           headers={"Authorization": "Bearer " + token}, verify=False)
    for line in cdb_text.splitlines():
        if line.startswith(ip + ":"):
            e["wazuh_cdb"] = True; e["cdb_source"] = line.split(":", 1)[1]; break
    e["sources_checked"].append("wazuh_cdb")
except Exception as ex:
    e["errors"].append("cdb: " + str(ex)[:80])
# ---------------------------------------------------------------------------------------------
# Cheap gate. The scorer closes allowlisted ranges and orgs no matter the score, and closes
# out-of-state return traffic unless a cheap signal already scored it. Neither outcome can change
# with a reputation lookup, so do not spend quota on them. Mirrors score_verdict exactly.
# ---------------------------------------------------------------------------------------------
cheap_close = e["is_private"]
try:
    for n in ALLOW_NETS:
        if ipo in ipaddress.ip_network(n, strict=False): cheap_close = True; break
except Exception:
    cheap_close = True
org_l = (e.get("org") or "").lower() + " " + (e.get("rdap_name") or "").lower()
if any(o in org_l for o in ALLOW_ORGS): cheap_close = True
try:
    sp, dp = int(p.get("srcport") or 0), int(p.get("dstport") or 0)
except Exception:
    sp, dp = 0, 0
cheap_signal = e["tor_exit"] or e["spamhaus_drop"] or e["wazuh_cdb"] or any(o in org_l for o in SCANNER_ORGS)
if sp in (80, 443, 8443) and dp >= 1024 and not cheap_signal: cheap_close = True
e["cheap_close"] = cheap_close
if cheap_close:
    e["skipped"].append("reputation lookups: not needed, cheap checks already close this")
else:
    # AbuseIPDB (keyed, budgeted)
    if keyed(abuse_key):
        try:
            d = spend("abuseipdb", lambda: keyed_get("abuseipdb", "https://api.abuseipdb.com/api/v2/check",
                      params={"ipAddress": ip, "maxAgeInDays": 90},
                      headers={"Key": abuse_key, "Accept": "application/json"}).json().get("data", {}))
            if d is not None:
                e["abuseipdb_confidence"] = d.get("abuseConfidenceScore"); e["abuseipdb_reports"] = d.get("totalReports")
                e["sources_checked"].append("abuseipdb")
        except Exception as ex:
            e["errors"].append("abuseipdb: " + str(ex)[:80])
    # VirusTotal (keyed, budgeted, throttled to VT_PER_MIN)
    if keyed(vt_key):
        try:
            d = spend("virustotal", lambda: keyed_get("virustotal", "https://www.virustotal.com/api/v3/ip_addresses/" + ip,
                      headers={"x-apikey": vt_key}).json(), per_minute=VT_PER_MIN)
            if d is not None:
                e["vt_malicious"] = d.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious")
                e["sources_checked"].append("virustotal")
        except Exception as ex:
            e["errors"].append("vt: " + str(ex)[:80])
    # ---- fallbacks: keyless or generous feeds so a rate-limited day still scores ----------------
    # Shodan InternetDB: keyless, ~600-request bursts before a 429, weekly data. Open ports, CVEs, tags.
    try:
        def _idb():
            r = requests.get("https://internetdb.shodan.io/" + ip, timeout=12)
            if r.status_code == 404: return {}
            if r.status_code == 429: cool("internetdb"); raise RuntimeError("HTTP 429, cooling %ds" % COOLDOWN)
            r.raise_for_status(); return r.json()
        d = spend("internetdb", _idb)
        if d is not None:
            e["internetdb"] = {"ports": len(d.get("ports") or []), "vulns": len(d.get("vulns") or []), "tags": d.get("tags") or []}
            e["sources_checked"].append("internetdb")
    except Exception as ex:
        e["errors"].append("internetdb: " + str(ex)[:80])
    # AlienVault OTX general endpoint: pulse count. Works without a key at a lower rate; a free key raises it.
    try:
        def _otx():
            h = {"X-OTX-API-KEY": otx_key} if keyed(otx_key) else {}
            r = requests.get("https://otx.alienvault.com/api/v1/indicators/IPv4/" + ip + "/general", headers=h, timeout=8)
            if r.status_code == 429: cool("otx"); raise RuntimeError("HTTP 429, cooling %ds" % COOLDOWN)
            r.raise_for_status(); return r.json()
        d = spend("otx", _otx)
        if d is not None:
            e["otx_pulses"] = (d.get("pulse_info") or {}).get("count")
            e["sources_checked"].append("otx")
    except Exception as ex:
        e["errors"].append("otx: " + str(ex)[:80])
    # GreyNoise Community: 50 lookups a week on the free key, so only when the two primary feeds both fell away.
    primary_missing = ("abuseipdb" not in e["sources_checked"] and "abuseipdb" not in e["cached"]) and ("virustotal" not in e["sources_checked"] and "virustotal" not in e["cached"])
    if keyed(gn_key) and primary_missing:
        try:
            def _gn():
                r = requests.get("https://api.greynoise.io/v3/community/" + ip, headers={"key": gn_key}, timeout=12)
                if r.status_code == 404: return {"classification": "unknown"}
                if r.status_code == 429: cool("greynoise"); raise RuntimeError("HTTP 429, cooling %ds" % COOLDOWN)
                r.raise_for_status(); return r.json()
            d = spend("greynoise", _gn)
            if d is not None:
                e["greynoise"] = {"classification": d.get("classification"), "noise": d.get("noise"), "riot": d.get("riot"), "name": d.get("name")}
                e["sources_checked"].append("greynoise")
        except Exception as ex:
            e["errors"].append("greynoise: " + str(ex)[:80])
# ---- bulk lists, always on, cached like Spamhaus DROP: FireHOL level1 and abuse.ch SSLBL C2 IPs -------------
e["firehol_level1"] = False; e["sslbl_c2"] = False
try:
    nets = [l.strip() for l in cached_text("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", ttl=3600).splitlines() if l and not l.startswith("#")]
    e["firehol_level1"] = any(ipo in ipaddress.ip_network(n, strict=False) for n in nets if n)
    e["sources_checked"].append("firehol_level1")
except Exception as ex:
    e["errors"].append("firehol: " + str(ex)[:80])
try:
    c2 = set(l.strip() for l in cached_text("https://sslbl.abuse.ch/blacklist/sslipblacklist.txt", ttl=3600).splitlines() if l and not l.startswith("#"))
    e["sslbl_c2"] = ip in c2
    e["sources_checked"].append("sslbl")
except Exception as ex:
    e["errors"].append("sslbl: " + str(ex)[:80])
print(json.dumps(e))
'''

ENRICH = ENRICH_HEAD + LISTS + ENRICH_BODY

SCORE_HEAD = r'''
import json, ipaddress
p = json.loads(r"""$parse_alert.message""")
e = json.loads(r"""$enrich_ip.message""")
ip = p.get("srcip", "")
approve_base = r"""$approve_url_base""".strip()
# --- allowlist: never act on these, whatever the score says -------------------------------
'''

SCORE_BODY = r'''
reasons, score = [], 0
allow = False
try:
    ipo = ipaddress.ip_address(ip)
    if ipo.is_unspecified or ipo.is_multicast or ipo.is_reserved:
        allow = True; reasons.append("unspecified/multicast/reserved source, not actionable")
    for n in ALLOW_NETS:
        if ipo in ipaddress.ip_network(n, strict=False):
            allow = True; reasons.append("allowlisted range " + n); break
except Exception:
    allow = True; reasons.append("unparseable source ip")
org = (e.get("org") or "").lower() + " " + (e.get("rdap_name") or "").lower()
if not allow and any(o in org for o in ALLOW_ORGS):
    allow = True; reasons.append("allowlisted org: " + (e.get("org") or e.get("rdap_name"))[:60])
# --- out-of-state return traffic: src 80/443 -> high dst port on the WAN address ---------
try:
    sp, dp = int(p.get("srcport") or 0), int(p.get("dstport") or 0)
except Exception:
    sp, dp = 0, 0
out_of_state = sp in (80, 443, 8443) and dp >= 1024
if out_of_state:
    reasons.append("out-of-state return traffic (src port %d -> dst port %d)" % (sp, dp))
# --- malicious signals ---------------------------------------------------------------------
if e.get("wazuh_cdb"):     score += 40; reasons.append("on Wazuh malicious-ip list (" + str(e.get("cdb_source")) + ")")
if e.get("tor_exit"):      score += 50; reasons.append("Tor exit node")
if e.get("spamhaus_drop"): score += 60; reasons.append("Spamhaus DROP")
if any(o in org for o in SCANNER_ORGS): score += 40; reasons.append("known internet scanner: " + (e.get("org") or "")[:40])
ac = e.get("abuseipdb_confidence")
if isinstance(ac, int):
    score += ac; reasons.append("AbuseIPDB confidence %d" % ac)
vt = e.get("vt_malicious")
if isinstance(vt, int) and vt > 0:
    score += min(vt * 20, 60); reasons.append("VirusTotal malicious votes %d" % vt)
# --- fallback signals (keyless feeds and bulk lists) -----------------------------------------
if e.get("firehol_level1"): score += 40; reasons.append("on FireHOL level1")
if e.get("sslbl_c2"):       score += 60; reasons.append("abuse.ch SSLBL C2 address")
idb = e.get("internetdb") or {}
if idb:
    risky = sorted(set(t.lower() for t in (idb.get("tags") or [])) & {"tor", "proxy", "vpn", "c2", "malware", "compromised", "honeypot"})
    if risky: score += 20; reasons.append("InternetDB tags: " + ",".join(risky))
    if (idb.get("vulns") or 0) >= 3: score += 15; reasons.append("InternetDB: %d known CVEs exposed" % idb["vulns"])
otx = e.get("otx_pulses")
if isinstance(otx, int) and otx >= 5: score += 30; reasons.append("OTX pulses %d" % otx)
elif isinstance(otx, int) and otx >= 1: score += 15; reasons.append("OTX pulses %d" % otx)
gn = e.get("greynoise") or {}
if gn.get("classification") == "malicious": score += 50; reasons.append("GreyNoise malicious")
elif gn.get("riot") or gn.get("classification") == "benign":
    score -= 40; reasons.append("GreyNoise benign/RIOT: " + str(gn.get("name") or "")[:30])
score = max(score, 0)
quota_skips = [x for x in e.get("skipped", []) if "budget" in x or "throttle" in x or "cooling" in x]
if quota_skips: reasons.append("degraded: " + "; ".join(quota_skips)[:90])
# --- verdict -------------------------------------------------------------------------------
if allow:
    verdict = "close"
elif out_of_state and score < 40:
    verdict = "close"
elif score >= 70:
    verdict = "block"
elif score >= 40:
    verdict = "escalate"
else:
    verdict = "escalate" if not e.get("sources_checked") else ("close" if p.get("rule_id") == "100503" and score == 0 and out_of_state else "escalate")
residential = any(o in org for o in RESIDENTIAL_ORGS)
if residential and verdict == "block":
    verdict = "escalate"; reasons.append("residential ISP space (Plex friends live here): never auto-blocked, analyst decides")
if not p.get("has_ip"):
    verdict = "escalate"; reasons.append("no source ip in alert")
reason = "; ".join(reasons)[:220].replace('"', "'")
event = 'soar_verdict: action=%s srcip=%s score=%d rule=%s reason="%s"' % (verdict, ip, min(score, 100), p.get("rule_id", "0"), reason)
approve = (approve_base + ("&" if "?" in approve_base else "?") + "ip=" + ip + "&rule=" + p.get("rule_id", "0")) if approve_base and not approve_base.startswith("$") else ""
import datetime
try:
    from zoneinfo import ZoneInfo
    _now = datetime.datetime.now(datetime.timezone.utc)
    when = "%s UTC / %s ET" % (_now.strftime("%b %d %H:%M"), _now.astimezone(ZoneInfo("America/Indiana/Indianapolis")).strftime("%b %d %I:%M %p"))
except Exception:
    when = datetime.datetime.utcnow().strftime("%b %d %H:%M UTC")
summary = ("SOAR %s: %s\n%s\nRule %s L%s on %s\n%s\nOrg: %s (%s)\nChecked: %s\nScore %d: %s" % (
    verdict.upper(), ip, when, p.get("rule_id"), p.get("rule_level"), p.get("agent"), p.get("rule_desc", "")[:80],
    (e.get("org") or "?")[:60], e.get("country") or "?", ",".join(e.get("sources_checked", [])), min(score, 100), reason))
if approve: summary += "\nApprove block: " + approve
sev = {"block": 5, "escalate": 1, "close": 3}[verdict]          # IRIS: 5 High, 1 Medium, 3 Informational
status = {"block": 6, "escalate": 2, "close": 6}[verdict]        # IRIS: 6 Closed, 2 New
desc = ("**SOAR verdict: %s** (score %d) at %s\n\n%s\n\nSource: %s (%s, %s)\nRule %s level %s on agent %s\nTraffic: %s:%s -> %s:%s %s on %s\nChecked: %s\nEnrichment errors: %s\n" % (
    verdict.upper(), min(score, 100), when, reason or "no findings", ip, (e.get("org") or "unknown org")[:80], e.get("country") or "?",
    p.get("rule_id"), p.get("rule_level"), p.get("agent"), ip, p.get("srcport"), p.get("dstip"), p.get("dstport"), p.get("direction"), p.get("iface"),
    ", ".join(e.get("sources_checked", [])) or "none", "; ".join(e.get("errors", [])) or "none"))
if verdict == "block": desc += "\nAction taken: Wazuh rule 100530 -> pfsense-block (24h, auto-expires).\n"
if approve: desc += "\nApprove block (analyst): " + approve + "\n"
iris_body = {"alert_title": "SOAR %s: %s (%s)" % (verdict.upper(), ip, (e.get("rdap_name") or e.get("org") or "unknown")[:40]),
             "alert_description": desc, "alert_source": "Shuffle / Wazuh", "alert_source_ref": str(p.get("alert_id") or ""),
             "alert_source_link": "http://10.0.0.30:3001/workflows/<your-workflow-id>",
             "alert_severity_id": sev, "alert_status_id": status, "alert_customer_id": 1,
             "alert_tags": "soar,%s,rule-%s" % (verdict, p.get("rule_id")),
             "alert_context": {"srcip": ip, "score": min(score, 100), "verdict": verdict, "wazuh_rule": p.get("rule_id"), "org": e.get("org"),
                               "tor_exit": e.get("tor_exit"), "spamhaus_drop": e.get("spamhaus_drop"), "wazuh_cdb": e.get("wazuh_cdb"),
                               "abuseipdb_confidence": e.get("abuseipdb_confidence"), "vt_malicious": e.get("vt_malicious"),
                               "firehol_level1": e.get("firehol_level1"), "sslbl_c2": e.get("sslbl_c2"), "internetdb": e.get("internetdb"),
                               "otx_pulses": e.get("otx_pulses"), "greynoise": e.get("greynoise"), "skipped": e.get("skipped"), "cached": e.get("cached")},
             "alert_source_content": {"wazuh_alert_id": p.get("alert_id"), "timestamp": p.get("timestamp"), "description": p.get("rule_desc")},
             "alert_iocs": [{"ioc_value": ip, "ioc_type_id": 79, "ioc_description": "flood source (" + verdict + ")", "ioc_tlp_id": 2, "ioc_tags": "soar"}] if p.get("has_ip") else []}
import re as _re
octets = ip.split(".") if p.get("has_ip") else []
ip_slow = '<break time="300ms"/>'.join('<say-as interpret-as="digits">%s</say-as>' % o for o in octets) or "unknown"
orgname = _re.sub(r"[^A-Za-z0-9 ,.-]", " ", (e.get("rdap_name") or (e.get("org") or "unknown").split("|")[0]))[:40].strip() or "unknown"
first_reason = _re.sub(r"[^A-Za-z0-9 ,.()-]", " ", (reason.split(";")[0] if reason else "no findings"))[:80]
what = "A block was applied automatically" if verdict == "block" else "An escalation needs your review"
spoken = "SOC lab alert. %s. Source address %s. Organization %s. Score %d. Reason: %s. Wazuh rule %s on %s." % (
    what, ".".join(octets) if octets else "unknown", orgname, min(score, 100), first_reason, p.get("rule_id"), p.get("agent"))
twiml = ('<Response><Say voice="Polly.Matthew"><prosody rate="slow">'
         'SOC lab alert. <break time="500ms"/>%s. <break time="500ms"/>Source address: %s. <break time="600ms"/>'
         'Organization: %s. <break time="400ms"/>Score %d. <break time="400ms"/>Reason: %s. <break time="600ms"/>'
         'Again, the source address is %s. <break time="400ms"/>Details are in IRIS.'
         '</prosody></Say></Response>') % (what, ip_slow, orgname, min(score, 100), first_reason, ip_slow)
import urllib.parse as _up
msg_text = summary[:1500]
twilio_msg_form = _up.urlencode({"To": r"""$twilio_msg_to""".strip(), "From": r"""$twilio_msg_from""".strip(), "Body": msg_text})
twilio_call_form = _up.urlencode({"To": r"""$twilio_to""".strip(), "From": r"""$twilio_from_voice""".strip(), "Twiml": twiml})
print(json.dumps({"verdict": verdict, "score": min(score, 100), "reason": reason, "event": event,
                  "summary": summary, "srcip": ip, "approve_url": approve, "iris_body": iris_body, "spoken": spoken, "twiml": twiml,
                  "twilio_msg_form": twilio_msg_form, "twilio_call_form": twilio_call_form}))
'''

SCORE = SCORE_HEAD + LISTS + SCORE_BODY

WAZUH = "https://10.0.0.20:55000"
n_parse  = action("tools", "execute_python", "parse_alert", {"code": PARSE.strip()}, 420, 200)
n_auth   = action("http", "POST", "wazuh_auth", {"url": WAZUH + "/security/user/authenticate?raw=true",
                  "username": "$wazuh_api_user", "password": "$wazuh_api_pass", "verify": "false", "timeout": "15"}, 420, 360)
n_enrich = action("tools", "execute_python", "enrich_ip", {"code": ENRICH.strip()}, 420, 520)
n_score  = action("tools", "execute_python", "score_verdict", {"code": SCORE.strip()}, 420, 680)
hdr = "Authorization: Bearer $wazuh_auth.body\nContent-Type: application/json"
n_block  = action("http", "POST", "block_via_wazuh", {"url": WAZUH + "/events", "headers": hdr, "verify": "false",
                  "body": '{"events": ["$score_verdict.message.event"]}', "timeout": "15"}, 120, 880)
n_close  = action("http", "POST", "auto_close", {"url": WAZUH + "/events", "headers": hdr, "verify": "false",
                  "body": '{"events": ["$score_verdict.message.event"]}', "timeout": "15"}, 420, 880)
n_tg     = action("http", "POST", "escalate_to_analyst", {"url": "https://api.telegram.org/bot$telegram_bot_token/sendMessage",
                  "headers": "Content-Type: application/json", "verify": "true",
                  "body": '{"chat_id": "$telegram_chat_id", "text": "$score_verdict.message.summary\\nIRIS alert #$iris_open_alert.body.data.alert_id: $iris_url/alerts?alert_ids=$iris_open_alert.body.data.alert_id", "disable_web_page_preview": true}',
                  "timeout": "15"}, 720, 1040)
n_log    = action("http", "POST", "log_escalation", {"url": WAZUH + "/events", "headers": hdr, "verify": "false",
                  "body": '{"events": ["$score_verdict.message.event"]}', "timeout": "15"}, 720, 1200)
IRIS = "$iris_url"
ihdr = "Authorization: Bearer $iris_api_key\nContent-Type: application/json"
n_iris_esc = action("http", "POST", "iris_open_alert", {"url": IRIS + "/alerts/add", "headers": ihdr, "verify": "false",
                  "body": "$score_verdict.message.iris_body", "timeout": "20"}, 720, 880)
n_iris_blk = action("http", "POST", "iris_record_block", {"url": IRIS + "/alerts/add", "headers": ihdr, "verify": "false",
                  "body": "$score_verdict.message.iris_body", "timeout": "20"}, 120, 1040)
TW = "https://api.twilio.com/2010-04-01/Accounts/$twilio_sid"
n_call = action("http", "POST", "call_analyst", {"url": TW + "/Calls.json", "username": "$twilio_sid", "password": "$twilio_token",
                  "headers": "Content-Type: application/x-www-form-urlencoded",
                  "body": "$score_verdict.message.twilio_call_form", "timeout": "20"}, 120, 1200)
n_wa = action("http", "POST", "message_analyst", {"url": TW + "/Messages.json", "username": "$twilio_sid", "password": "$twilio_token",
                  "headers": "Content-Type: application/x-www-form-urlencoded",
                  "body": "$score_verdict.message.twilio_msg_form", "timeout": "20"}, 1020, 1040)

wf["actions"] = [n_parse, n_auth, n_enrich, n_score, n_block, n_close, n_tg, n_log, n_iris_esc, n_iris_blk, n_wa]  # call_analyst removed 2026-09-11 per Scott: text only
wf["start"] = n_parse["id"]
n_parse["isStartNode"] = True
V = "$score_verdict.message.verdict"
wf["branches"] = [
    branch(trigger_id, n_parse["id"]),
    branch(n_parse["id"], n_auth["id"]),
    branch(n_auth["id"], n_enrich["id"]),
    branch(n_enrich["id"], n_score["id"]),
    branch(n_score["id"], n_block["id"], cond(V, "block")),
    branch(n_score["id"], n_close["id"], cond(V, "close")),
    branch(n_score["id"], n_iris_esc["id"], cond(V, "escalate")),
    branch(n_iris_esc["id"], n_tg["id"]),
    branch(n_tg["id"], n_log["id"]),
    branch(n_block["id"], n_iris_blk["id"]),
    branch(n_iris_esc["id"], n_wa["id"]),
]
wf["visual_branches"] = []
wf["description"] = ("Wazuh level 10+ alert -> parse -> enrich (RDAP, Tor, Spamhaus DROP, Wazuh CDB, FireHOL L1, SSLBL, InternetDB, OTX; AbuseIPDB/VT/GreyNoise keyed and quota-protected) "
                     "-> allowlist + score -> block (Wazuh rule 100530 -> pfsense-block AR, 24h), close (100531 audit) "
                     "or escalate (Telegram + 100532). Built 2026-09-11.")
existing = {v["name"]: v for v in (wf.get("workflow_variables") or [])}
def var(name, value, desc):
    v = existing.get(name) or {"id": uid(), "name": name}
    v["value"] = value if name not in existing else existing[name]["value"]; v["description"] = desc
    return v
wf["workflow_variables"] = [
    var("wazuh_api_user", "wazuh-wui", "Wazuh API user"),
    var("wazuh_api_pass", "", "Wazuh API password (pass wazuh_api_pass=... on the command line)"),
    var("abuseipdb_key", "", "AbuseIPDB API key (optional; blank = skipped)"),
    var("virustotal_key", "", "VirusTotal API key (optional; blank = skipped)"),
    var("greynoise_key", "", "GreyNoise Community API key (optional; only used when AbuseIPDB and VT both fell away)"),
    var("otx_key", "", "AlienVault OTX API key (optional; raises the OTX rate limit)"),
    var("telegram_bot_token", "", "Telegram bot token for analyst escalation"),
    var("telegram_chat_id", "", "Telegram chat id for analyst escalation"),
    var("approve_url_base", "", "n8n approval webhook base URL (optional)"),
    var("iris_url", "https://10.0.0.30", "DFIR-IRIS base URL"),
    var("iris_api_key", "", "DFIR-IRIS API key (administrator or a dedicated soar user)"),
    var("twilio_sid", "", "Twilio Account SID"),
    var("twilio_token", "", "Twilio Auth Token"),
    var("twilio_to", "+15555550100", "Analyst phone for voice calls (E.164)"),
    var("twilio_from_voice", "+15555550101", "Twilio number for outbound voice (local 463)"),
    var("twilio_msg_to", "whatsapp:+15555550100", "Analyst messaging address: whatsapp:+1... (sandbox) or +1... once SMS is verified"),
    var("twilio_msg_from", "whatsapp:+14155238886", "Twilio sender: WhatsApp sandbox now, +15555550102 after toll-free verification"),
]
# secrets passed on the command line so they never live in this file
for kv in sys.argv[1:]:
    k, _, v = kv.partition("=")
    for w in wf["workflow_variables"]:
        if w["name"] == k: w["value"] = v

res = api("PUT", f"/api/v1/workflows/{WF_ID}", wf)
print("PUT:", json.dumps(res)[:300])
chk = api("GET", f"/api/v1/workflows/{WF_ID}")
print("actions:", [a["label"] for a in chk["actions"]])
print("branches:", len(chk["branches"]), "start:", chk["start"] == n_parse["id"], "vars:", [v["name"] for v in chk["workflow_variables"]])
