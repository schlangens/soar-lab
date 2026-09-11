#!/usr/bin/env python3
"""SOC lab 12-hour report (Wazuh + pfSense + SOAR + DFIR-IRIS).

Replaces /var/ossec/bin/ssh_block_report.sh (2026-09-11). Fixes:
  - Firewall blocks are counted from active-responses.log and rules 100503/100504/100530,
    not from rule 100501 (level 2, never written to alerts.json, so the old count was always 0).
  - SOAR section: verdict counts and detail from rules 100530/100531/100532, IRIS alert/case counts.
  - Status reflects blocks and escalations, not only SSH.
  - pfSense is queried with the AR key (/var/ossec/.ssh/pfsense_ar), no password in the script.
  - Every timestamp shown as UTC and Eastern (America/Indiana/Indianapolis).
  - Sent through Resend (alerts.example.com) with fallback to the mx relay.
Secrets: /var/ossec/etc/soc_report.env (mode 600): RESEND_KEY, IRIS_API_KEY, IRIS_URL, REPORT_TO.
"""
import json, re, os, sys, subprocess, smtplib, datetime, collections, html, ssl, urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from zoneinfo import ZoneInfo

HOURS = int(os.environ.get("REPORT_HOURS", "12"))
ALERTS = "/var/ossec/logs/alerts/alerts.json"
ARLOG = "/var/ossec/logs/active-responses.log"
ENV = "/var/ossec/etc/soc_report.env"
UTC, EST = ZoneInfo("UTC"), ZoneInfo("America/Indiana/Indianapolis")
now = datetime.datetime.now(UTC); cutoff = now - datetime.timedelta(hours=HOURS)

def both(dt):
    return "%s UTC / %s ET" % (dt.astimezone(UTC).strftime("%b %d %H:%M"), dt.astimezone(EST).strftime("%b %d %I:%M %p"))

env = {}
if os.path.exists(ENV):
    for line in open(ENV):
        if "=" in line and not line.startswith("#"):
            k, v = line.strip().split("=", 1); env[k] = v.strip().strip('"')
TO = [x.strip() for x in env.get("REPORT_TO", "analyst@example.com,analyst-2@example.com").split(",")]

# ---------------------------------------------------------------- alerts.json in window
alerts = []
with open(ALERTS, errors="ignore") as f:
    for line in f:
        try: d = json.loads(line)
        except Exception: continue
        ts = d.get("timestamp", "")
        try: t = datetime.datetime.fromisoformat(re.sub(r"([+-]\d\d)(\d\d)$", r"\1:\2", ts.replace("Z", "+00:00")))
        except Exception: continue
        if t >= cutoff and isinstance(d.get("rule"), dict): alerts.append((t, d))
total = len(alerts)
rules = collections.Counter((d["rule"].get("id","?"), (d["rule"].get("description") or "")[:80]) for _, d in alerts)
ssh = [(t, d) for t, d in alerts if d["rule"]["id"] in ("5763", "5712", "99903", "99904")]
ssh_ips = collections.Counter(d.get("data", {}).get("srcip", "?") for _, d in ssh)
floods = [(t, d) for t, d in alerts if d["rule"]["id"] in ("100503", "100504")]
flood_ips = collections.Counter(d.get("data", {}).get("srcip", "?") for _, d in floods)
flood_ports = collections.Counter(d.get("data", {}).get("dstport", "?") for _, d in floods)
soar = [(t, d) for t, d in alerts if d["rule"]["id"] in ("100530", "100531", "100532")]
soar_counts = collections.Counter(d["rule"]["id"] for _, d in soar)
high = sum(1 for _, d in alerts if int(d["rule"].get("level", 0)) >= 10)

# ---------------------------------------------------------------- active-responses.log in window
blocked, unblocked, errors = [], 0, 0
for line in open(ARLOG, errors="ignore"):
    m = re.match(r"(\w{3} \w{3}\s+\d+ \d\d:\d\d:\d\d) UTC (\d{4}) pfsense-block\.sh (BLOCKED|UNBLOCKED|ERROR)\D*([\d.]+)?", line)
    if not m: continue
    t = datetime.datetime.strptime(m.group(1) + " " + m.group(2), "%a %b %d %H:%M:%S %Y").replace(tzinfo=UTC)
    if t < cutoff: continue
    if m.group(3) == "BLOCKED": blocked.append((t, m.group(4)))
    elif m.group(3) == "UNBLOCKED": unblocked += 1
    else: errors += 1
block_ips = collections.Counter(ip for _, ip in blocked)

# ---------------------------------------------------------------- pfSense (AR key) and RDAP org
def pf(cmd):
    try:
        return subprocess.run(["ssh", "-n", "-i", "/var/ossec/.ssh/pfsense_ar", "-o", "KexAlgorithms=ecdh-sha2-nistp256", "-o", "StrictHostKeyChecking=no",
                               "-o", "BatchMode=yes", "-o", "ConnectTimeout=6", "admin@10.0.0.1", cmd], capture_output=True, text=True, timeout=15).stdout.strip()
    except Exception: return ""
table_n = pf("pfctl -t Blocked_IPs -T show | wc -l").strip() or "?"
geo = {c: (pf("pfctl -t GeoBlock_%s -T show | wc -l" % c).strip() or "?") for c in ("CN", "RU", "KP", "IR", "SY")}
def org(ip):
    try:
        d = json.load(urllib.request.urlopen(urllib.request.Request("https://rdap.org/ip/" + ip, headers={"Accept": "application/rdap+json"}), timeout=6))
        names = []
        def walk(es):
            for e in es or []:
                v = e.get("vcardArray")
                if v and len(v) > 1:
                    for it in v[1]:
                        if it and it[0] == "fn" and it[3]: names.append(it[3])
                walk(e.get("entities"))
        walk(d.get("entities"))
        return (names[0] if names else d.get("name", "")) [:40]
    except Exception: return ""

# ---------------------------------------------------------------- IRIS
iris_alerts = iris_cases = None
if env.get("IRIS_API_KEY"):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    def iris(path):
        r = urllib.request.Request(env.get("IRIS_URL", "https://10.0.0.30") + path, headers={"Authorization": "Bearer " + env["IRIS_API_KEY"]})
        return json.load(urllib.request.urlopen(r, timeout=10, context=ctx))
    try:
        al = iris("/alerts/filter?per_page=200")["data"]["alerts"]
        iris_alerts = collections.Counter(a["status"]["status_name"] for a in al if a.get("alert_creation_time", "") >= cutoff.strftime("%Y-%m-%dT%H:%M:%S"))
        iris_cases = sum(1 for c in iris("/manage/cases/list")["data"] if not c.get("case_close_date"))
    except Exception as ex:
        iris_alerts = {"error": str(ex)[:60]}

# ---------------------------------------------------------------- status
esc = soar_counts.get("100532", 0); blk = soar_counts.get("100530", 0)
if len(blocked) > 10 or len(ssh) > 20 or any(d["rule"]["id"] == "100504" for _, d in floods):
    status, color, bg, emoji = "ELEVATED", "#e74c3c", "#fdf2f2", "&#128680;"
elif blocked or ssh or esc:
    status, color, bg, emoji = "ACTIVITY", "#f39c12", "#fef9e7", "&#9888;&#65039;"
else:
    status, color, bg, emoji = "ALL CLEAR", "#27ae60", "#eafaf1", "&#9989;"
subject = "[SOC LAB] %s: %d FW blocks, %d SOAR verdicts (%d esc), %d alerts (%dh)" % (status, len(blocked), len(soar), esc, total, HOURS)

# ---------------------------------------------------------------- HTML
def rows(items, empty, cols):
    if not items: return "<tr><td colspan='%d' style='padding:12px;text-align:center;color:#999'>%s</td></tr>" % (cols, empty)
    return "".join("<tr>" + "".join("<td style='padding:6px 10px;border-bottom:1px solid #eee;font-family:%s'>%s</td>" % ("monospace" if i == 0 else "inherit", html.escape(str(c))) for i, c in enumerate(r)) + "</tr>" for r in items)
def table(title, header, body):
    return "<h3 style='margin:18px 0 6px'>%s</h3><table style='border-collapse:collapse;width:100%%;font-size:13px'><tr>%s</tr>%s</table>" % (title, "".join("<th style='text-align:left;padding:6px 10px;border-bottom:2px solid #ddd'>%s</th>" % h for h in header), body)
soar_rows = []
for t, d in sorted(soar, key=lambda x: x[0], reverse=True)[:25]:
    x = d.get("data", {})
    soar_rows.append((both(t), {"100530": "BLOCK", "100531": "close", "100532": "ESCALATE"}[d["rule"]["id"]], x.get("srcip", ""), x.get("soar_score", ""), x.get("soar_rule", ""), (x.get("soar_reason") or "")[:90]))
block_rows = [(ip, n, org(ip)) for ip, n in block_ips.most_common(15)]
body = """<div style='font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;max-width:760px;margin:auto;color:#222'>
<div style='background:%s;border-left:6px solid %s;padding:14px 18px;border-radius:6px'>
<div style='font-size:22px;font-weight:700'>%s SOC Lab Report: %s</div>
<div style='color:#555;margin-top:4px'>Generated %s &middot; window %d h &middot; host %s</div>
<div style='margin-top:10px;font-size:15px'><b>%d</b> firewall blocks &middot; <b>%d</b> SOAR verdicts (%d block, %d close, %d escalate) &middot; <b>%d</b> SSH attack alerts &middot; <b>%d</b> total alerts &middot; <b>%d</b> level 10+</div>
</div>
%s %s %s %s %s
<h3 style='margin:18px 0 6px'>pfSense tables</h3><div style='font-size:13px'>Blocked_IPs currently holds <b>%s</b> entries (24 h expiry). GeoIP: CN %s, RU %s, KP %s, IR %s, SY %s. Plex port 32400 exempt.</div>
<h3 style='margin:18px 0 6px'>DFIR-IRIS</h3><div style='font-size:13px'>Alerts in window by status: %s &middot; open cases: %s &middot; <a href='https://iris.example.internal'>iris.example.internal</a></div>
<p style='color:#888;font-size:12px;margin-top:22px'>Wazuh manager wazuh-manager &middot; playbook: Shuffle "Wazuh Alert Triage" &middot; next report in %d h. Times shown as UTC / Eastern (Indianapolis).</p></div>""" % (
    bg, color, emoji, status, both(now), HOURS, os.uname().nodename, len(blocked), len(soar), blk, soar_counts.get("100531", 0), esc, len(ssh), total, high,
    table("Firewall blocks applied (active response, %d, %d unblocked, %d errors)" % (len(blocked), unblocked, errors), ["Source IP", "Blocks", "Organization (RDAP)"], rows(block_rows, "No blocks applied in this period", 3)),
    table("SOAR verdicts (newest first)", ["Time", "Verdict", "Source", "Score", "From rule", "Reason"], rows(soar_rows, "No SOAR verdicts in this period", 6)),
    table("Flood detections (100503 moderate, 100504 severe)", ["Source IP", "Alerts"], rows(flood_ips.most_common(10), "No flood detections", 2)) + table("Targeted ports", ["Port", "Hits"], rows(flood_ports.most_common(10), "n/a", 2)),
    table("SSH attack alerts", ["Source IP", "Alerts"], rows(ssh_ips.most_common(10), "No SSH brute force in this period", 2)),
    table("Top alert rules", ["Rule", "Description", "Count"], rows([(r, d, n) for (r, d), n in rules.most_common(12)], "none", 3)),
    table_n, geo["CN"], geo["RU"], geo["KP"], geo["IR"], geo["SY"],
    ", ".join("%s %s" % (k, v) for k, v in (iris_alerts or {}).items()) or "n/a", iris_cases if iris_cases is not None else "n/a", HOURS)

# ---------------------------------------------------------------- send
msg = MIMEMultipart("alternative"); msg["Subject"] = subject; msg["From"] = "SOC Lab Alerts <soc-alerts@alerts.example.com>"; msg["To"] = ", ".join(TO); msg["Reply-To"] = "analyst@example.com"
msg.attach(MIMEText(re.sub(r"<[^>]+>", " ", body), "plain")); msg.attach(MIMEText(body, "html"))
sent = ""
if env.get("RESEND_KEY"):
    try:
        with smtplib.SMTP("smtp.resend.com", 587, timeout=20) as s:
            s.starttls(); s.login("resend", env["RESEND_KEY"]); s.sendmail(msg["From"], TO, msg.as_string()); sent = "resend"
    except Exception as ex: sent = "resend-failed: " + str(ex)[:80]
if not sent.startswith("resend"):
    try:
        with smtplib.SMTP("10.0.0.99", 25, timeout=20) as s:
            s.sendmail("wazuh@example.com", TO, msg.as_string()); sent = (sent + " | " if sent else "") + "mx-relay"
    except Exception as ex: sent = (sent + " | " if sent else "") + "mx-failed: " + str(ex)[:80]
with open("/var/ossec/logs/report.log", "a") as f: f.write("%s %s | %s\n" % (now.isoformat(), sent, subject))
print(subject, "|", sent)
