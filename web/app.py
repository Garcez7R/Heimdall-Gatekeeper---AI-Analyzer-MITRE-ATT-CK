import argparse
import sys
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

sys.dont_write_bytecode = True

from core.analyzer import analyze_text, get_grouped_findings, get_analysis_history
from core.cache import cleanup_runtime_cache

DEFAULT_SAMPLE = """Jul 10 10:15:30 server sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2
Jul 10 10:15:31 server sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2
Jul 10 10:15:32 server sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2
Jul 10 10:15:33 server sshd[1234]: Accepted password for root from 203.0.113.5 port 22 ssh2
Jul 11 14:20:01 server sshd[9999]: Failed password for admin from 192.168.1.50 port 22 ssh2
Jul 11 14:20:05 server sshd[9999]: Failed password for admin from 192.168.1.50 port 22 ssh2"""


def render_page(log_text: str = DEFAULT_SAMPLE, grouped_findings: list[dict] | None = None) -> str:
    grouped_findings = grouped_findings or []
    history = get_analysis_history()
    
    # Widgets
    compromised_count = sum(1 for f in grouped_findings if f["classification"] == "comprometido")
    critical_count = sum(1 for f in grouped_findings if f["classification"] == "crítico")
    
    cards = "\n".join(render_finding_card(item) for item in grouped_findings)
    history_html = "\n".join(render_history_item(item) for item in history[:5])
    
    empty_state = "" if grouped_findings else "<p class='empty'>Insira logs para iniciar a auditoria.</p>"

    # Insight Banner
    insight_html = ""
    top_threat = grouped_findings[0] if grouped_findings else None
    if top_threat and top_threat["risk_score"] >= 70:
        is_comp = top_threat["classification"] == "comprometido"
        icon = "🚨" if is_comp else "🔥"
        title = "CRITICAL: Account Compromised" if is_comp else "HIGH RISK: Active Attack"
        insight_html = f"""
        <div class="insight-banner {"banner--compromised" if is_comp else ""}">
            <div class="insight-icon">{icon}</div>
            <div class="insight-content">
                <strong>{title}</strong>
                <p>IP {escape(top_threat["ip"])} ({top_threat["context"]["country"]}) - Risk Score {top_threat["risk_score"]}/100</p>
            </div>
        </div>
        """

    return f"""<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Heimdall Gatekeeper | Security Audit</title>
  <style>
    :root {{
      --bg: #0d1117;
      --panel: #161b22;
      --panel-dark: #010409;
      --border: #30363d;
      --text: #c9d1d9;
      --text-dim: #8b949e;
      --cyan: #58a6ff;
      --green: #3fb950;
      --amber: #d29922;
      --red: #f85149;
      --purple: #bc8cff;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0; background: var(--bg); color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
      font-size: 14px;
    }}
    main {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
    
    header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 1px solid var(--border); padding-bottom: 15px; }}
    .brand {{ font-size: 1.2rem; font-weight: bold; color: var(--green); }}
    .status-tag {{ font-size: 10px; background: var(--border); padding: 2px 8px; border-radius: 10px; color: var(--text-dim); }}

    .insight-banner {{
        background: rgba(248, 81, 73, 0.1); border: 1px solid var(--red); border-radius: 6px;
        padding: 12px 20px; margin-bottom: 20px; display: flex; align-items: center; gap: 15px;
        animation: pulse 2s infinite;
    }}
    .banner--compromised {{ background: rgba(188, 140, 255, 0.1); border-color: var(--purple); }}
    @keyframes pulse {{ 0% {{ opacity: 0.8; }} 50% {{ opacity: 1; }} 100% {{ opacity: 0.8; }} }}
    .insight-icon {{ font-size: 1.2rem; }}
    .insight-content strong {{ color: #fff; display: block; }}
    .insight-content p {{ color: var(--text-dim); font-size: 12px; margin: 0; }}

    .layout {{ display: grid; grid-template-columns: 300px 1fr 320px; gap: 20px; }}
    .col-title {{ font-size: 11px; color: var(--text-dim); text-transform: uppercase; margin-bottom: 10px; display: block; letter-spacing: 0.5px; }}
    
    .panel {{ background: var(--panel); border: 1px solid var(--border); border-radius: 6px; }}
    
    /* Editor */
    .editor-box {{ padding: 15px; }}
    textarea {{
      width: 100%; height: 500px; background: var(--panel-dark); color: #79c0ff;
      border: 1px solid var(--border); border-radius: 4px; padding: 10px;
      font-family: monospace; font-size: 12px; outline: none; resize: none;
    }}
    .btn-run {{
      margin-top: 10px; width: 100%; padding: 8px; background: #238636;
      color: #fff; border: 1px solid rgba(240,246,252,0.1); border-radius: 6px; font-weight: 600; cursor: pointer;
    }}

    /* Findings */
    .finding {{ margin-bottom: 15px; padding: 15px; border-top: 3px solid var(--border); }}
    .finding.comprometido {{ border-top-color: var(--purple); }}
    .finding.crítico {{ border-top-color: var(--red); }}
    
    .f-header {{ display: flex; justify-content: space-between; margin-bottom: 10px; }}
    .f-ip {{ font-weight: bold; color: #fff; }}
    .f-score {{ font-size: 10px; font-weight: 800; padding: 2px 6px; border-radius: 4px; }}
    .score--comprometido {{ background: var(--purple); color: #fff; }}
    .score--crítico {{ background: var(--red); color: #fff; }}
    .score--suspeito {{ background: var(--amber); color: #000; }}

    .f-context {{ font-size: 11px; color: var(--cyan); margin-bottom: 8px; }}
    .f-meta {{ display: grid; grid-template-columns: 1fr 1fr; gap: 5px; font-size: 11px; color: var(--text-dim); }}
    .f-meta b {{ color: var(--text); }}

    .timeline {{ margin-top: 12px; font-size: 10px; font-family: monospace; border-top: 1px solid var(--border); padding-top: 8px; }}
    .t-item {{ display: flex; gap: 8px; margin-bottom: 2px; }}
    .t-success {{ color: var(--green); }}
    .t-failed {{ color: var(--red); }}

    /* History */
    .history-item {{ padding: 10px; border-bottom: 1px solid var(--border); font-size: 12px; }}
    .history-item:last-child {{ border-bottom: none; }}
    .h-time {{ font-size: 10px; color: var(--text-dim); display: block; }}
    .h-summary {{ margin-top: 4px; display: flex; gap: 10px; font-size: 11px; }}
    .h-tag {{ color: var(--red); font-weight: bold; }}

    @media (max-width: 1100px) {{ .layout {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <main>
    <header>
      <div class="brand">HEIMDALL GATEKEEPER <span class="status-tag">v5.0 ENTERPRISE</span></div>
      <div class="stats">
        <span style="color:var(--purple)">Compromised: {compromised_count}</span> | 
        <span style="color:var(--red)">Critical: {critical_count}</span>
      </div>
    </header>

    {insight_html}

    <div class="layout">
      <section>
        <span class="col-title">Audit History</span>
        <div class="panel">
          {history_html or "<p style='padding:15px;color:var(--text-dim)'>Sem histórico.</p>"}
        </div>
      </section>

      <section>
        <span class="col-title">Log Input (SSH/Auth)</span>
        <div class="panel editor-box">
          <form method="post" action="/analyze">
            <textarea name="logs" spellcheck="false">{escape(log_text)}</textarea>
            <button type="submit" class="btn-run">EXECUTE SECURITY AUDIT</button>
          </form>
        </div>
      </section>

      <section>
        <span class="col-title">Live Threat Intel</span>
        <div class="results-list">
          {empty_state}
          {cards}
        </div>
      </section>
    </div>
  </main>
</body>
</html>"""


def render_finding_card(item: dict) -> str:
    classification = item["classification"]
    score = item["risk_score"]
    ctx = item["context"]
    
    timeline_html = "".join([
        f'<div class="t-item"><span style="color:var(--text-dim)">{e["time"]}</span> <span class="t-{e["status"]}">{e["status"].upper()}</span> {escape(e["user"])}</div>'
        for e in item["timeline"][-5:]
    ])

    return f"""
    <div class="panel finding {classification}">
        <div class="f-header">
            <span class="f-ip">{escape(item["ip"])}</span>
            <span class="f-score score--{classification}">{score}% RISK</span>
        </div>
        <div class="f-context">📍 {ctx["country"]}, {ctx["city"]} | 🏢 {ctx["asn"]}</div>
        <div class="f-meta">
            <span>Users: <b>{escape(item["user"])}</b></span>
            <span>Events: <b>{item["count"]}</b></span>
            <span>Duration: <b>{int(item["duration_seconds"])}s</b></span>
            <span>MITRE: <b>{", ".join(item["mitre_techniques"]) or "N/A"}</b></span>
        </div>
        <div class="timeline">
            {timeline_html}
        </div>
    </div>
    """

def render_history_item(item: dict) -> str:
    return f"""
    <div class="history-item">
        <span class="h-time">{item["timestamp"]}</span>
        <div class="h-summary">
            <span>IPs: {item["summary"]["total_ips"]}</span>
            <span class="h-tag">{item["summary"]["compromised"]} Comp.</span>
            <span class="h-tag">{item["summary"]["critical"]} Crit.</span>
        </div>
    </div>
    """

class HeimdallWebHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.respond_html(render_page())

    def do_POST(self) -> None:
        if self.path != "/analyze":
            self.send_error(404)
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        log_text = parse_qs(raw_body).get("logs", [""])[0]
        
        findings = analyze_text(log_text)
        grouped_findings = get_grouped_findings(findings)
        
        self.respond_html(render_page(log_text, grouped_findings))

    def respond_html(self, content: str) -> None:
        encoded = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    cleanup_runtime_cache(project_root)
    parser = argparse.ArgumentParser(description="Run the Heimdall AI local web interface.")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind. Defaults to 127.0.0.1.")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind. Defaults to 8080.")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), HeimdallWebHandler)
    print(f"Heimdall AI web running at http://{args.host}:{args.port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        cleanup_runtime_cache(project_root)


if __name__ == "__main__":
    main()
