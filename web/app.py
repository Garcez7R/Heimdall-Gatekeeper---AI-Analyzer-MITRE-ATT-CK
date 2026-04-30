import argparse
import sys
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

sys.dont_write_bytecode = True

from core.analyzer import analyze_text, get_grouped_findings
from core.cache import cleanup_runtime_cache

DEFAULT_SAMPLE = """Jul 10 10:15:30 server sshd[1234]: Failed password for invalid user admin from 192.168.1.10 port 22 ssh2
Jul 10 10:15:31 server sshd[1234]: Failed password for invalid user admin from 192.168.1.10 port 22 ssh2
Jul 10 10:15:32 server sshd[1234]: Failed password for invalid user admin from 192.168.1.10 port 22 ssh2
Jul 10 10:15:33 server sshd[1234]: Failed password for invalid user admin from 192.168.1.10 port 22 ssh2
Jul 10 10:15:34 server sshd[1234]: Failed password for invalid user admin from 192.168.1.10 port 22 ssh2
Jul 11 09:00:01 server sshd[5678]: Failed password for root from 203.0.113.5 port 22 ssh2
Jul 11 09:00:02 server sshd[5678]: Failed password for root from 203.0.113.5 port 22 ssh2
Jul 11 09:00:03 server sshd[5678]: Failed password for root from 203.0.113.5 port 22 ssh2
Jul 11 09:00:05 server sshd[5678]: Accepted password for root from 203.0.113.5 port 22 ssh2"""


def render_page(log_text: str = DEFAULT_SAMPLE, grouped_findings: list[dict] | None = None) -> str:
    grouped_findings = grouped_findings or []
    
    # Resumo para os widgets
    compromised_count = sum(1 for f in grouped_findings if f["classification"] == "comprometido")
    critical_count = sum(1 for f in grouped_findings if f["classification"] == "crítico")
    avg_risk = sum(f["risk_score"] for f in grouped_findings) / len(grouped_findings) if grouped_findings else 0
    
    cards = "\n".join(render_finding_card(item) for item in grouped_findings)
    empty_state = "" if grouped_findings else "<p class='empty'>Insira logs para iniciar o Threat Hunting.</p>"

    # Insight de topo
    insight_html = ""
    top_threat = grouped_findings[0] if grouped_findings else None
    if top_threat and top_threat["risk_score"] >= 70:
        is_comp = top_threat["classification"] == "comprometido"
        icon = "🚨" if is_comp else "🔥"
        title = "CRITICAL THREAT: Account Compromise" if is_comp else "HIGH RISK: Active Brute Force"
        
        insight_html = f"""
        <div class="insight-banner {"banner--compromised" if is_comp else ""}">
            <div class="insight-icon">{icon}</div>
            <div class="insight-content">
                <strong>{title}</strong>
                <p>IP {escape(top_threat["ip"])} apresenta padrão anômalo com Risk Score {top_threat["risk_score"]}/100.</p>
            </div>
        </div>
        """

    return f"""<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Heimdall AI | Threat Intelligence</title>
  <style>
    :root {{
      --bg: #05070a;
      --panel: #0d1117;
      --panel-light: #161b22;
      --text: #c9d1d9;
      --text-dim: #8b949e;
      --border: #30363d;
      --cyan: #58a6ff;
      --green: #3fb950;
      --amber: #d29922;
      --red: #f85149;
      --purple: #bc8cff;
      --red-glow: rgba(248, 81, 73, 0.1);
      --purple-glow: rgba(188, 140, 255, 0.1);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0; background: var(--bg); color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
      line-height: 1.5;
    }}
    main {{ max-width: 1200px; margin: 0 auto; padding: 40px 20px; }}
    
    header {{ margin-bottom: 32px; border-bottom: 1px solid var(--border); padding-bottom: 20px; }}
    h1 {{ font-size: 1.5rem; margin: 0; display: flex; align-items: center; gap: 10px; }}
    .logo {{ color: var(--green); font-weight: 800; letter-spacing: -0.5px; }}
    .version {{ font-size: 0.7rem; background: var(--border); padding: 2px 6px; border-radius: 4px; color: var(--text-dim); }}

    .insight-banner {{
        background: var(--red-glow); border: 1px solid var(--red); border-radius: 8px;
        padding: 16px; margin-bottom: 24px; display: flex; align-items: center; gap: 16px;
        animation: pulse 2s infinite;
    }}
    .banner--compromised {{ background: var(--purple-glow); border-color: var(--purple); }}
    @keyframes pulse {{
        0% {{ box-shadow: 0 0 0 0 rgba(248, 81, 73, 0.2); }}
        70% {{ box-shadow: 0 0 0 6px rgba(248, 81, 73, 0); }}
        100% {{ box-shadow: 0 0 0 0 rgba(248, 81, 73, 0); }}
    }}
    .insight-icon {{ font-size: 1.4rem; }}
    .insight-content strong {{ color: #fff; display: block; }}
    .insight-content p {{ color: var(--text-dim); font-size: 0.85rem; margin: 2px 0 0; }}

    .grid {{ display: grid; grid-template-columns: 1fr 380px; gap: 24px; }}
    .panel {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
    
    .editor-container {{ padding: 16px; }}
    textarea {{
      width: 100%; height: 400px; background: #010409; color: #79c0ff;
      border: 1px solid var(--border); border-radius: 6px; padding: 12px;
      font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, Liberation Mono, monospace;
      font-size: 12px; outline: none; resize: none;
    }}
    .btn-analyze {{
      margin-top: 12px; width: 100%; padding: 10px; background: var(--green);
      color: #fff; border: none; border-radius: 6px; font-weight: 600; cursor: pointer;
    }}
    .btn-analyze:hover {{ opacity: 0.9; }}

    .stats-bar {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 20px; }}
    .stat-card {{ background: var(--panel); border: 1px solid var(--border); padding: 12px; border-radius: 8px; text-align: center; }}
    .stat-val {{ font-size: 1.2rem; font-weight: bold; display: block; }}
    .stat-label {{ font-size: 0.65rem; color: var(--text-dim); text-transform: uppercase; }}

    .finding {{ margin-bottom: 16px; padding: 16px; border-left: 4px solid var(--border); }}
    .finding.comprometido {{ border-left-color: var(--purple); }}
    .finding.crítico {{ border-left-color: var(--red); }}
    .finding.suspeito {{ border-left-color: var(--amber); }}
    
    .finding-header {{ display: flex; justify-content: space-between; align-items: start; margin-bottom: 12px; }}
    .ip-addr {{ font-size: 1.1rem; font-weight: bold; color: #fff; }}
    .risk-badge {{ font-size: 0.7rem; font-weight: 800; padding: 2px 8px; border-radius: 99px; }}
    .risk--comprometido {{ background: var(--purple); color: #fff; }}
    .risk--crítico {{ background: var(--red); color: #fff; }}
    .risk--suspeito {{ background: var(--amber); color: #000; }}

    .risk-meter {{ height: 4px; background: var(--border); border-radius: 2px; margin: 8px 0; overflow: hidden; }}
    .risk-fill {{ height: 100%; transition: width 0.5s; }}

    .meta-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 0.75rem; color: var(--text-dim); }}
    .meta-item b {{ color: var(--text); }}

    .timeline {{ margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border); }}
    .timeline-title {{ font-size: 0.65rem; color: var(--text-dim); text-transform: uppercase; margin-bottom: 8px; display: block; }}
    .timeline-item {{ font-family: monospace; font-size: 11px; display: flex; gap: 8px; margin-bottom: 2px; }}
    .t-time {{ color: var(--text-dim); min-width: 55px; }}
    .t-status {{ font-weight: bold; width: 50px; }}
    .status--failed {{ color: var(--red); }}
    .status--success {{ color: var(--green); }}

    @media (max-width: 900px) {{ .grid {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1><span class="logo">HEIMDALL</span> GATEKEEPER <span class="version">v4.0 PRO</span></h1>
    </header>

    {insight_html}

    <div class="grid">
      <section>
        <div class="panel editor-container">
          <form method="post" action="/analyze">
            <textarea name="logs" spellcheck="false">{escape(log_text)}</textarea>
            <button type="submit" class="btn-analyze">RUN SECURITY ANALYSIS</button>
          </form>
        </div>
      </section>

      <aside>
        <div class="stats-bar">
          <div class="stat-card"><span class="stat-val">{compromised_count}</span><span class="stat-label">Compromised</span></div>
          <div class="stat-card"><span class="stat-val">{critical_count}</span><span class="stat-label">Critical</span></div>
          <div class="stat-card"><span class="stat-val">{int(avg_risk)}</span><span class="stat-label">Avg Risk</span></div>
        </div>
        
        <div class="results-list">
          {empty_state}
          {cards}
        </div>
      </aside>
    </div>
  </main>
</body>
</html>"""


def render_finding_card(item: dict) -> str:
    classification = item["classification"]
    score = item["risk_score"]
    
    # Timeline HTML
    timeline_items = []
    for entry in item["timeline"]:
        status_class = f"status--{entry['status']}"
        timeline_items.append(f"""
            <div class="timeline-item">
                <span class="t-time">[{entry['time']}]</span>
                <span class="t-status {status_class}">{entry['status'].upper()}</span>
                <span class="t-user">{escape(entry['user'])}</span>
            </div>
        """)
    
    timeline_html = f"""
        <div class="timeline">
            <span class="timeline-title">Event Timeline (Last 10)</span>
            {''.join(timeline_items)}
        </div>
    """

    return f"""
    <div class="panel finding {classification}">
        <div class="finding-header">
            <span class="ip-addr">{escape(item["ip"])}</span>
            <span class="risk-badge risk--{classification}">{score}% RISK</span>
        </div>
        
        <div class="risk-meter">
            <div class="risk-fill risk--{classification}" style="width: {score}%"></div>
        </div>

        <div class="meta-grid">
            <div class="meta-item">Users: <b>{escape(item["user"])}</b></div>
            <div class="meta-item">Total Events: <b>{item["count"]}</b></div>
            <div class="meta-item">Duration: <b>{int(item["duration_seconds"])}s</b></div>
            <div class="meta-item">MITRE: <b>{", ".join(item["mitre_techniques"]) or "N/A"}</b></div>
        </div>

        {timeline_html}
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
