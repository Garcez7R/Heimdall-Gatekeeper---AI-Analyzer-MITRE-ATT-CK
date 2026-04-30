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
Jul 10 10:15:32 server sshd[1234]: Failed password for invalid user admin from 192.168.1.10 port 22 ssh2
Jul 10 10:15:34 server sshd[1234]: Failed password for invalid user admin from 192.168.1.10 port 22 ssh2
Jul 10 10:15:36 server sshd[1234]: Failed password for invalid user admin from 192.168.1.10 port 22 ssh2
Jul 10 10:15:38 server sshd[1234]: Failed password for invalid user admin from 192.168.1.10 port 22 ssh2"""


def render_page(log_text: str = DEFAULT_SAMPLE, grouped_findings: list[dict] | None = None) -> str:
    grouped_findings = grouped_findings or []
    critical_findings = [f for f in grouped_findings if f["classification"] == "crítico"]
    critical_count = len(critical_findings)
    suspicious_count = sum(1 for f in grouped_findings if f["classification"] == "suspeito")
    
    cards = "\n".join(render_finding_card(item) for item in grouped_findings)
    empty_state = "" if grouped_findings else "<p class='empty'>Cole logs SSH/auth.log e clique em analisar.</p>"

    # Insight de topo se houver críticos
    insight_html = ""
    if critical_findings:
        top_critical = critical_findings[0]
        mitre = ", ".join(top_critical["mitre_techniques"]) if top_critical["mitre_techniques"] else "N/A"
        insight_html = f"""
        <div class="insight-banner">
            <div class="insight-icon">⚠️</div>
            <div class="insight-content">
                <strong>Possível ataque de força bruta detectado</strong>
                <p>IP: {escape(top_critical["ip"])} | MITRE: {escape(mitre)}</p>
            </div>
        </div>
        """

    return f"""<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Heimdall AI Analyzer</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #07090d;
      --panel: #10151f;
      --panel-soft: #151c28;
      --text: #edf2f7;
      --muted: #9aa7b6;
      --line: #263244;
      --green: #3fb950;
      --cyan: #4fd7ff;
      --amber: #ffb454;
      --red: #ff5a5f;
      --red-glow: rgba(255, 90, 95, 0.15);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      background: radial-gradient(circle at top right, rgba(79, 215, 255, 0.12), transparent 32%), var(--bg);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.5;
    }}
    main {{ width: min(1120px, calc(100% - 32px)); margin: 0 auto; padding: 32px 0 48px; }}
    header {{ display: flex; justify-content: space-between; gap: 20px; align-items: end; margin-bottom: 24px; }}
    h1, h2, p {{ margin: 0; }}
    h1 {{ font-size: clamp(2rem, 5vw, 3.5rem); line-height: 0.95; letter-spacing: -0.02em; }}
    h2 {{ font-size: 1.1rem; }}
    .eyebrow, .metric span, button, label, .badge {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}
    .eyebrow {{ color: var(--green); font-size: 0.78rem; margin-bottom: 10px; }}
    .subtitle {{ max-width: 680px; color: var(--muted); margin-top: 14px; }}
    
    .insight-banner {{
        background: var(--red-glow);
        border: 1px solid rgba(255, 90, 95, 0.3);
        border-radius: 12px;
        padding: 16px;
        margin-bottom: 24px;
        display: flex;
        align-items: center;
        gap: 16px;
        animation: pulse 2s infinite;
    }}
    @keyframes pulse {{
        0% {{ box-shadow: 0 0 0 0 rgba(255, 90, 95, 0.4); }}
        70% {{ box-shadow: 0 0 0 10px rgba(255, 90, 95, 0); }}
        100% {{ box-shadow: 0 0 0 0 rgba(255, 90, 95, 0); }}
    }}
    .insight-icon {{ font-size: 1.5rem; }}
    .insight-content strong {{ color: var(--red); display: block; font-size: 1.1rem; }}
    .insight-content p {{ color: var(--muted); font-size: 0.9rem; }}

    .shell {{ display: grid; grid-template-columns: minmax(0, 1.05fr) minmax(320px, 0.95fr); gap: 18px; align-items: start; }}
    .panel {{
      border: 1px solid var(--line);
      border-radius: 18px;
      background: linear-gradient(180deg, rgba(255,255,255,0.035), rgba(255,255,255,0.012)), var(--panel);
      box-shadow: 0 24px 60px rgba(0, 0, 0, 0.28);
    }}
    form {{ padding: 18px; }}
    label {{ display: block; color: var(--muted); font-size: 0.72rem; margin-bottom: 10px; }}
    textarea {{
      width: 100%;
      min-height: 430px;
      resize: vertical;
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 14px;
      background: #080c12;
      color: var(--text);
      font: 0.9rem/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      outline: none;
    }}
    textarea:focus {{ border-color: rgba(79, 215, 255, 0.55); }}
    .actions {{ display: flex; justify-content: flex-end; margin-top: 14px; }}
    button {{
      border: 1px solid rgba(79, 215, 255, 0.35);
      border-radius: 999px;
      padding: 0.8rem 1.5rem;
      background: rgba(79, 215, 255, 0.12);
      color: var(--text);
      cursor: pointer;
      transition: all 0.2s;
    }}
    button:hover {{ background: rgba(79, 215, 255, 0.2); border-color: var(--cyan); }}
    
    .results {{ display: grid; gap: 14px; }}
    .metrics {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; padding: 14px; }}
    .metric {{ border: 1px solid var(--line); border-radius: 12px; padding: 12px; background: var(--panel-soft); text-align: center; }}
    .metric strong {{ display: block; font-size: 1.6rem; }}
    .metric span {{ color: var(--muted); font-size: 0.68rem; }}
    
    .finding {{ padding: 20px; display: grid; gap: 12px; position: relative; overflow: hidden; }}
    .finding.critical {{ border-left: 4px solid var(--red); background: linear-gradient(90deg, var(--red-glow), transparent); }}
    
    .finding h2 {{ display: flex; justify-content: space-between; gap: 12px; align-items: center; }}
    .badge {{ border-radius: 4px; padding: 0.2rem 0.5rem; font-size: 0.65rem; font-weight: bold; }}
    .badge--crítico {{ color: #fff; background: var(--red); }}
    .badge--suspeito {{ color: #000; background: var(--amber); }}
    
    .meta {{ display: flex; flex-wrap: wrap; gap: 8px; color: var(--muted); font-size: 0.85rem; }}
    .meta span {{ border: 1px solid var(--line); border-radius: 6px; padding: 0.2rem 0.6rem; background: rgba(0,0,0,0.2); }}
    .event-count {{ color: var(--cyan); font-weight: bold; }}
    
    .explanation {{ color: var(--text); font-weight: 500; }}
    .reasoning {{ color: var(--muted); font-size: 0.9rem; border-top: 1px solid var(--line); pt: 10px; }}
    .empty {{ padding: 24px; color: var(--muted); text-align: center; font-style: italic; }}
    
    @media (max-width: 860px) {{
      header, .shell {{ grid-template-columns: 1fr; display: grid; }}
      .metrics {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <p class="eyebrow">Heimdall Gatekeeper</p>
        <h1>Security Analyzer</h1>
        <p class="subtitle">Análise inteligente de logs SSH com agrupamento por IP e detecção de padrões MITRE ATT&CK.</p>
      </div>
    </header>

    {insight_html}

    <section class="shell">
      <form class="panel" method="post" action="/analyze">
        <label for="logs">Logs SSH/auth.log</label>
        <textarea id="logs" name="logs" spellcheck="false">{escape(log_text)}</textarea>
        <div class="actions"><button type="submit">Executar Análise</button></div>
      </form>
      <aside class="results">
        <div class="panel metrics">
          <div class="metric"><strong>{len(grouped_findings)}</strong><span>IPs Únicos</span></div>
          <div class="metric"><strong>{suspicious_count}</strong><span>Suspeitos</span></div>
          <div class="metric"><strong>{critical_count}</strong><span>Críticos</span></div>
        </div>
        {empty_state}
        {cards}
      </aside>
    </section>
  </main>
</body>
</html>"""


def render_finding_card(item: dict) -> str:
    mitre = ", ".join(item["mitre_techniques"]) if item["mitre_techniques"] else "N/A"
    classification = item["classification"]
    critical_class = "critical" if classification == "crítico" else ""
    
    return f"""<article class="panel finding {critical_class}">
  <h2>{escape(item["ip"] or "IP desconhecido")} <span class="badge badge--{escape(classification)}">{escape(classification)}</span></h2>
  <div class="meta">
    <span class="event-count">Eventos: {item["count"]}</span>
    <span>Usuários: {escape(item["user"])}</span>
    <span>MITRE: {escape(mitre)}</span>
  </div>
  <p class="explanation">{escape(item["explanation"])}</p>
  <p class="reasoning">{escape(item["reasoning"] or "Sem raciocínio adicional.")}</p>
</article>"""


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
        
        # Realiza a análise e agrupa os resultados
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
