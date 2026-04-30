import argparse
import sys
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

sys.dont_write_bytecode = True

from core.analyzer import analyze_text
from core.cache import cleanup_runtime_cache
from formatters.result_formatter import analysis_to_dict

DEFAULT_SAMPLE = """Jul 10 10:15:30 server sshd[1234]: Failed password for invalid user admin from 192.168.1.10 port 22 ssh2
Jul 10 10:15:32 server sshd[1234]: Failed password for invalid user admin from 192.168.1.10 port 22 ssh2
Jul 10 10:15:34 server sshd[1234]: Failed password for invalid user admin from 192.168.1.10 port 22 ssh2
Jul 10 10:15:36 server sshd[1234]: Failed password for invalid user admin from 192.168.1.10 port 22 ssh2
Jul 10 10:15:38 server sshd[1234]: Failed password for invalid user admin from 192.168.1.10 port 22 ssh2"""


def render_page(log_text: str = DEFAULT_SAMPLE, findings: list[dict] | None = None) -> str:
    findings = findings or []
    critical_count = sum(1 for item in findings if item["classification"] == "crítico")
    suspicious_count = sum(1 for item in findings if item["classification"] == "suspeito")
    cards = "\n".join(render_finding_card(item) for item in findings)
    empty_state = "" if findings else "<p class='empty'>Cole logs SSH/auth.log e clique em analisar.</p>"

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
    h1 {{ font-size: clamp(2rem, 5vw, 4rem); line-height: 0.95; letter-spacing: 0; }}
    h2 {{ font-size: 1rem; }}
    .eyebrow, .metric span, button, label {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}
    .eyebrow {{ color: var(--green); font-size: 0.78rem; margin-bottom: 10px; }}
    .subtitle {{ max-width: 680px; color: var(--muted); margin-top: 14px; }}
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
      padding: 0.8rem 1rem;
      background: rgba(79, 215, 255, 0.12);
      color: var(--text);
      cursor: pointer;
    }}
    .results {{ display: grid; gap: 14px; }}
    .metrics {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; padding: 14px; }}
    .metric {{ border: 1px solid var(--line); border-radius: 12px; padding: 12px; background: var(--panel-soft); }}
    .metric strong {{ display: block; font-size: 1.6rem; }}
    .metric span {{ color: var(--muted); font-size: 0.68rem; }}
    .finding {{ padding: 16px; display: grid; gap: 10px; }}
    .finding h2 {{ display: flex; justify-content: space-between; gap: 12px; align-items: center; }}
    .badge {{ border-radius: 999px; padding: 0.28rem 0.58rem; font-size: 0.68rem; }}
    .badge--crítico {{ color: #ffd9dc; background: rgba(255, 90, 95, 0.16); border: 1px solid rgba(255, 90, 95, 0.32); }}
    .badge--suspeito {{ color: #ffe9c7; background: rgba(255, 180, 84, 0.14); border: 1px solid rgba(255, 180, 84, 0.28); }}
    .meta {{ display: flex; flex-wrap: wrap; gap: 8px; color: var(--muted); font-size: 0.88rem; }}
    .meta span {{ border: 1px solid var(--line); border-radius: 999px; padding: 0.24rem 0.5rem; }}
    .explanation {{ color: var(--text); }}
    .reasoning {{ color: var(--muted); }}
    .empty {{ padding: 18px; color: var(--muted); }}
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
        <p class="eyebrow">Heimdall AI</p>
        <h1>Log Analyzer</h1>
        <p class="subtitle">Interface web local para analisar logs SSH, classificar risco e explicar eventos sem gravar uploads, banco ou arquivos temporários.</p>
      </div>
    </header>
    <section class="shell">
      <form class="panel" method="post" action="/analyze">
        <label for="logs">Logs SSH/auth.log</label>
        <textarea id="logs" name="logs" spellcheck="false">{escape(log_text)}</textarea>
        <div class="actions"><button type="submit">Analisar logs</button></div>
      </form>
      <aside class="results">
        <div class="panel metrics">
          <div class="metric"><strong>{len(findings)}</strong><span>Eventos</span></div>
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
    return f"""<article class="panel finding">
  <h2>{escape(item["ip"] or "IP desconhecido")} <span class="badge badge--{escape(classification)}">{escape(classification)}</span></h2>
  <div class="meta">
    <span>Usuário: {escape(item["user"] or "desconhecido")}</span>
    <span>Confiança: {item["confidence"]:.2f}</span>
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
        findings = [analysis_to_dict(event, result) for event, result in analyze_text(log_text)]
        self.respond_html(render_page(log_text, findings))

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
