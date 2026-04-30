from core.models import AnalysisResult, Event
from detectors.failed_login_detector import FailedLoginDetector
from parsers.ssh_parser import parse_ssh_log
from collections import defaultdict
from datetime import datetime
import json
import os

# Caminho para "banco de dados" simples de persistência
HISTORY_FILE = "analysis_history.json"

def analyze_lines(lines: list[str]) -> list[tuple[Event, AnalysisResult]]:
    detector = FailedLoginDetector()
    findings = []

    for line in lines:
        event = parse_ssh_log(line)
        if not event:
            continue

        result = detector.analyze(event)
        findings.append((event, result))

    return findings

def analyze_text(log_text: str) -> list[tuple[Event, AnalysisResult]]:
    return analyze_lines(log_text.splitlines())

def get_context_enrichment(ip: str) -> dict:
    """
    Simula enriquecimento de contexto (GeoIP/ASN/Reputação).
    Em um cenário real, aqui seria feita uma chamada de API ou busca em DB local.
    """
    # Simulação baseada em faixas de IP para demonstração
    if ip.startswith("192.168"):
        return {"country": "Local Network", "city": "Internal", "asn": "N/A", "reputation": "Trusted"}
    elif ip.startswith("203."):
        return {"country": "Netherlands", "city": "Amsterdam", "asn": "AS16276 (OVH)", "reputation": "Suspicious"}
    else:
        return {"country": "Unknown", "city": "Unknown", "asn": "Unknown", "reputation": "Neutral"}

def calculate_deterministic_risk_score(data: dict) -> int:
    """
    Cálculo de score determinístico e explicável.
    """
    score = 0
    
    # 1. Volume de falhas (max 40)
    if data["failed_count"] >= 10: score += 40
    elif data["failed_count"] >= 5: score += 30
    elif data["failed_count"] >= 1: score += 10
    
    # 2. Comprometimento (Ouro da detecção)
    if data["is_compromised"]:
        score += 40
        
    # 3. Usuários Privilegiados
    if "root" in data["user"] or "admin" in data["user"]:
        score += 10
        
    # 4. Intensidade Temporal (Burst)
    if data["failed_count"] >= 3 and data["duration_seconds"] < 10:
        score += 10
        
    return min(score, 100)

def save_to_history(new_findings: list[dict]):
    """
    Persiste os achados em um arquivo JSON para histórico.
    """
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                history = json.load(f)
        except:
            history = []
            
    # Adiciona timestamp da análise
    analysis_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "total_ips": len(new_findings),
            "compromised": sum(1 for f in new_findings if f["classification"] == "comprometido"),
            "critical": sum(1 for f in new_findings if f["classification"] == "crítico")
        },
        "details": new_findings[:5] # Salva apenas os top 5 para não inflar o arquivo
    }
    
    history.insert(0, analysis_entry)
    with open(HISTORY_FILE, "w") as f:
        json.dump(history[:20], f, indent=2) # Mantém apenas as últimas 20 análises

def get_grouped_findings(findings: list[tuple[Event, AnalysisResult]]) -> list[dict]:
    grouped = defaultdict(lambda: {
        "ip": "",
        "user": set(),
        "count": 0,
        "failed_count": 0,
        "success_count": 0,
        "classification": "suspeito",
        "risk_score": 0,
        "mitre_techniques": set(),
        "is_critical": False,
        "is_compromised": False,
        "first_seen": None,
        "last_seen": None,
        "timeline": [],
        "context": {}
    })

    for event, result in findings:
        ip_data = grouped[event.ip]
        ip_data["ip"] = event.ip
        ip_data["user"].add(event.user or "desconhecido")
        ip_data["count"] += 1
        
        ip_data["timeline"].append({
            "time": event.timestamp.strftime("%H:%M:%S"),
            "status": event.status,
            "user": event.user or "desconhecido"
        })
        
        if ip_data["first_seen"] is None or event.timestamp < ip_data["first_seen"]:
            ip_data["first_seen"] = event.timestamp
        if ip_data["last_seen"] is None or event.timestamp > ip_data["last_seen"]:
            ip_data["last_seen"] = event.timestamp

        if event.status == "failed":
            ip_data["failed_count"] += 1
            if result:
                ip_data["mitre_techniques"].update(result.mitre_techniques)
        
        elif event.status == "success":
            ip_data["success_count"] += 1
            if ip_data["failed_count"] >= 3:
                ip_data["is_compromised"] = True
                ip_data["mitre_techniques"].update(["T1110", "T1078"])

    result_list = []
    for ip in grouped:
        data = grouped[ip]
        if data["failed_count"] == 0 and not data["is_compromised"]:
            continue
            
        duration = (data["last_seen"] - data["first_seen"]).total_seconds()
        data["duration_seconds"] = duration
        
        # Enriquecimento de Contexto
        data["context"] = get_context_enrichment(ip)
        
        # Risk Score Determinístico
        data["risk_score"] = calculate_deterministic_risk_score(data)
        
        # Classificação Rígida
        if data["is_compromised"]:
            data["classification"] = "comprometido"
        elif data["risk_score"] >= 60:
            data["classification"] = "crítico"
        else:
            data["classification"] = "suspeito"
            
        data["user"] = ", ".join(data["user"])
        data["mitre_techniques"] = sorted(list(data["mitre_techniques"]))
        data["timeline"] = data["timeline"][-10:]
        
        result_list.append(data)
    
    result_list.sort(key=lambda x: x["risk_score"], reverse=True)
    
    # Persiste no histórico se houver resultados
    if result_list:
        save_to_history(result_list)
        
    return result_list

def get_analysis_history():
    """Retorna o histórico de análises salvas."""
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r") as f:
            return json.load(f)
    return []
