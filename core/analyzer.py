from core.models import AnalysisResult, Event
from detectors.failed_login_detector import FailedLoginDetector
from parsers.ssh_parser import parse_ssh_log
from collections import defaultdict
from datetime import datetime

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

def calculate_risk_score(data: dict) -> int:
    """
    Calcula um score de 0 a 100 baseado no comportamento.
    """
    score = 0
    
    # Pontuação por falhas (max 40)
    score += min(data["failed_count"] * 8, 40)
    
    # Bônus por densidade temporal (janela curta = maior risco)
    if data["failed_count"] >= 2 and data["duration_seconds"] > 0:
        events_per_second = data["failed_count"] / data["duration_seconds"]
        if events_per_second > 0.5: # Mais de 1 evento a cada 2 seg
            score += 20
    
    # Bônus por comprometimento (sucesso após falhas)
    if data["is_compromised"]:
        score += 40
        
    return min(score, 100)

def get_grouped_findings(findings: list[tuple[Event, AnalysisResult]]) -> list[dict]:
    """
    Agrupa achados por IP com análise temporal, score de risco e timeline.
    """
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
        "timeline": [] # Lista de {time, status, user}
    })

    for event, result in findings:
        ip_data = grouped[event.ip]
        ip_data["ip"] = event.ip
        ip_data["user"].add(event.user or "desconhecido")
        ip_data["count"] += 1
        
        # Timeline
        ip_data["timeline"].append({
            "time": event.timestamp.strftime("%H:%M:%S"),
            "status": event.status,
            "user": event.user or "desconhecido"
        })
        
        # Janela Temporal
        if ip_data["first_seen"] is None or event.timestamp < ip_data["first_seen"]:
            ip_data["first_seen"] = event.timestamp
        if ip_data["last_seen"] is None or event.timestamp > ip_data["last_seen"]:
            ip_data["last_seen"] = event.timestamp

        if event.status == "failed":
            ip_data["failed_count"] += 1
            if result:
                ip_data["mitre_techniques"].update(result.mitre_techniques)
                if result.classification == "crítico":
                    ip_data["is_critical"] = True
        
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
            
        # Calcula duração da janela
        duration = (data["last_seen"] - data["first_seen"]).total_seconds()
        data["duration_seconds"] = duration
        
        # Risk Score
        data["risk_score"] = calculate_risk_score(data)
        
        # Classificação Final baseada no Score
        if data["is_compromised"]:
            data["classification"] = "comprometido"
        elif data["risk_score"] >= 60:
            data["classification"] = "crítico"
        else:
            data["classification"] = "suspeito"
            
        # Formatação de campos para UI
        data["user"] = ", ".join(data["user"])
        data["mitre_techniques"] = sorted(list(data["mitre_techniques"]))
        data["timeline"] = data["timeline"][-10:] # Mantém apenas os últimos 10 eventos
        
        result_list.append(data)
    
    # Ordenação por Risk Score (Maior primeiro)
    result_list.sort(key=lambda x: x["risk_score"], reverse=True)
        
    return result_list
