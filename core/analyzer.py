from core.models import AnalysisResult, Event
from detectors.failed_login_detector import FailedLoginDetector
from parsers.ssh_parser import parse_ssh_log
from collections import defaultdict

def analyze_lines(lines: list[str]) -> list[tuple[Event, AnalysisResult]]:
    detector = FailedLoginDetector()
    findings = []

    for line in lines:
        event = parse_ssh_log(line)
        if not event:
            continue

        result = detector.analyze(event)
        if result:
            findings.append((event, result))

    return findings

def analyze_text(log_text: str) -> list[tuple[Event, AnalysisResult]]:
    return analyze_lines(log_text.splitlines())

def get_grouped_findings(findings: list[tuple[Event, AnalysisResult]]) -> dict:
    """
    Agrupa os achados por IP para uma visão consolidada.
    """
    grouped = defaultdict(lambda: {
        "ip": "",
        "user": set(),
        "count": 0,
        "classification": "suspeito",
        "confidence": 0.0,
        "mitre_techniques": set(),
        "explanations": set(),
        "reasoning": "",
        "is_critical": False
    })

    for event, result in findings:
        ip_data = grouped[event.ip]
        ip_data["ip"] = event.ip
        ip_data["user"].add(event.user or "desconhecido")
        ip_data["count"] += 1
        ip_data["mitre_techniques"].update(result.mitre_techniques)
        ip_data["explanations"].add(result.explanation)
        
        # Se qualquer evento for crítico, o grupo se torna crítico
        if result.classification == "crítico":
            ip_data["classification"] = "crítico"
            ip_data["is_critical"] = True
            ip_data["confidence"] = max(ip_data["confidence"], result.confidence)
            ip_data["reasoning"] = result.reasoning
        elif not ip_data["is_critical"]:
            ip_data["confidence"] = max(ip_data["confidence"], result.confidence)
            ip_data["reasoning"] = result.reasoning

    # Converte sets para listas/strings para exibição
    result_list = []
    for ip in grouped:
        data = grouped[ip]
        data["user"] = ", ".join(data["user"])
        data["mitre_techniques"] = list(data["mitre_techniques"])
        data["explanation"] = " | ".join(data["explanations"])
        result_list.append(data)
        
    return result_list
