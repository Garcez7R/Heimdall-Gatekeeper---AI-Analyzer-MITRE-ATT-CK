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
        # Mesmo se o detector não retornar um AnalysisResult (ex: status="success"), 
        # nós guardamos o evento para análise comportamental posterior.
        findings.append((event, result))

    return findings

def analyze_text(log_text: str) -> list[tuple[Event, AnalysisResult]]:
    return analyze_lines(log_text.splitlines())

def get_grouped_findings(findings: list[tuple[Event, AnalysisResult]]) -> dict:
    """
    Agrupa os achados por IP para uma visão consolidada e detecta padrões complexos.
    """
    grouped = defaultdict(lambda: {
        "ip": "",
        "user": set(),
        "count": 0,
        "failed_count": 0,
        "success_count": 0,
        "classification": "suspeito",
        "confidence": 0.0,
        "mitre_techniques": set(),
        "explanations": [],
        "reasoning": "",
        "is_critical": False,
        "is_compromised": False,
        "last_status": ""
    })

    for event, result in findings:
        ip_data = grouped[event.ip]
        ip_data["ip"] = event.ip
        ip_data["user"].add(event.user or "desconhecido")
        ip_data["count"] += 1
        
        if event.status == "failed":
            ip_data["failed_count"] += 1
            if result:
                ip_data["mitre_techniques"].update(result.mitre_techniques)
                if result.explanation not in ip_data["explanations"]:
                    ip_data["explanations"].append(result.explanation)
                
                # Atualiza criticidade baseada no detector de falhas
                if result.classification == "crítico":
                    ip_data["is_critical"] = True
                    ip_data["confidence"] = max(ip_data["confidence"], result.confidence)
                    ip_data["reasoning"] = result.reasoning
                elif not ip_data["is_critical"]:
                    ip_data["confidence"] = max(ip_data["confidence"], result.confidence)
                    ip_data["reasoning"] = result.reasoning
        
        elif event.status == "success":
            ip_data["success_count"] += 1
            # DETECÇÃO DE COMPROMETIMENTO: Falhas seguidas de sucesso
            if ip_data["failed_count"] >= 3:
                ip_data["is_compromised"] = True
                ip_data["classification"] = "comprometido"
                ip_data["confidence"] = 1.0
                ip_data["mitre_techniques"].update(["T1110", "T1078"]) # Brute Force + Valid Accounts
                ip_data["reasoning"] = f"IP realizou {ip_data['failed_count']} falhas seguidas de um login bem-sucedido."
                msg = "🚨 POSSÍVEL COMPROMETIMENTO: Login realizado após múltiplas falhas."
                if msg not in ip_data["explanations"]:
                    ip_data["explanations"].insert(0, msg)

    # Pós-processamento para exibição
    result_list = []
    for ip in grouped:
        data = grouped[ip]
        # Se não houve falhas nem comprometimento, e apenas sucessos isolados, podemos ignorar ou marcar como normal
        if data["failed_count"] == 0 and not data["is_compromised"]:
            continue
            
        data["user"] = ", ".join(data["user"])
        data["mitre_techniques"] = sorted(list(data["mitre_techniques"]))
        
        # Formatação da narrativa (Removendo o "|")
        if data["is_compromised"]:
            data["explanation"] = "Padrão de comprometimento detectado: múltiplas falhas seguidas de acesso garantido."
        elif data["is_critical"]:
            data["explanation"] = "Ataque de força bruta identificado com alta densidade de falhas."
        else:
            data["explanation"] = "Atividade suspeita: tentativas de login falhas isoladas."
            
        result_list.append(data)
    
    # Ordenação por risco: Comprometido > Crítico > Suspeito
    rank = {"comprometido": 0, "crítico": 1, "suspeito": 2}
    result_list.sort(key=lambda x: rank.get(x["classification"], 3))
        
    return result_list
