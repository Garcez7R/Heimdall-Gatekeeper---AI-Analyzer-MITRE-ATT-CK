from collections import defaultdict
from core.models import Event, AnalysisResult

THRESHOLD = 5

class FailedLoginDetector:
    def __init__(self):
        self.failed_attempts = defaultdict(int)

    def analyze(self, event: Event) -> AnalysisResult | None:
        if event.status != "failed":
            return None

        self.failed_attempts[event.ip] += 1
        attempts = self.failed_attempts[event.ip]

        if attempts >= THRESHOLD:
            return AnalysisResult(
                classification="crítico",
                confidence=0.9,
                mitre_techniques=["T1110"],
                explanation="Múltiplas tentativas de login falharam, indicando possível ataque de força bruta.",
                reasoning=f"IP {event.ip} realizou {attempts} tentativas falhas."
            )

        return AnalysisResult(
            classification="suspeito",
            confidence=0.6,
            mitre_techniques=[],
            explanation="Tentativa de login falhou.",
            reasoning=f"Falha isolada do IP {event.ip}."
        )
