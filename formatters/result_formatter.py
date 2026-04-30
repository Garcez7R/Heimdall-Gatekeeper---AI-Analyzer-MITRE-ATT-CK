import json
from typing import Literal

from core.models import AnalysisResult, Event

OutputFormat = Literal["json", "text"]


def analysis_to_dict(event: Event, result: AnalysisResult) -> dict:
    return {
        "timestamp": event.timestamp.isoformat(),
        "source": event.source,
        "ip": event.ip,
        "user": event.user,
        "status": event.status,
        "classification": result.classification,
        "confidence": result.confidence,
        "mitre_techniques": result.mitre_techniques,
        "explanation": result.explanation,
        "reasoning": result.reasoning,
        "raw_log": event.raw_log,
    }


def format_analysis(
    event: Event,
    result: AnalysisResult,
    output_format: OutputFormat = "json",
    pretty: bool = False,
) -> str:
    if output_format == "text":
        mitre = ", ".join(result.mitre_techniques) if result.mitre_techniques else "N/A"
        return "\n".join(
            [
                f"[{result.classification.upper()}] {event.source} event from {event.ip or 'unknown IP'}",
                f"User: {event.user or 'unknown'}",
                f"Confidence: {result.confidence:.2f}",
                f"MITRE ATT&CK: {mitre}",
                f"Explanation: {result.explanation}",
                f"Reasoning: {result.reasoning or 'N/A'}",
            ]
        )

    if output_format != "json":
        raise ValueError(f"Unsupported output format: {output_format}")

    indent = 2 if pretty else None
    return json.dumps(analysis_to_dict(event, result), ensure_ascii=False, indent=indent)
