from core.models import AnalysisResult, Event
from detectors.failed_login_detector import FailedLoginDetector
from parsers.ssh_parser import parse_ssh_log


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
