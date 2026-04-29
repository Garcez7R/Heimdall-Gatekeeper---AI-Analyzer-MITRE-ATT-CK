import sys
import json
from parsers.ssh_parser import parse_ssh_log
from detectors.failed_login_detector import FailedLoginDetector

def main():
    if len(sys.argv) < 2:
        print("Uso: python -m cli.main <arquivo_log>")
        return

    log_file = sys.argv[1]
    detector = FailedLoginDetector()

    try:
        with open(log_file, "r") as f:
            for line in f:
                event = parse_ssh_log(line)
                if not event:
                    continue

                result = detector.analyze(event)
                if result:
                    print(json.dumps({
                        "ip": event.ip,
                        "user": event.user,
                        "classification": result.classification,
                        "confidence": result.confidence,
                        "explanation": result.explanation,
                        "reasoning": result.reasoning
                    }, ensure_ascii=False))
    except FileNotFoundError:
        print(f"Erro: Arquivo '{log_file}' não encontrado.")
    except Exception as e:
        print(f"Ocorreu um erro: {e}")

if __name__ == "__main__":
    main()
