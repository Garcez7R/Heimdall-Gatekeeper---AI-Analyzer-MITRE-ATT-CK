import argparse
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from core.analyzer import analyze_lines
from core.cache import cleanup_runtime_cache
from formatters.result_formatter import format_analysis

def main():
    cleanup_runtime_cache(Path(__file__).resolve().parents[1])
    parser = argparse.ArgumentParser(
        description="Analyze SSH/auth logs and explain suspicious security events."
    )
    parser.add_argument("log_file", help="Path to the log file to analyze.")
    parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="json",
        help="Output format. Defaults to json.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output.",
    )
    args = parser.parse_args()

    emitted_results = 0

    try:
        with open(args.log_file, "r") as f:
            for event, result in analyze_lines(f.readlines()):
                if args.format == "text" and emitted_results:
                    print()
                print(format_analysis(event, result, args.format, args.pretty))
                emitted_results += 1
    except FileNotFoundError:
        print(f"Erro: Arquivo '{args.log_file}' não encontrado.")
    except Exception as e:
        print(f"Ocorreu um erro: {e}")

if __name__ == "__main__":
    main()
