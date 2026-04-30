from pathlib import Path
import shutil


def cleanup_runtime_cache(root: str | Path | None = None) -> None:
    project_root = Path(root or Path.cwd()).resolve()

    for cache_dir in project_root.rglob("__pycache__"):
        if ".git" in cache_dir.parts:
            continue
        shutil.rmtree(cache_dir, ignore_errors=True)

    for pyc_file in project_root.rglob("*.pyc"):
        if ".git" in pyc_file.parts:
            continue
        try:
            pyc_file.unlink(missing_ok=True)
        except OSError:
            continue
