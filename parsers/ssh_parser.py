import re
from datetime import datetime
from core.models import Event

SSH_REGEX = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+).*sshd.*(?P<status>Failed|Accepted).*for\s+(invalid user\s+)?(?P<user>\w+)\s+from\s+(?P<ip>[\d\.]+)'
)

def parse_ssh_log(line: str) -> Event | None:
    match = SSH_REGEX.search(line)
    if not match:
        return None

    now_year = datetime.now().year
    timestamp_str = f"{match.group('month')} {match.group('day')} {now_year} {match.group('time')}"
    timestamp = datetime.strptime(timestamp_str, "%b %d %Y %H:%M:%S")

    status = "failed" if match.group("status") == "Failed" else "success"

    return Event(
        raw_log=line.strip(),
        source="ssh",
        timestamp=timestamp,
        ip=match.group("ip"),
        user=match.group("user"),
        status=status
    )
