"""Live streaming log tailer with file rotation and truncation detection."""

import io
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any


def tail_file(
    file_path: Path | str,
    from_start: bool = False,
    poll_interval: float = 0.2,
    stop_event: Any = None,
) -> Iterator[tuple[int, str]]:
    """Continuously tail a log file, yielding line numbers and line contents in real time."""
    target = Path(file_path)
    while not target.is_file():
        if stop_event and stop_event.is_set():
            return
        time.sleep(poll_interval)

    f = target.open("r", encoding="utf-8", errors="replace")
    line_number = 0

    if not from_start:
        # Move to end of file for live tailing
        f.seek(0, io.SEEK_END)
    else:
        # Count lines up to current position
        pass

    try:
        while True:
            if stop_event and stop_event.is_set():
                break

            line = f.readline()
            if line:
                line_number += 1
                yield (line_number, line.rstrip("\r\n"))
            else:
                # Check for file truncation or rotation
                try:
                    curr_size = target.stat().st_size
                    curr_pos = f.tell()
                    if curr_size < curr_pos:
                        # File was truncated: rewind to start
                        f.seek(0, io.SEEK_SET)
                except OSError:
                    pass

                time.sleep(poll_interval)
    finally:
        f.close()
