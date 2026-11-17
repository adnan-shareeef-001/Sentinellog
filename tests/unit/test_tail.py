"""Unit tests for the live log tailing streamer."""

import threading
import time
from pathlib import Path

from sentinellog.ingest.tail import tail_file


def test_tail_file_reading(tmp_path: Path) -> None:
    log_file = tmp_path / "tail_test.log"
    log_file.write_text("initial line 1\ninitial line 2\n", encoding="utf-8")

    stop_event = threading.Event()
    read_lines: list[str] = []

    def _tail_worker() -> None:
        for _num, line in tail_file(
            log_file, from_start=True, poll_interval=0.05, stop_event=stop_event
        ):
            read_lines.append(line)
            if len(read_lines) >= 3:
                stop_event.set()
                break

    t = threading.Thread(target=_tail_worker)
    t.start()

    time.sleep(0.1)
    with log_file.open("a", encoding="utf-8") as f:
        f.write("appended line 3\n")

    t.join(timeout=2.0)
    stop_event.set()

    assert len(read_lines) == 3
    assert read_lines[0] == "initial line 1"
    assert read_lines[1] == "initial line 2"
    assert read_lines[2] == "appended line 3"
