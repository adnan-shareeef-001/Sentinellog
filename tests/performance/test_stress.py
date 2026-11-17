"""High-throughput stress and performance benchmark tests."""

import time
from pathlib import Path

import pytest

from sentinellog.engine.engine import DetectionEngine
from sentinellog.ingest.reader import read_lines
from sentinellog.parsers.ssh_auth import SSHAuthParser
from sentinellog.rules.loader import load_rules_from_dir


@pytest.mark.slow
def test_high_throughput_ingest_and_detection(tmp_path: Path) -> None:
    """Benchmark: Ingest and detect over 50,000 to 100,000 lines within 10 seconds."""
    log_file = tmp_path / "stress_auth.log"
    total_lines = 100_000

    # Write synthetic lines rapidly
    sample_line = (
        "Oct 13 10:14:00 srv-prod-01 sshd[1234]: "
        "Accepted publickey for devops from 10.0.0.15 port 45212 ssh2: RSA SHA256:abc...\n"
    )
    with log_file.open("w", encoding="utf-8") as f:
        # Write chunks of 1,000 lines
        chunk = sample_line * 1000
        for _ in range(total_lines // 1000):
            f.write(chunk)

    rules = load_rules_from_dir("rules")
    engine = DetectionEngine(rules=rules)
    parser = SSHAuthParser()

    start_time = time.perf_counter()
    parsed_count = 0

    for line_num, line in read_lines(log_file):
        event = parser.parse(line, str(log_file), line_num)
        if event is not None:
            engine.process_event(event)
            parsed_count += 1

    engine.flush()
    elapsed = time.perf_counter() - start_time
    throughput = parsed_count / elapsed if elapsed > 0 else 0
    res_msg = f"\nPerformance Result: {throughput:.1f} events/s ({parsed_count} in {elapsed:.2f}s)"
    print(res_msg)

    # Assert processing 100k lines takes less than 10 seconds
    assert parsed_count == total_lines
    assert elapsed < 10.0, f"Processing took {elapsed:.2f}s, exceeding 10.0s threshold."
    assert throughput >= 10_000.0, f"Throughput was {throughput:.1f} events/s, below 10k/s."
