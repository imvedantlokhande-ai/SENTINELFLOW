"""Unit tests strictly covering the PromptWars Efficiency Criteria."""

from benchmark import run_benchmark


def test_reproducible_benchmark_speed():
    """Efficiency check: Core domain operations must complete in sub-millisecond latencies."""
    results = run_benchmark(iterations=100)

    # Correlation latency should be well under 5 milliseconds
    assert results["corr_latency_ms"] < 5.0
    # Throughput should exceed 10,000 events per second
    assert results["events_per_sec"] > 10_000
    # Verification latency should be sub-millisecond
    assert results["verif_latency_ms"] < 1.0
