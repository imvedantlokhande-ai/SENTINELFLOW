"""Unit tests for the Analytics and Plotly Visualization Engine."""

from sentinelflow.analytics import (
    calculate_soc_metrics,
    build_severity_donut_chart,
    build_attack_vectors_bar_chart,
    build_global_threat_map,
    build_entity_relationship_graph,
)
from sentinelflow.sample_data import (
    SEEDED_INCIDENTS,
    SYNTHETIC_ATTACK_VECTORS,
    SYNTHETIC_GEO_POINTS,
    SCENARIO_1_EVENTS,
)
from sentinelflow.audit import AuditTrail


def test_calculate_soc_metrics():
    """Test SOC metrics calculation from seeded incidents and audit trail."""
    audit = AuditTrail()
    audit.log("DEMO_INITIALIZED", "SUCCESS", "Init", actor="system")

    metrics = calculate_soc_metrics(
        incidents=SEEDED_INCIDENTS,
        audit_entries=audit.get_entries(),
        attack_vectors=SYNTHETIC_ATTACK_VECTORS,
    )

    assert metrics["total_incidents"] == len(SEEDED_INCIDENTS)
    assert metrics["critical_count"] == 2  # INC-003 and INC-006
    assert metrics["high_count"] == 2      # INC-001 and INC-002
    assert metrics["medium_count"] == 1    # INC-004
    assert metrics["verification_success_rate"] == 100.0


def test_build_plotly_charts_render_valid_figures():
    """Test that all Plotly chart generation functions return valid non-empty figures."""
    metrics = calculate_soc_metrics(SEEDED_INCIDENTS, [], SYNTHETIC_ATTACK_VECTORS)

    # Donut chart
    donut = build_severity_donut_chart(metrics)
    assert donut is not None
    assert len(donut.data) > 0

    # Bar chart
    bar = build_attack_vectors_bar_chart(SYNTHETIC_ATTACK_VECTORS)
    assert bar is not None
    assert len(bar.data) > 0

    # Threat map
    threat_map = build_global_threat_map(SYNTHETIC_GEO_POINTS, category_filter="ALL")
    assert threat_map is not None
    assert len(threat_map.data) > 0

    # Entity graph
    entity_graph = build_entity_relationship_graph(SEEDED_INCIDENTS[0], SCENARIO_1_EVENTS)
    assert entity_graph is not None
    assert len(entity_graph.data) >= 2  # edge trace + node trace
