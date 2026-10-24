"""Analytics and Plotly Visualization Engine for SentinelFlow AI.

Produces metrics and interactive Plotly visualizations in a futuristic SOC dark theme.
All metrics are derived from real session data and seeded synthetic telemetry.
"""

from typing import List, Dict, Any, Optional
import math
import plotly.graph_objects as go

from sentinelflow.config import (
    COLOR_BG_DARK,
    COLOR_PANEL_BG,
    COLOR_PANEL_BORDER,
    COLOR_ACCENT_CYAN,
    COLOR_ACCENT_BLUE,
    COLOR_CRITICAL,
    COLOR_HIGH,
    COLOR_MEDIUM,
    COLOR_LOW,
    COLOR_INFO,
    COLOR_SUCCESS,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY,
)
from sentinelflow.models import Incident, SecurityEvent, AuditEntry


def calculate_soc_metrics(
    incidents: List[Incident],
    audit_entries: List[AuditEntry],
    attack_vectors: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compute SOC operational metrics from active application state."""
    total_incidents = len(incidents)
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
    status_counts = {}

    investigated_count = 0
    durations = []
    approvals_count = 0
    rejections_count = 0
    verifications_passed = 0
    verifications_failed = 0
    gemini_calls = 0
    deterministic_fallbacks = 0

    for inc in incidents:
        sev = inc.severity.upper()
        if sev in severity_counts:
            severity_counts[sev] += 1
        status_counts[inc.status] = status_counts.get(inc.status, 0) + 1

        if inc.finding is not None:
            investigated_count += 1
            if inc.finding.analysis_mode == "gemini_ai":
                gemini_calls += 1
            else:
                deterministic_fallbacks += 1

        if inc.proposed_action is not None:
            if inc.proposed_action.status in ("approved", "executed_simulation", "verified"):
                approvals_count += 1
            elif inc.proposed_action.status == "rejected":
                rejections_count += 1

        if inc.verification_result is not None:
            if inc.verification_result.passed:
                verifications_passed += 1
            else:
                verifications_failed += 1

    total_verifications = verifications_passed + verifications_failed
    verification_success_rate = (
        round((verifications_passed / total_verifications) * 100, 1) if total_verifications > 0 else 100.0
    )

    return {
        "total_incidents": total_incidents,
        "investigated_count": investigated_count,
        "severity_counts": severity_counts,
        "status_counts": status_counts,
        "critical_count": severity_counts["CRITICAL"],
        "high_count": severity_counts["HIGH"],
        "medium_count": severity_counts["MEDIUM"],
        "low_count": severity_counts["LOW"] + severity_counts["INFORMATIONAL"],
        "approvals_count": approvals_count,
        "rejections_count": rejections_count,
        "verifications_passed": verifications_passed,
        "verifications_failed": verifications_failed,
        "verification_success_rate": verification_success_rate,
        "gemini_calls": gemini_calls,
        "deterministic_fallbacks": deterministic_fallbacks,
        "attack_vectors": attack_vectors,
    }


def build_severity_donut_chart(metrics: Dict[str, Any]) -> go.Figure:
    """Build a donut chart showing severity distribution."""
    sev = metrics["severity_counts"]
    labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    values = [sev.get(k, 0) for k in labels]
    colors = [COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW, COLOR_INFO]

    # Filter out 0 values for clean rendering
    filtered = [(l, v, c) for l, v, c in zip(labels, values, colors) if v > 0]
    if not filtered:
        filtered = [("NO INCIDENTS", 1, COLOR_INFO)]

    f_labels, f_values, f_colors = zip(*filtered)

    fig = go.Figure(
        data=[
            go.Pie(
                labels=f_labels,
                values=f_values,
                hole=0.68,
                marker=dict(colors=f_colors, line=dict(color=COLOR_PANEL_BG, width=2)),
                textinfo="label+value",
                textfont=dict(size=12, color=COLOR_TEXT_PRIMARY),
                hoverinfo="label+value+percent",
            )
        ]
    )

    fig.update_layout(
        autosize=True,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=10, r=10, t=10, b=10),
        height=240,
        showlegend=False,
        annotations=[
            dict(
                text=f"<b>{metrics['total_incidents']}</b><br><span style='font-size:10px; color:{COLOR_TEXT_SECONDARY}'>TOTAL</span>",
                x=0.5,
                y=0.5,
                font=dict(size=20, color=COLOR_ACCENT_CYAN),
                showarrow=False,
            )
        ],
    )
    return fig


def build_attack_vectors_bar_chart(attack_vectors: List[Dict[str, Any]]) -> go.Figure:
    """Build horizontal bar chart for top attack vectors."""
    vectors = list(reversed(attack_vectors))
    labels = [v["vector"] for v in vectors]
    counts = [v["count"] for v in vectors]

    fig = go.Figure(
        data=[
            go.Bar(
                x=counts,
                y=labels,
                orientation="h",
                marker=dict(
                    color=COLOR_ACCENT_CYAN,
                    line=dict(color=COLOR_ACCENT_BLUE, width=1),
                ),
                text=[f" {c}" for c in counts],
                textposition="auto",
                textfont=dict(color=COLOR_TEXT_PRIMARY, size=11),
            )
        ]
    )

    fig.update_layout(
        autosize=True,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=10, r=10, t=10, b=10),
        height=250,
        xaxis=dict(
            showgrid=True,
            gridcolor=COLOR_PANEL_BORDER,
            tickfont=dict(color=COLOR_TEXT_SECONDARY, size=10),
            title=None,
        ),
        yaxis=dict(
            tickfont=dict(color=COLOR_TEXT_PRIMARY, size=11),
            autorange=True,
        ),
    )
    return fig


def build_global_threat_map(geo_points: List[Dict[str, Any]], category_filter: str = "ALL") -> go.Figure:
    """Build global synthetic threat map with attack arcs and pulsed geo-origins."""
    filtered_points = geo_points
    if category_filter and category_filter != "ALL":
        filtered_points = [p for p in geo_points if p.get("category") == category_filter]

    fig = go.Figure()

    # Draw simulated attack trajectory lines
    for p in filtered_points:
        fig.add_trace(
            go.Scattergeo(
                lon=[p["lon"], p["target_lon"]],
                lat=[p["lat"], p["target_lat"]],
                mode="lines",
                line=dict(
                    width=2,
                    color=COLOR_CRITICAL if p["severity"] == "CRITICAL" else COLOR_ACCENT_CYAN,
                    dash="dot",
                ),
                hoverinfo="none",
                showlegend=False,
            )
        )

    # Origin markers
    if filtered_points:
        origin_lons = [p["lon"] for p in filtered_points]
        origin_lats = [p["lat"] for p in filtered_points]
        origin_texts = [
            f"<b>{p['origin_name']}</b><br>IP: {p['source_ip']}<br>Vector: {p['attack_vector']}<br>Severity: {p['severity']}"
            for p in filtered_points
        ]
        origin_colors = [
            COLOR_CRITICAL if p["severity"] == "CRITICAL" else (COLOR_HIGH if p["severity"] == "HIGH" else COLOR_MEDIUM)
            for p in filtered_points
        ]

        fig.add_trace(
            go.Scattergeo(
                lon=origin_lons,
                lat=origin_lats,
                mode="markers+text",
                marker=dict(
                    size=12,
                    color=origin_colors,
                    line=dict(width=2, color="#ffffff"),
                    symbol="circle",
                ),
                text=[p["category"][:4] for p in filtered_points],
                textposition="top center",
                textfont=dict(color=COLOR_TEXT_PRIMARY, size=9),
                hovertext=origin_texts,
                hoverinfo="text",
                name="Synthetic Attack Origins",
            )
        )

        # Target markers
        target_lons = [p["target_lon"] for p in filtered_points]
        target_lats = [p["target_lat"] for p in filtered_points]
        target_texts = [f"<b>Target: {p['target_name']}</b>" for p in filtered_points]

        fig.add_trace(
            go.Scattergeo(
                lon=target_lons,
                lat=target_lats,
                mode="markers",
                marker=dict(
                    size=14,
                    color=COLOR_ACCENT_CYAN,
                    symbol="diamond",
                    line=dict(width=2, color=COLOR_ACCENT_BLUE),
                ),
                hovertext=target_texts,
                hoverinfo="text",
                name="Monitored SOC Targets",
            )
        )

    fig.update_layout(
        autosize=True,
        paper_bgcolor=COLOR_BG_DARK,
        plot_bgcolor=COLOR_BG_DARK,
        margin=dict(l=0, r=0, t=10, b=10),
        height=380,
        showlegend=True,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
            font=dict(color=COLOR_TEXT_SECONDARY, size=10),
        ),
        geo=dict(
            scope="world",
            projection_type="natural earth",
            showland=True,
            landcolor="#111827",
            showocean=True,
            oceancolor="#070b12",
            showcountries=True,
            countrycolor="#1e293b",
            countrywidth=0.8,
            coastlinecolor="#1e293b",
            lakecolor="#070b12",
            bgcolor=COLOR_BG_DARK,
        ),
    )
    return fig


def build_entity_relationship_graph(incident: Incident, events: List[SecurityEvent]) -> go.Figure:
    """Build interactive 2D node-link graph of entities in the selected incident."""
    primary_node = incident.primary_account
    nodes = {primary_node: {"type": "account", "label": f"Account:\n{primary_node}"}}

    # Add entity nodes
    for ent in incident.correlated_entities:
        ent_type = "session" if ent.startswith("sess-") else ("host" if "host" in ent or "workstation" in ent else "resource")
        nodes[ent] = {"type": ent_type, "label": f"{ent_type.upper()}:\n{ent}"}

    # Add event nodes
    for ev in events:
        nodes[ev.event_id] = {"type": "event", "label": f"{ev.event_id}\n{ev.severity}"}

    # Generate layout positions in circle or radial ring around center account
    node_list = list(nodes.keys())
    node_positions = {}
    node_positions[primary_node] = (0.0, 0.0)

    other_nodes = [n for n in node_list if n != primary_node]
    n_others = len(other_nodes)
    for idx, node in enumerate(other_nodes):
        angle = (2 * math.pi * idx) / max(1, n_others)
        radius = 1.0 if nodes[node]["type"] == "event" else 1.8
        node_positions[node] = (radius * math.cos(angle), radius * math.sin(angle))

    # Build edges
    edge_x = []
    edge_y = []

    # Edges from account to events
    for ev in events:
        p0 = node_positions[primary_node]
        p1 = node_positions[ev.event_id]
        edge_x.extend([p0[0], p1[0], None])
        edge_y.extend([p0[1], p1[1], None])

        # Edges from events to related entities
        for ent in ev.related_entity_ids:
            if ent in node_positions:
                p2 = node_positions[ent]
                edge_x.extend([p1[0], p2[0], None])
                edge_y.extend([p1[1], p2[1], None])

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        line=dict(width=1.2, color="#334155"),
        hoverinfo="none",
        mode="lines",
    )

    # Build node scatter traces by type
    node_x = [node_positions[n][0] for n in node_list]
    node_y = [node_positions[n][1] for n in node_list]
    node_texts = [nodes[n]["label"] for n in node_list]

    color_map = {
        "account": COLOR_ACCENT_CYAN,
        "event": COLOR_CRITICAL if incident.severity == "CRITICAL" else COLOR_HIGH,
        "session": COLOR_MEDIUM,
        "host": COLOR_LOW,
        "resource": COLOR_SUCCESS,
    }
    node_colors = [color_map.get(nodes[n]["type"], COLOR_INFO) for n in node_list]
    node_sizes = [28 if nodes[n]["type"] == "account" else 20 for n in node_list]

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers+text",
        text=[n if len(n) < 14 else n[:12] + ".." for n in node_list],
        textposition="bottom center",
        textfont=dict(size=10, color=COLOR_TEXT_PRIMARY),
        hovertext=node_texts,
        hoverinfo="text",
        marker=dict(
            size=node_sizes,
            color=node_colors,
            line=dict(width=2, color=COLOR_PANEL_BG),
        ),
    )

    fig = go.Figure(data=[edge_trace, node_trace])
    fig.update_layout(
        autosize=True,
        paper_bgcolor=COLOR_PANEL_BG,
        plot_bgcolor=COLOR_PANEL_BG,
        showlegend=False,
        hovermode="closest",
        margin=dict(b=20, l=20, r=20, t=20),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        height=300,
    )
    return fig
