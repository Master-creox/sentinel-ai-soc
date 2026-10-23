"""Incident report generation (Markdown)."""

from __future__ import annotations


def build_report(state: dict, evaluation: dict) -> str:
    lines = [
        "# SentinelAI - Incident Report",
        "",
        f"- Simulated time: {state['time']}s",
        f"- Events processed: {state['total_events']}",
        f"- Open incidents: {state['open_incidents']}",
        f"- Blocked sources: {len(state['blocked'])}",
        "",
        "## Incidents",
        "",
    ]
    if not state["incidents"]:
        lines.append("No incidents recorded.")
    for inc in state["incidents"]:
        lines.append(f"- #{inc['id']} **{inc['attack_type']}** from {inc['target']} - "
                     f"peak risk {inc['peak_score']:.0f}, status: {inc['status']}")
    lines += ["", "## Autonomous actions", ""]
    if not state["actions"]:
        lines.append("No actions taken.")
    for act in state["actions"]:
        lines.append(f"- `{act['action']}` {act['target']} - {act['explanation']}")
    lines += ["", "## Detection benchmark (vs simulator ground truth)", "",
              f"- Attacking IPs: {evaluation['attacking_ips']}",
              f"- Detected: {evaluation['detected_attacking_ips']}",
              f"- IP recall: {evaluation['ip_recall']:.1%}",
              f"- IP precision: {evaluation['ip_precision']:.1%}",
              "", "_SentinelAI is a defensive security research/education project. "
              "All traffic is simulated; all responses are simulated._"]
    return "\n".join(lines) + "\n"
