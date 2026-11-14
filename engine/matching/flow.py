"""Flow matcher: ``flow:to_server|to_client`` and ``established|not_established``.

Works only on the flow context given by the FlowTracker (state of the flow
right after the current packet was counted); it never re-derives anything
from the packet itself. A rule with a ``flow`` option never matches a packet
that has no flow context.

Definitions (also in README):
    to_server    <=> direction == "forward"  (sent by the initiator A)
    to_client    <=> direction == "backward"
    established  TCP: state is ESTABLISHED or CLOSING (a FIN was seen from one
                 side only, data may still flow = half-closed).
                 NEW / HANDSHAKE / CLOSED / RESET are NOT established.
                 UDP: no state machine, so established <=> at least one packet
                 of the reverse direction was already seen (a reply).
    not_established  exactly the negation of established.
"""

from __future__ import annotations

from typing import Any

from engine.rule_model import Rule

_TCP_ESTABLISHED = frozenset({"ESTABLISHED", "CLOSING"})


def is_established(ctx: dict[str, Any]) -> bool:
    if ctx.get("protocol") == "TCP":
        return ctx.get("state") in _TCP_ESTABLISHED
    # UDP: a reply (backward packet) has been seen in this flow.
    return int(ctx.get("bwd_packet_count") or 0) >= 1


def match_flow(rule: Rule, flow_ctx: dict[str, Any] | None) -> str | None:
    """Return None when the flow conditions hold, else the reason."""
    option = rule.flow
    if option is None:
        return None  # rule has no flow condition
    if not flow_ctx or not flow_ctx.get("flow_id"):
        return "flow:no_context"
    if option.direction is not None:
        wanted = "forward" if option.direction == "to_server" else "backward"
        if flow_ctx.get("direction") != wanted:
            return f"flow:{option.direction}"
    if option.state is not None:
        established = is_established(flow_ctx)
        if established != (option.state == "established"):
            return f"flow:{option.state}"
    return None
