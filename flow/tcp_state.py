"""TCP connection state machine (one instance per TCP flow).

States:
    NEW         first SYN (without ACK) seen from A, the initiator
    HANDSHAKE   SYN/ACK seen from B (2nd step of the 3-way handshake)
    ESTABLISHED ACK from A after the SYN/ACK (3rd step), or data in both
                directions (connection picked up mid-stream)
    CLOSING     FIN seen from one side
    CLOSED      FIN seen from both sides
    RESET       RST seen, from any state

    A: SYN ──► NEW ── B: SYN/ACK ──► HANDSHAKE ── A: ACK ──► ESTABLISHED
                                                              │ FIN (one side)
                                                              ▼
                       any state ── RST ──► RESET          CLOSING
                                                              │ FIN (other side)
                                                              ▼
                                                            CLOSED

Every packet goes through ``update`` - also pure ACKs without payload,
because handshake and teardown are made of such packets.
CLOSED is entered as soon as both FINs are seen; the last ACK usually
follows and is still counted because the tracker keeps CLOSED/RESET flows
for ``flow.closed_linger`` seconds before exporting them.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from flow.flow import BACKWARD, FORWARD

NEW = "NEW"
HANDSHAKE = "HANDSHAKE"
ESTABLISHED = "ESTABLISHED"
CLOSING = "CLOSING"
CLOSED = "CLOSED"
RESET = "RESET"
TERMINAL_STATES = frozenset({CLOSED, RESET})


def is_connection_start(tcp_flags: list[str]) -> bool:
    """A SYN without ACK opens a new connection (1st handshake step)."""
    return "SYN" in tcp_flags and "ACK" not in tcp_flags


@dataclass
class TcpStateMachine:
    """State of one TCP flow; ``midstream`` is True when no SYN was seen."""

    state: str
    midstream: bool = False
    fin_from: set[str] = field(default_factory=set)
    data_from: set[str] = field(default_factory=set)

    @classmethod
    def start(cls, first_flags: list[str]) -> TcpStateMachine:
        """Initial state from the first packet of the flow (sent by A)."""
        if is_connection_start(first_flags):
            return cls(NEW)
        # Capture started in the middle of a connection: we never saw the
        # handshake, so we assume the connection is already established.
        return cls(ESTABLISHED, midstream=True)

    def update(self, direction: str, tcp_flags: list[str], payload_length: int) -> str:
        """Apply one packet (``direction`` relative to A) and return the new state."""
        # RST aborts the connection immediately, whatever the current state.
        if "RST" in tcp_flags:
            self.state = RESET
            return self.state
        # CLOSED/RESET never change here; a new SYN on the same 5-tuple is a
        # new connection and is handled by the tracker (new flow, seq + 1).
        if self.state in TERMINAL_STATES:
            return self.state

        syn, ack = "SYN" in tcp_flags, "ACK" in tcp_flags
        if payload_length > 0:
            self.data_from.add(direction)
        if "FIN" in tcp_flags:
            self.fin_from.add(direction)

        if self.state == NEW and syn and ack and direction == BACKWARD:
            # Step 2: B answers A's SYN with SYN/ACK.
            self.state = HANDSHAKE
        elif self.state == HANDSHAKE and ack and not syn and direction == FORWARD:
            # Step 3: A acknowledges the SYN/ACK -> handshake complete.
            self.state = ESTABLISHED

        if self.state in (NEW, HANDSHAKE) and self.data_from == {FORWARD, BACKWARD}:
            # Data flows both ways although we missed part of the handshake.
            self.state = ESTABLISHED

        if self.fin_from:
            # One FIN = half-closed (CLOSING); FIN from both sides = CLOSED.
            self.state = CLOSED if self.fin_from == {FORWARD, BACKWARD} else CLOSING
        return self.state
