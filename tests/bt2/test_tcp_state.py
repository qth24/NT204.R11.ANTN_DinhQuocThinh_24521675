"""Unit tests for flow.tcp_state (TCP state machine)."""

from __future__ import annotations

from flow.flow import BACKWARD, FORWARD
from flow.tcp_state import (
    CLOSED,
    CLOSING,
    ESTABLISHED,
    HANDSHAKE,
    NEW,
    RESET,
    TcpStateMachine,
    is_connection_start,
)


def _run(packets: list[tuple[str, list[str], int]]) -> list[str]:
    machine = TcpStateMachine.start(packets[0][1])
    return [
        machine.update(direction, flags, size) for direction, flags, size in packets
    ]


def test_three_way_handshake() -> None:
    states = _run(
        [
            (FORWARD, ["SYN"], 0),
            (BACKWARD, ["SYN", "ACK"], 0),
            (FORWARD, ["ACK"], 0),
        ]
    )
    assert states == [NEW, HANDSHAKE, ESTABLISHED]


def test_full_close_with_fin_from_both_sides() -> None:
    states = _run(
        [
            (FORWARD, ["SYN"], 0),
            (BACKWARD, ["SYN", "ACK"], 0),
            (FORWARD, ["ACK"], 0),
            (FORWARD, ["PSH", "ACK"], 100),
            (BACKWARD, ["ACK"], 0),
            (FORWARD, ["FIN", "ACK"], 0),
            (BACKWARD, ["ACK"], 0),
            (BACKWARD, ["FIN", "ACK"], 0),
            (FORWARD, ["ACK"], 0),
        ]
    )
    assert states[3:] == [
        ESTABLISHED,
        ESTABLISHED,
        CLOSING,
        CLOSING,
        CLOSED,
        CLOSED,  # last ACK does not change CLOSED
    ]


def test_rst_from_any_state() -> None:
    assert _run([(FORWARD, ["SYN"], 0), (BACKWARD, ["RST", "ACK"], 0)])[-1] == RESET
    machine = TcpStateMachine(CLOSING, fin_from={FORWARD})
    assert machine.update(BACKWARD, ["RST"], 0) == RESET


def test_retransmitted_syn_stays_new() -> None:
    assert _run([(FORWARD, ["SYN"], 0), (FORWARD, ["SYN"], 0)]) == [NEW, NEW]


def test_ack_from_wrong_side_does_not_establish() -> None:
    states = _run(
        [(FORWARD, ["SYN"], 0), (BACKWARD, ["SYN", "ACK"], 0), (BACKWARD, ["ACK"], 0)]
    )
    assert states[-1] == HANDSHAKE


def test_midstream_pickup() -> None:
    machine = TcpStateMachine.start(["PSH", "ACK"])
    assert (machine.state, machine.midstream) == (ESTABLISHED, True)
    assert machine.update(FORWARD, ["PSH", "ACK"], 50) == ESTABLISHED


def test_data_both_ways_establishes_after_missed_ack() -> None:
    states = _run(
        [
            (FORWARD, ["SYN"], 0),
            (BACKWARD, ["SYN", "ACK"], 0),
            (FORWARD, ["PSH", "ACK"], 10),  # 3rd step ACK missing, data instead
        ]
    )
    assert states[-1] == ESTABLISHED
    states = _run([(FORWARD, ["SYN"], 0), (FORWARD, [], 5), (BACKWARD, [], 5)])
    assert states[-1] == ESTABLISHED


def test_terminal_states_are_sticky() -> None:
    machine = TcpStateMachine(CLOSED, fin_from={FORWARD, BACKWARD})
    assert machine.update(FORWARD, ["ACK"], 0) == CLOSED
    assert machine.update(FORWARD, ["SYN"], 0) == CLOSED  # tracker opens a new flow


def test_is_connection_start() -> None:
    assert is_connection_start(["SYN"]) is True
    assert is_connection_start(["SYN", "ACK"]) is False
    assert is_connection_start(["ACK"]) is False
