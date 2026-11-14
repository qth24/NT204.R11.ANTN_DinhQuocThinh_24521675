"""Rule parser and validator: one rule line -> ``ParseResult``.

Rule line layout (Snort 2 style)::

    action proto src_ip src_port dir dst_ip dst_port ( key:value; key; ... )

Decision order for every rule (see ``parse_rule``):
    1. syntax broken            -> status ``invalid``
    2. syntax fine, out of scope -> status ``unsupported``
    3. otherwise                -> status ``valid`` (a ``Rule`` object)

Problems are reported with stable reason codes, e.g.
``invalid:missing_sid``, ``invalid:bad_port_range:80:20``,
``unsupported:keyword:pcre``, ``unsupported:protocol:icmp``.

Only the standard library is used (``ipaddress`` for CIDR); the options
tokenizer is hand written because Snort strings have their own escaping.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from engine.rule_model import PortRange, RuleHeader


class RuleError(Exception):
    """Internal: a rule problem with its final ``status`` and reason ``code``."""

    def __init__(self, status: str, code: str) -> None:
        super().__init__(code)
        self.status = status
        self.code = code


def invalid(code: str) -> RuleError:
    return RuleError("invalid", f"invalid:{code}")


def unsupported(code: str) -> RuleError:
    return RuleError("unsupported", f"unsupported:{code}")


# --- rule split -------------------------------------------------------------

_ACTIONS_OUT_OF_SCOPE = frozenset(
    {"drop", "sdrop", "reject", "pass", "log", "activate", "dynamic", "block"}
)
_IDENT = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


def split_rule(line: str) -> tuple[str, str]:
    """Split a rule line into (header text, options text without parentheses)."""
    text = line.strip()
    start = text.find("(")
    if start < 0:
        raise invalid("missing_options")
    if not text.endswith(")"):
        raise invalid("unbalanced_parentheses")
    return text[:start].strip(), text[start + 1 : -1]


# --- header -----------------------------------------------------------------


def parse_header(text: str) -> tuple[str, RuleHeader]:
    """Parse ``action proto src_ip src_port dir dst_ip dst_port``.

    Returns (action, RuleHeader). Raises RuleError.
    """
    parts = text.split()
    if len(parts) != 7:
        raise invalid(f"bad_header_fields:{len(parts)}")
    action, proto, src_ip, src_port, direction, dst_ip, dst_port = parts

    action = action.lower()
    if action != "alert":
        if action in _ACTIONS_OUT_OF_SCOPE:
            raise unsupported(f"action:{action}")
        raise invalid(f"unknown_action:{action}")

    proto = proto.lower()
    if proto not in ("tcp", "udp"):
        if _IDENT.match(proto):
            raise unsupported(f"protocol:{proto}")  # ip, icmp, http ...
        raise invalid(f"bad_protocol:{proto}")

    if direction == "<-":
        raise invalid("bad_direction:<-")  # Snort 2 has no reversed arrow
    if direction not in ("->", "<>"):
        raise invalid(f"bad_direction:{direction}")

    header = RuleHeader(
        proto=proto.upper(),
        src_nets=parse_nets(src_ip),
        src_ports=parse_ports(src_port),
        direction=direction,
        dst_nets=parse_nets(dst_ip),
        dst_ports=parse_ports(dst_port),
    )
    return action, header


def parse_nets(text: str) -> tuple[ipaddress.IPv4Network, ...]:
    """``any`` -> (); ``1.2.3.4`` or ``10.0.0.0/8`` -> one network."""
    if text.lower() == "any":
        return ()
    if text[0] in "![$":
        # negation, [list] and $VARIABLE are outside the required scope
        raise unsupported(f"ip_syntax:{text}")
    try:
        # strict=False: 10.1.2.3/8 is accepted and means 10.0.0.0/8
        net = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise invalid(f"bad_ip:{text}") from exc
    if not isinstance(net, ipaddress.IPv4Network):
        raise unsupported(f"ipv6:{text}")
    return (net,)


def parse_ports(text: str) -> tuple[PortRange, ...]:
    """``any``, ``80``, ``1:1024``, ``:1024`` (0..1024), ``1024:`` (1024..65535)."""
    if text.lower() == "any":
        return ()
    if text[0] in "![$":
        raise unsupported(f"port_syntax:{text}")
    low_text, colon, high_text = text.partition(":")
    try:
        if not colon:
            low = high = _port(low_text)
        else:
            low = _port(low_text) if low_text else 0
            high = _port(high_text) if high_text else 65535
    except ValueError as exc:
        raise invalid(f"bad_port:{text}") from exc
    if low > high:
        raise invalid(f"bad_port_range:{low}:{high}")
    return (PortRange(low, high),)


def _port(text: str) -> int:
    if not text.isdigit():
        raise ValueError(text)
    value = int(text)
    if value > 65535:
        raise ValueError(text)
    return value


# --- options tokenizer ------------------------------------------------------


@dataclass(frozen=True)
class RawOption:
    """One ``key:value`` (or bare ``key``) option; ``value`` is still raw text
    (quotes and escapes are decoded later by the keyword parser)."""

    key: str
    value: str | None


def tokenize_options(text: str) -> list[RawOption]:
    """Split the text between ``( ... )`` into options.

    A small state machine instead of ``str.split(";")``, because a ``;`` must
    NOT end an option when it is
        * inside a quoted string  ``content:"a;b";``
        * escaped                 ``msg:foo\;bar;``
    State: ``in_quote`` flips on an unescaped ``"``; a backslash copies itself
    and the next character verbatim so ``\\"`` never closes a string.
    """
    options: list[RawOption] = []
    current: list[str] = []
    in_quote = False
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            current.append(text[index : index + 2])  # keep the escape as is
            index += 2
            continue
        if char == '"':
            in_quote = not in_quote
        if char == ";" and not in_quote:
            _flush(current, options)
            current = []
        else:
            current.append(char)
        index += 1
    if in_quote:
        raise invalid("unterminated_string")
    _flush(current, options)  # last option may omit the final ';'
    return options


def _flush(chars: list[str], options: list[RawOption]) -> None:
    item = "".join(chars).strip()
    if not item:
        return  # empty segment, e.g. ";;" or trailing ";"
    key, colon, value = item.partition(":")
    key = key.strip().lower()
    if not key or not re.fullmatch(r"[a-z0-9_.-]+", key):
        raise invalid(f"bad_option:{item[:30]}")
    options.append(RawOption(key, value.strip() if colon else None))
