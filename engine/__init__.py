"""BT3 core engine: Snort rule loading, indexing and matching.

Pipeline position: after the FlowTracker. The engine only reads event dicts
and flow context; it never imports Scapy and never touches raw packets.
"""
