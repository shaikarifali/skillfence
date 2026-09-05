"""Agent Action Provenance Graph.

Answers "why did the agent do this?" by chaining events through their
`parent_event` links back to the prompt/skill root, e.g.:

    prompt -> skill -> external-content -> instruction -> tool-call -> OS-action
"""

from __future__ import annotations

from dataclasses import dataclass

from skillfence.events.schema import Event


@dataclass
class ProvenanceNode:
    event: Event

    @property
    def label(self) -> str:
        kind = self.event.event_type.value
        if self.event.resource:
            return f"{kind} ({self.event.resource})"
        return kind


class ProvenanceGraph:
    def __init__(self, events: list[Event]) -> None:
        self._by_id = {e.event_id: e for e in events}

    def chain_to_root(self, event_id: str) -> list[ProvenanceNode]:
        """Walk parent_event links back to the root, return root-first."""
        chain: list[ProvenanceNode] = []
        seen: set[str] = set()
        current = self._by_id.get(event_id)
        while current is not None and current.event_id not in seen:
            seen.add(current.event_id)
            chain.append(ProvenanceNode(event=current))
            current = self._by_id.get(current.parent_event) if current.parent_event else None
        chain.reverse()
        return chain

    def render_ascii(self, event_id: str) -> str:
        chain = self.chain_to_root(event_id)
        return "\n  -> ".join(node.label for node in chain)
