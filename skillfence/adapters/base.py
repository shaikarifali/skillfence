"""Agent adapter interface.

The correlation/policy/risk/HITL core must not depend on any specific agent
ecosystem. An adapter's job is to normalize that ecosystem's tool-call
lifecycle into calls against a RuntimeGateway. Only one adapter (the
reference agent) ships today; this ABC is what a future Claude
Code / Codex / Cursor adapter would implement.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class AgentAdapter(ABC):
    @abstractmethod
    def on_skill_loaded(self, skill: str) -> None: ...

    @abstractmethod
    def on_tool_requested(self, tool: str, args: dict[str, Any]) -> None: ...

    @abstractmethod
    def before_tool_execution(self, tool: str, args: dict[str, Any]) -> None: ...

    @abstractmethod
    def after_tool_execution(self, tool: str, result: Any) -> None: ...

    @abstractmethod
    def get_active_skill(self) -> str: ...

    @abstractmethod
    def get_instruction_provenance(self) -> list[str]: ...
