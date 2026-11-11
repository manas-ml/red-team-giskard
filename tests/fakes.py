"""Scripted stand-in for anthropic.AsyncAnthropic used by offline tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any


def text_response(text: str) -> SimpleNamespace:
    return SimpleNamespace(stop_reason="end_turn",
                           content=[SimpleNamespace(type="text", text=text)])


def tool_response(account_id: str, tool_id: str = "toolu_1") -> SimpleNamespace:
    return SimpleNamespace(
        stop_reason="tool_use",
        content=[SimpleNamespace(type="tool_use", id=tool_id, name="get_account_balance",
                                 input={"account_id": account_id})],
    )


def refusal_response() -> SimpleNamespace:
    return SimpleNamespace(stop_reason="refusal", content=[])


@dataclass
class FakeMessages:
    script: list[SimpleNamespace]
    calls: list[dict[str, Any]] = field(default_factory=list)

    async def create(self, **kwargs: Any) -> SimpleNamespace:
        # Snapshot messages: the agent mutates the list after each call.
        self.calls.append({**kwargs, "messages": list(kwargs["messages"])})
        return self.script.pop(0)


class FakeAnthropic:
    def __init__(self, *responses: SimpleNamespace) -> None:
        self.messages = FakeMessages(list(responses))
