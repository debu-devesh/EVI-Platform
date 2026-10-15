#!/usr/bin/env python3
"""
Follow-up mode (client `followup_mode`): the stream handler sets `followup_llm_only`
so deterministic database operations are skipped and the pipeline uses the LLM with
the selected base message as context.

`evaluate_followup_mode_policy` is retained for tests / tooling; it no longer blocks
queries — all follow-up questions are handled by the LLM path in `web_interface.py`.
"""

from __future__ import annotations

from typing import Any, Dict, Literal, Tuple

Decision = Literal["allowed", "blocked"]


def evaluate_followup_mode_policy(_user_query: str, _parsed_intent: Dict[str, Any]) -> Tuple[Decision, str]:
    """
    Legacy hook: previously used to block “data-style” questions in follow-up mode.
    Follow-up queries now always route to the LLM with base context.

    Returns:
        ("allowed", "")
    """
    return ("allowed", "")
