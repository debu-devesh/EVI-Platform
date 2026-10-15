#!/usr/bin/env python3
"""
Per-LLM-turn evidence boundary contract. One resolver (compute_evidence_scope) drives
what may enter get_relevant_data_for_llm — avoids whole-case priming on slice queries.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from core.query_intent_parser import parse_query_intent


_WIDENING = re.compile(
    r"\b(compare|correlat|cross[-\s]?reference|overlap\b|across|between\b|"
    r"cross[-\s]?platform|whole\s+case|entire\s+case|full\s+case|overall\b|"
    r"all\s+platforms|every\s+platform)\b",
    re.I,
)

_OVERVIEW_HINTS = (
    "what platforms",
    "which platforms",
    "list platforms",
    "show platforms",
    "platform breakdown",
    "platform classification",
    "classify platforms",
    "messaging apps",
    "what apps",
    "which apps",
    "how many chats",
    "chat apps",
    "case overview",
    "overview of",
    "summarize the case",
    "summary of the case",
    "everything on this device",
    "whole dataset",
    # Inventory / "what's in the load" — must get include_global_preamble so DAL emits === DATA AVAILABILITY ===
    "what data is available",
    "what data exists",
    "what data was extracted",
    "what data is in",
    "what is in this extraction",
    "what's in this extraction",
    "what does this extraction",
    "available in this extraction",
    "types of data",
    "data types",
)


@dataclass(frozen=True)
class EvidenceScope:
    """Evidence boundary for one LLM call (not conversation typing — use query_route for that)."""

    mode: str  # case_overview | domain_isolated | platform_isolated | cross_domain_scoped
    domains: Tuple[str, ...] = ()
    platforms: Tuple[str, ...] = ()
    include_global_preamble: bool = False
    is_followup: bool = False

    def allows_domain(self, domain: str) -> bool:
        if self.mode == "case_overview":
            return True
        eff = self.effective_domains()
        if not eff:
            return True
        return domain in eff

    def effective_domains(self) -> FrozenSet[str]:
        d = set(self.domains)
        if self.mode == "platform_isolated" and not d:
            d.update({"messages", "chats"})
        return frozenset(d)

    def scope_header_line(
        self,
        *,
        sufficient_for_analysis: bool,
        evidence_rows: int,
    ) -> str:
        gs = "included" if self.include_global_preamble else "excluded"
        eff = self.effective_domains()
        if eff:
            dom = ",".join(sorted(eff))
        elif self.domains:
            dom = ",".join(self.domains)
        else:
            dom = "*"
        plat = ",".join(self.platforms) if self.platforms else "-"
        suf = "true" if sufficient_for_analysis else "false"
        return (
            f"EVIDENCE_SCOPE: mode={self.mode}; domains={dom}; platforms={plat}; "
            f"global_stats={gs}; sufficient_for_analysis={suf}; evidence_rows={evidence_rows}"
        )


def _q_lower(q: str) -> str:
    return (q or "").strip().lower()


def _has_widening(q: str) -> bool:
    return bool(_WIDENING.search(_q_lower(q)))


def _has_overview_hint(q: str) -> bool:
    low = _q_lower(q)
    return any(h in low for h in _OVERVIEW_HINTS)


def _comprehensive_without_platform(q: str, platforms: List[str]) -> bool:
    low = _q_lower(q)
    if platforms:
        return False
    return any(
        w in low
        for w in (
            " entire ",
            " whole case",
            " full case",
            " all messages",
            " all chats",
            " all calls",
            " everything ",
            " list all",
            " show all",
            "every message",
            "complete dump",
        )
    )


def compute_evidence_scope(
    query: str,
    parsed_intent: Optional[Dict[str, Any]] = None,
    query_route: Optional[Dict[str, Any]] = None,
) -> EvidenceScope:
    """
    Single place to decide evidence boundaries. Prefer isolated scope when ambiguous.
    """
    if not parsed_intent:
        parsed_intent = parse_query_intent(query or "")

    domains = tuple(dict.fromkeys(parsed_intent.get("domains") or []))
    platforms = tuple(dict.fromkeys(parsed_intent.get("platforms") or []))

    is_followup = False
    if query_route:
        guar = query_route.get("guarantee_class") or ""
        primary = query_route.get("primary") or ""
        is_followup = "followup" in str(primary).lower() or "followup" in str(guar).lower()

    widening = _has_widening(query or "")
    overview_hint = _has_overview_hint(query or "")
    comp_no_plat = _comprehensive_without_platform(query or "", list(platforms))

    if overview_hint or (comp_no_plat and not platforms):
        return EvidenceScope(
            mode="case_overview",
            domains=domains,
            platforms=platforms,
            include_global_preamble=True,
            is_followup=is_followup,
        )

    if widening or len(domains) > 1 or len(platforms) > 1:
        return EvidenceScope(
            mode="cross_domain_scoped",
            domains=domains,
            platforms=platforms,
            include_global_preamble=False,
            is_followup=is_followup,
        )

    if len(platforms) == 1:
        dom = domains
        if not dom:
            dom = ("messages", "chats")
        return EvidenceScope(
            mode="platform_isolated",
            domains=dom,
            platforms=platforms,
            include_global_preamble=False,
            is_followup=is_followup,
        )

    if len(domains) == 1:
        return EvidenceScope(
            mode="domain_isolated",
            domains=domains,
            platforms=platforms,
            include_global_preamble=False,
            is_followup=is_followup,
        )

    if domains:
        return EvidenceScope(
            mode="cross_domain_scoped",
            domains=domains,
            platforms=platforms,
            include_global_preamble=False,
            is_followup=is_followup,
        )

    # Ambiguous — prefer tighter packet (no global preamble); rely on intent-driven sections
    return EvidenceScope(
        mode="cross_domain_scoped",
        domains=tuple(),
        platforms=tuple(),
        include_global_preamble=False,
        is_followup=is_followup,
    )


def assess_evidence_sufficiency(text: str, *, min_rows: int = 5, min_chars: int = 400) -> Tuple[bool, int]:
    """Heuristic: enough surface for analysis vs thin slice."""
    lines = [ln for ln in (text or "").splitlines() if ln.strip()]
    # Lines that look like forensic rows (not headers-only)
    substantive = 0
    for ln in lines:
        s = ln.strip()
        if s.startswith("==="):
            continue
        if len(s) < 12:
            continue
        substantive += 1
    ok = substantive >= min_rows or len(text or "") >= min_chars
    return ok, substantive
