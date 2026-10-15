#!/usr/bin/env python3
"""
Natural Language UFDR Query Engine

Provides investigator-friendly NL query handling over UFDR JSON data and returns
strict JSON outputs. Uses lightweight rules with optional Hugging Face/OpenAI
models if available. Never fabricates data; only returns facts from UFDR.
"""

import os
import re
from datetime import datetime
import os
import json
import requests
from typing import Any, Dict, List, Optional, Tuple

try:
    from transformers import pipeline  # type: ignore
except Exception:
    pipeline = None  # Optional

try:
    import openai  # type: ignore
except Exception:
    openai = None  # Optional


SUSPICIOUS_MONEY_KEYWORDS = [
    "money", "transfer", "wire", "payment", "pay", "fee", "processing fee",
    "UPI", "bank", "account", "deposit", "withdraw", "wallet"
]

SUSPICIOUS_GENERIC_KEYWORDS = [
    "send package", "otp", "one time password", "pin", "password",
    "confidential", "credential", "delete", "erase"
]


class NaturalLanguageUFDR:
    """Minimal NL->forensic intent resolver and executor over UFDR data."""

    def __init__(self, ufdr_data: Dict[str, Dict[str, Any]]):
        self.ufdr_data = ufdr_data
        self.zero_shot = None
        self._init_optional_models()

    def _init_optional_models(self) -> None:
        # Optional HF zero-shot for intent classification.
        # Skip by default on flaky networks: set EVI_ENABLE_HF_ZERO_SHOT=1 to opt in.
        # Rule-based intent classification works without this model.
        skip_hf = os.getenv("EVI_SKIP_HF_MODELS", "").strip().lower() in ("1", "true", "yes")
        enable_hf = os.getenv("EVI_ENABLE_HF_ZERO_SHOT", "").strip().lower() in ("1", "true", "yes")
        if pipeline is not None and enable_hf and not skip_hf:
            try:
                # Prefer cached weights; avoid blocking startup on huggingface.co timeouts.
                local_only = os.getenv("EVI_HF_LOCAL_FILES_ONLY", "1").strip().lower() in (
                    "1", "true", "yes"
                )
                self.zero_shot = pipeline(
                    "zero-shot-classification",
                    model="facebook/bart-large-mnli",
                    local_files_only=local_only,
                )
            except Exception:
                self.zero_shot = None
        else:
            self.zero_shot = None

        # Optional OpenAI
        if openai is not None:
            api_key = os.getenv("OPENAI_API_KEY")
            if api_key:
                try:
                    openai.api_key = api_key
                except Exception:
                    pass

        # Optional LM Studio (Qwen 2.5 7B Instruct) over local HTTP API
        self.lm_studio_host = os.getenv("LM_STUDIO_HOST", "http://localhost:1234")
        self.lm_studio_model = os.getenv("LM_STUDIO_MODEL", "Qwen/Qwen2.5-7B-Instruct")

    def update_data(self, ufdr_data: Dict[str, Dict[str, Any]]) -> None:
        self.ufdr_data = ufdr_data

    # Public API
    def answer(self, query: str) -> Dict[str, Any]:
        query_norm = query.strip()
        if not query_norm:
            return {"error": "No query provided."}

        intent, params = self._classify_intent(query_norm)

        try:
            if intent == "suspicious_money_messages":
                return self._suspicious_money_messages(query_norm)
            if intent == "top_contacts":
                return self._top_contacts(query_norm, top_n=5)
            if intent == "files_external_email":
                return self._files_with_external_email(query_norm)
            if intent == "last_communication_between":
                a, b = params.get("party_a"), params.get("party_b")
                return self._last_comm_between(query_norm, a, b)
            if intent == "suspicious_generic":
                return self._suspicious_generic(query_norm)

            # Fallback generic handler: attempt keyword search in messages
            return self._generic_keyword_search(query_norm)
        except Exception:
            return {"error": "Internal error while answering query."}

    # Intent classification
    def _classify_intent(self, query: str) -> Tuple[str, Dict[str, Any]]:
        lowered = query.lower()

        # Simple rules first (fast path)
        if "money" in lowered or "transfer" in lowered or "payment" in lowered:
            if "message" in lowered or "chat" in lowered or "text" in lowered:
                return "suspicious_money_messages", {}

        if "top" in lowered and ("contact" in lowered or "number" in lowered):
            return "top_contacts", {}

        if ("file" in lowered or "document" in lowered) and ("email" in lowered or "external" in lowered):
            return "files_external_email", {}

        m = re.search(r"last\s+(?:spoke|talked|called|messaged)\s+(?:with|to)\s+([\w+@.\-\s]+)", lowered)
        if m:
            party_b = m.group(1).strip()
            party_a = None
            # Try detect insider/device owner later during execution
            return "last_communication_between", {"party_a": party_a, "party_b": party_b}

        # Generic suspicious
        if any(kw in lowered for kw in ["otp", "send package", "processing fee", "credential", "password"]):
            return "suspicious_generic", {}

        # Optional LM Studio (Llama 3.2) intent classification
        intent_from_lm_studio = self._lm_studio_classify_intent(query)
        if intent_from_lm_studio:
            return intent_from_lm_studio, {"party_a": None, "party_b": self._extract_party_b(query)} if intent_from_lm_studio == "last_communication_between" else {}

        # Optional zero-shot as a soft hint
        if self.zero_shot is not None:
            try:
                labels = [
                    "suspicious money messages",
                    "top contacts",
                    "files external email",
                    "last communication between two parties",
                ]
                zs = self.zero_shot(query, candidate_labels=labels)
                if zs and zs.get("labels"):
                    best = zs["labels"][0]
                    if "money" in best:
                        return "suspicious_money_messages", {}
                    if "top contacts" in best:
                        return "top_contacts", {}
                    if "external email" in best:
                        return "files_external_email", {}
                    if "between" in best:
                        return "last_communication_between", {"party_a": None, "party_b": self._extract_party_b(query)}
            except Exception:
                pass

        return "generic", {}

    # Executors
    def _suspicious_money_messages(self, query: str) -> Dict[str, Any]:
        matches: List[Dict[str, Any]] = []
        for fname, data in self.ufdr_data.items():
            for msg in data.get("messages", []):
                text = (msg.get("text") or msg.get("content") or "")
                if any(kw in text.lower() for kw in SUSPICIOUS_MONEY_KEYWORDS):
                    rec = {
                        "msg_id": msg.get("msg_id") or msg.get("message_id"),
                        "timestamp": msg.get("timestamp"),
                        "from": msg.get("from") or msg.get("sender"),
                        "to": msg.get("to") or msg.get("receiver"),
                        "text": text,
                        "source_file": fname
                    }
                    matches.append(rec)

        return {
            "query": query,
            "matches": matches,
            "summary": f"{len(matches)} suspicious messages mentioning money/transfer/payment found."
        } if matches else {"error": "No relevant evidence found in this UFDR."}

    def _top_contacts(self, query: str, top_n: int = 5) -> Dict[str, Any]:
        from collections import Counter
        counter = Counter()

        for _, data in self.ufdr_data.items():
            for call in data.get("call_logs", []):
                a = call.get("from"); b = call.get("to")
                if a: counter[a] += 1
                if b: counter[b] += 1
            for msg in data.get("messages", []):
                a = msg.get("from"); b = msg.get("to")
                if a: counter[a] += 1
                if b: counter[b] += 1

        most = counter.most_common(top_n)
        matches = [{"phone": k, "count": v} for k, v in most]
        return {
            "query": query,
            "matches": matches,
            "summary": f"Top {len(matches)} most contacted numbers computed."
        } if matches else {"error": "No relevant evidence found in this UFDR."}

    def _files_with_external_email(self, query: str) -> Dict[str, Any]:
        email_regex = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
        matches: List[Dict[str, Any]] = []

        for fname, data in self.ufdr_data.items():
            for f in data.get("files", []):
                context_fields = [
                    f.get("shared_with", ""), f.get("owner", ""), f.get("path", ""),
                    f.get("description", ""), f.get("filename", "")
                ]
                found_emails = []
                for field in context_fields:
                    if isinstance(field, str):
                        found_emails += email_regex.findall(field)
                    elif isinstance(field, list):
                        for item in field:
                            if isinstance(item, str):
                                found_emails += email_regex.findall(item)

                if found_emails:
                    matches.append({
                        "filename": f.get("filename"),
                        "timestamp": f.get("timestamp"),
                        "emails": sorted(list(set(found_emails))),
                        "source_file": fname
                    })

        return {
            "query": query,
            "matches": matches,
            "summary": f"{len(matches)} files appear associated with external email addresses."
        } if matches else {"error": "No relevant evidence found in this UFDR."}

    def _last_comm_between(self, query: str, party_a: Optional[str], party_b: Optional[str]) -> Dict[str, Any]:
        # Try to deduce device owner as party A if not provided
        owner_candidates = set()
        for _, data in self.ufdr_data.items():
            dev = data.get("device", {})
            if dev.get("phone_number"):
                owner_candidates.add(dev.get("phone_number"))
        owner = next(iter(owner_candidates)) if owner_candidates else None

        target = (party_b or "").strip()
        if not target:
            return {"error": "No relevant evidence found in this UFDR."}

        latest: Optional[Dict[str, Any]] = None

        def consider(ts: Optional[str], rec: Dict[str, Any]) -> None:
            nonlocal latest
            if not ts:
                return
            try:
                dt = datetime.fromisoformat(ts.replace("Z", ""))
            except Exception:
                return
            if latest is None:
                latest = {"dt": dt, **rec}
            else:
                if dt > latest["dt"]:
                    latest = {"dt": dt, **rec}

        # Scan messages and calls between owner and target (or any two parties if owner unknown)
        for fname, data in self.ufdr_data.items():
            for msg in data.get("messages", []):
                a = msg.get("from"); b = msg.get("to")
                if owner:
                    if (a == owner and (target in (b or ""))) or (b == owner and (target in (a or ""))):
                        consider(msg.get("timestamp"), {"type": "message", "from": a, "to": b, "text": msg.get("text"), "source_file": fname})
                else:
                    if target in (a or "") or target in (b or ""):
                        consider(msg.get("timestamp"), {"type": "message", "from": a, "to": b, "text": msg.get("text"), "source_file": fname})

            for call in data.get("call_logs", []):
                a = call.get("from"); b = call.get("to")
                if owner:
                    if (a == owner and (target in (b or ""))) or (b == owner and (target in (a or ""))):
                        consider(call.get("timestamp"), {"type": "call", "from": a, "to": b, "duration": call.get("duration") or call.get("duration_seconds"), "source_file": fname})
                else:
                    if target in (a or "") or target in (b or ""):
                        consider(call.get("timestamp"), {"type": "call", "from": a, "to": b, "duration": call.get("duration") or call.get("duration_seconds"), "source_file": fname})

        if latest is None:
            return {"error": "No relevant evidence found in this UFDR."}

        rec = latest.copy(); rec.pop("dt", None)
        return {
            "query": query,
            "matches": [rec],
            "summary": "Latest communication located between target and device owner." if owner else "Latest communication involving the target located."
        }

    def _suspicious_generic(self, query: str) -> Dict[str, Any]:
        keywords = SUSPICIOUS_GENERIC_KEYWORDS
        matches: List[Dict[str, Any]] = []
        for fname, data in self.ufdr_data.items():
            for msg in data.get("messages", []):
                text = (msg.get("text") or msg.get("content") or "")
                if any(kw in text.lower() for kw in keywords):
                    matches.append({
                        "msg_id": msg.get("msg_id") or msg.get("message_id"),
                        "timestamp": msg.get("timestamp"),
                        "from": msg.get("from") or msg.get("sender"),
                        "to": msg.get("to") or msg.get("receiver"),
                        "text": text,
                        "source_file": fname
                    })

        return {
            "query": query,
            "matches": matches,
            "summary": f"{len(matches)} messages matched suspicious keywords."
        } if matches else {"error": "No relevant evidence found in this UFDR."}

    def _generic_keyword_search(self, query: str) -> Dict[str, Any]:
        # Extract simple keyword(s)
        kws = [w for w in re.findall(r"\w+", query.lower()) if len(w) > 3]
        if not kws:
            return {"error": "No relevant evidence found in this UFDR."}

        matches: List[Dict[str, Any]] = []
        for fname, data in self.ufdr_data.items():
            for msg in data.get("messages", []):
                text = (msg.get("text") or msg.get("content") or "").lower()
                if all(kw in text for kw in set(kws[:3])):
                    matches.append({
                        "msg_id": msg.get("msg_id") or msg.get("message_id"),
                        "timestamp": msg.get("timestamp"),
                        "from": msg.get("from") or msg.get("sender"),
                        "to": msg.get("to") or msg.get("receiver"),
                        "text": msg.get("text") or msg.get("content"),
                        "source_file": fname
                    })

        return {
            "query": query,
            "matches": matches,
            "summary": f"{len(matches)} messages matched the query keywords."
        } if matches else {"error": "No relevant evidence found in this UFDR."}

    # Helpers
    def _lm_studio_classify_intent(self, query: str) -> Optional[str]:
        try:
            url = f"{self.lm_studio_host}/v1/chat/completions"
            system_prompt = (
                "You are a classifier for forensic queries. Given a query, respond with one of: "
                "suspicious_money_messages | top_contacts | files_external_email | last_communication_between. "
                "Respond with ONLY the label and nothing else."
            )
            body = {
                "model": self.lm_studio_model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Query: {query}\nLabel:"}
                ],
                "stream": False
            }
            resp = requests.post(url, json=body, timeout=3)
            if resp.status_code == 200:
                out = resp.json().get("choices", [{}])[0].get("message", {}).get("content", "").strip().lower()
                mapping = {
                    "suspicious_money_messages": "suspicious_money_messages",
                    "top_contacts": "top_contacts",
                    "files_external_email": "files_external_email",
                    "last_communication_between": "last_communication_between"
                }
                return mapping.get(out)
        except Exception:
            return None
        return None

    def _extract_party_b(self, query: str) -> Optional[str]:
        m = re.search(r"with\s+([\w+@.\-\s]+)$", query.lower())
        if m:
            return m.group(1).strip()
        return None


