#!/usr/bin/env python3
"""Tests for LLM provider switch helpers."""

import unittest

import web_interface as wi


class TestLlmProviderSwitch(unittest.TestCase):
    def test_normalize_provider_defaults_to_local(self):
        self.assertEqual(wi.normalize_llm_provider("LOCAL"), "local")
        self.assertEqual(wi.normalize_llm_provider("openrouter"), "openrouter")
        self.assertEqual(wi.normalize_llm_provider("invalid"), "local")
        self.assertEqual(wi.normalize_llm_provider(None), "local")

    def test_request_provider_override_wins(self):
        provider = wi.resolve_effective_llm_provider(
            session_id="abc",
            request_data={"llm_provider": "openrouter"},
        )
        self.assertEqual(provider, "openrouter")

    def test_session_preference_used_when_request_missing(self):
        old_db = wi.SESSION_DB_AVAILABLE
        old_get = wi.get_preferences
        try:
            wi.SESSION_DB_AVAILABLE = True
            wi.get_preferences = lambda _sid: {"llm_provider": "openrouter"}
            provider = wi.resolve_effective_llm_provider(
                session_id="abc",
                request_data={},
            )
            self.assertEqual(provider, "openrouter")
        finally:
            wi.SESSION_DB_AVAILABLE = old_db
            wi.get_preferences = old_get

    def test_openrouter_model_resolution_prefers_openrouter_model(self):
        old_model = wi.LLM_OPENROUTER_MODEL
        try:
            wi.LLM_OPENROUTER_MODEL = "openrouter/demo-free"
            self.assertEqual(
                wi.resolve_effective_llm_model("openrouter"),
                "openrouter/demo-free",
            )
        finally:
            wi.LLM_OPENROUTER_MODEL = old_model

    def test_normalize_openrouter_api_key_strips_bearer_prefix(self):
        self.assertEqual(
            wi._normalize_openrouter_api_key("  Bearer sk-test  "),
            "sk-test",
        )
        self.assertEqual(
            wi._normalize_openrouter_api_key("bEaReR sk-or-v1-abc"),
            "sk-or-v1-abc",
        )

    def test_openrouter_401_hint_only_for_openrouter(self):
        body = '{"error":{"message":"User not found.","code":401}}'
        self.assertIn("User not found", wi._openrouter_client_error_hint("openrouter", 401, body))
        self.assertEqual(wi._openrouter_client_error_hint("local", 401, body), "")


if __name__ == "__main__":
    unittest.main()
