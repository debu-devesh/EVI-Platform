#!/usr/bin/env python3
"""Unit tests for LLM mojibake repair (OpenRouter / streaming)."""

import unittest

from utils.llm_text_repair import repair_llm_mojibake


class TestLlmTextRepair(unittest.TestCase):
    def test_google_fi_space(self):
        self.assertIn("Google Fi", repair_llm_mojibake("Google\u00e2Fi"))

    def test_possessive(self):
        self.assertIn("Google's", repair_llm_mojibake("Google\u00e2s"))

    def test_iso_date(self):
        self.assertIn("2020-10-03", repair_llm_mojibake("2020\u00e210\u00e203"))

    def test_cross_platform_hyphen(self):
        out = repair_llm_mojibake("Cross\u00e2platform")
        self.assertIn("Cross-platform", out)

    def test_message_number_range(self):
        out = repair_llm_mojibake("Messages 9\u00e212 and 13\u00e214")
        self.assertIn("9-12", out)
        self.assertIn("13-14", out)

    def test_spaced_iso_date(self):
        self.assertIn("2020-09-23", repair_llm_mojibake("2020\u00e2 09\u00e2 23"))

    def test_spaced_multimodal(self):
        out = repair_llm_mojibake("multi\u00e2 modal analysis")
        self.assertIn("multi-modal", out)

    def test_word_space_digit(self):
        out = repair_llm_mojibake("See Message\u00e2 4 for details")
        self.assertIn("Message 4", out)

    def test_line_start_smart_quote_mojibake(self):
        out = repair_llm_mojibake("\u00e2Important note")
        self.assertTrue(out.startswith('"Important'))

    def test_spaced_number_range(self):
        out = repair_llm_mojibake("items 9\u00e2 12 only")
        self.assertIn("9-12", out)


if __name__ == "__main__":
    unittest.main()
