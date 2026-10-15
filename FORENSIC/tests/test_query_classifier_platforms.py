#!/usr/bin/env python3
"""Regression: platform tokens (LINE vs timeline) and find-* extraction."""

import unittest

from core.guarantee_class import _has_explicit_raw_pull
from core.query_classifier import classify_query


class TestQueryClassifierPlatforms(unittest.TestCase):
    def test_line_in_timeline_does_not_false_detect_line_app(self):
        q = "show a time-ordered timeline for line on 2020-10-04"
        r = classify_query(q)
        self.assertEqual(r.get("platform"), "line")

    def test_timeline_word_does_not_match_line_platform(self):
        q = "show timeline for 2020-10-03"
        r = classify_query(q)
        self.assertIsNone(r.get("platform"))

    def test_find_all_line_messages_uppercase_brand(self):
        q = "Find all LINE messages from 2020-09-22"
        r = classify_query(q)
        self.assertEqual(r.get("platform"), "line")
        self.assertEqual(r.get("type"), "extraction")


class TestExplicitRawPull(unittest.TestCase):
    def test_find_all_messages_is_explicit_pull(self):
        ql = "find all line messages from 2020-09-22"
        self.assertTrue(_has_explicit_raw_pull(ql))


if __name__ == "__main__":
    unittest.main()
