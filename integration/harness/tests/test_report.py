"""HTML report sanitization: escape + allowlisted CSS, no content rewrite."""
import unittest

from report import render_html_report


class TestReport(unittest.TestCase):
    def test_script_tags_escaped(self):
        evil = "<script>alert(1)</script>"
        html = render_html_report(
            "Test",
            [{"name": evil, "outcome": "failed", "detail": evil}],
            {"note": "illustrative only"},
        )
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_literal_onclick_text_not_rewritten(self):
        html = render_html_report(
            "t",
            [{"name": "n", "outcome": "passed", "detail": "onclick=alert(1)"}],
            {},
        )
        self.assertIn("onclick=alert(1)", html)
        self.assertNotIn("onclick_", html)
        self.assertIn("class='passed'", html)

    def test_outcome_class_from_allowlist_only(self):
        html = render_html_report(
            "t",
            [{"name": "n", "outcome": "passed' onclick=alert(1)", "detail": "d"}],
            {},
        )
        self.assertIn("class='unknown'", html)
        self.assertNotRegex(html, r"<tr class='[^']*onclick")
        self.assertIn("onclick=alert(1)", html)

    def test_known_outcome_classes(self):
        for outcome in ("passed", "failed", "provider_error", "not_run"):
            html = render_html_report(
                "t", [{"name": "n", "outcome": outcome, "detail": "d"}], {}
            )
            self.assertIn(f"class='{outcome}'", html)


if __name__ == "__main__":
    unittest.main()
