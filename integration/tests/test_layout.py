import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TestIntegrationLayout(unittest.TestCase):
    def test_top_level_modules_are_named_by_role(self):
        expected_dirs = {
            "contracts",
            "harness",
            "providers",
            "runtime",
            "semantics",
            "tests",
            "tools",
        }
        actual_dirs = {p.name for p in ROOT.iterdir() if p.is_dir() and not p.name.startswith(".")}
        self.assertTrue(expected_dirs.issubset(actual_dirs))
        self.assertNotIn("profiles", actual_dirs)
        self.assertNotIn("zk-platform", actual_dirs)
        self.assertNotIn("scripts", actual_dirs)
        self.assertNotIn("docker", actual_dirs)

    def test_all_providers_live_under_one_provider_root(self):
        providers = ROOT / "providers"
        for name in ["openac", "semantic-reference", "test-stub"]:
            self.assertTrue((providers / name / "manifest.json").is_file(), name)
        self.assertFalse((ROOT / "harness" / "providers").exists())

    def test_root_readme_explains_profiles_vs_semantics(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("implementation profile", readme)
        self.assertIn("semantic claim", readme)
        self.assertIn("Do not add semantic definitions to a profiles directory", readme)


if __name__ == "__main__":
    unittest.main()
