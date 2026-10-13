import unittest

from scanner.ai_analyzer import analyse_finding


class TestAIAnalyzer(unittest.TestCase):

    def test_missing_required_field(self):
        finding = {
            "rule_id": "B602",
            "severity": "HIGH",
        }

        with self.assertRaises(ValueError):
            analyse_finding(finding)

    def test_non_dictionary_finding(self):
        with self.assertRaises(TypeError):
            analyse_finding("not a finding")


if __name__ == "__main__":
    unittest.main()