import unittest

from scanner.sanitizer import (
    redact_private_ips,
    redact_secrets,
    sanitize_text,
)


class SanitizerTests(unittest.TestCase):

    def test_password_redaction(self):
        text = 'password = "ExamplePassword123"'

        result = redact_secrets(text)

        self.assertNotIn("ExamplePassword123", result)
        self.assertIn("[REDACTED_SECRET]", result)

    def test_api_key_redaction(self):
        text = 'api_key = "example_secret_123456"'

        result = redact_secrets(text)

        self.assertNotIn("example_secret_123456", result)
        self.assertIn("[REDACTED_SECRET]", result)

    def test_aws_key_redaction(self):
        text = "key = AKIA1234567890ABCDEF"

        result = redact_secrets(text)

        self.assertNotIn("AKIA1234567890ABCDEF", result)
        self.assertIn("[REDACTED_AWS_KEY]", result)

    def test_github_token_redaction(self):
        token = "github_pat_" + ("A" * 30)
        result = redact_secrets(token)

        self.assertNotIn(token, result)
        self.assertIn("[REDACTED_GITHUB_TOKEN]", result)

    def test_private_ip_redaction(self):
        text = "Internal host: 192.168.1.10"

        result = redact_private_ips(text)

        self.assertNotIn("192.168.1.10", result)
        self.assertIn("[REDACTED_PRIVATE_IP]", result)

    def test_public_ip_preserved(self):
        text = "Public host: 8.8.8.8"

        result = redact_private_ips(text)

        self.assertIn("8.8.8.8", result)

    def test_combined_sanitization(self):
        text = (
            'api_key = "example_secret_123456"\n'
            "host = 192.168.1.10"
        )

        result = sanitize_text(text, redact_ips=True)

        self.assertNotIn("example_secret_123456", result)
        self.assertNotIn("192.168.1.10", result)

    def test_non_string_rejected(self):
        with self.assertRaises(TypeError):
            redact_secrets(None)


if __name__ == "__main__":
    unittest.main(verbosity=2)