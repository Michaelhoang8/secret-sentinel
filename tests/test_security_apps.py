import json
import unittest
from portfolio import security_apps as s
from portfolio.validation import ValidationError

def event(minute, status='failure', user='alice', ip='192.0.2.10'):
    return json.dumps({'timestamp': f'2026-01-01T10:{minute:02}:00Z', 'ip': ip, 'user': user, 'status': status})

class SecurityTests(unittest.TestCase):

    def test_secret_overlap_is_deduplicated_without_leakage(self):
        fake = 'ghp_' + 'A' * 36
        r = s.scan_secrets({'text': f'api_key = "{fake}"'})
        self.assertEqual(r['count'], 1)
        self.assertNotIn(fake, json.dumps(r))
        self.assertEqual(r['findings'][0]['severity'], 'high')

    def test_private_key_multiline_and_bearer(self):
        text = 'comment\n-----BEGIN PRIVATE KEY-----\nFAKE_DATA\n-----END PRIVATE KEY-----\nAuthorization: Bearer FICTIONAL_BEARER_VALUE'
        r = s.scan_secrets({'text': text})
        self.assertEqual([f['line'] for f in r['findings']], [2, 5])
        self.assertNotIn('FAKE_DATA', json.dumps(r))
        self.assertNotIn('FICTIONAL_BEARER_VALUE', json.dumps(r))

    def test_fine_grained_tokens_and_cloud_assignments_are_value_free(self):
        token = 'github_pat_' + 'DEMO_NOT_A_REAL_TOKEN_' * 4
        source = 'token: ' + token + '\nAWS_SECRET_ACCESS_KEY="SYNTHETIC_CLOUD_VALUE"\nrefresh_token="SYNTHETIC_REFRESH_VALUE"'
        report = s.scan_secrets({'text': source})
        self.assertEqual([item['line'] for item in report['findings']], [1, 2, 3])
        self.assertEqual(report['findings'][0]['rule'], 'Fine-grained GitHub-style token')
        self.assertEqual(report['findings'][0]['severity'], 'high')
        for secret in (token, 'SYNTHETIC_CLOUD_VALUE', 'SYNTHETIC_REFRESH_VALUE'):
            self.assertNotIn(secret, json.dumps(report))
        overlap = s.scan_secrets({'text': 'api_key="' + token + '"'})
        self.assertEqual(overlap['count'], 1)
        self.assertEqual(overlap['findings'][0]['severity'], 'high')

    def test_encrypted_private_key_and_dense_scan_line_numbers(self):
        report = s.scan_secrets({'text': 'comment\n-----BEGIN ENCRYPTED PRIVATE KEY-----\nSYNTHETIC_DATA\n-----END ENCRYPTED PRIVATE KEY-----'})
        self.assertEqual(report['findings'][0]['line'], 2)
        self.assertNotIn('SYNTHETIC_DATA', json.dumps(report))
        text = '\n'.join((f'password="SYNTHETIC_VALUE_{index}"' for index in range(5000)))
        report = s.scan_secrets({'text': text})
        self.assertEqual(report['count'], 5000)
        self.assertEqual([item['line'] for item in report['findings']], list(range(1, 5001)))

    def test_secret_locations_follow_supported_line_endings(self):
        for separator in ('\n', '\r\n', '\r', '\u2028'):
            report = s.scan_secrets({'text': separator.join(['comment', 'password="SYNTHETIC_ONLY_VALUE"', 'refresh_token="SYNTHETIC_REFRESH_VALUE"'])})
            self.assertEqual(report['lines_scanned'], 3)
            self.assertEqual([item['line'] for item in report['findings']], [2, 3])

    def test_secret_no_match_and_size_limits(self):
        self.assertEqual(s.scan_secrets({'text': 'ordinary text'})['count'], 0)
        for text in ['', 'a' * 500001, 'x\n' * 5001]:
            with self.assertRaises(ValidationError):
                s.scan_secrets({'text': text})
