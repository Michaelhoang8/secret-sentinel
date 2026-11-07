import json
import csv
import io
from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path
from portfolio import capabilities as c, data_apps as d, security_apps as security
from portfolio.db import initialize, connect, SCHEMA
from portfolio.validation import ValidationError, NotFoundError

def enhanced(path, data, function):
    return c.enrich(path, data, function(data))

class AnalysisCapabilities(unittest.TestCase):

    def test_secret_gate_and_export_are_value_free(self):
        data = {'text': 'password="FICTIONAL_CREDENTIAL"', 'gate_severity': 'high'}
        r = enhanced('/api/security/secrets', data, security.scan_secrets)
        self.assertFalse(r['gate']['blocked'])
        self.assertNotIn('FICTIONAL_CREDENTIAL', json.dumps(r))
        data['gate_severity'] = 'medium'
        self.assertTrue(enhanced('/api/security/secrets', data, security.scan_secrets)['gate']['blocked'])
        data['gate_severity'] = 'unknown'
        with self.assertRaises(ValidationError):
            enhanced('/api/security/secrets', data, security.scan_secrets)
if __name__ == '__main__':
    unittest.main()
