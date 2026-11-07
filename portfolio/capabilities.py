from collections import Counter
from . import data_apps
from .validation import ValidationError

def table(title, headers, rows):
    return {'title': title, 'headers': headers, 'rows': rows}

def enrich(path, data, result):
    """Attach diagnostics without changing existing response fields."""
    tables, notes = ([], [])
    level = data.get('gate_severity', 'high')
    if level not in ('medium', 'high'):
        raise ValidationError('gate_severity must be medium or high')
    blocked = [f for f in result['findings'] if f['severity'] == 'high' or level == 'medium']
    result['gate'] = {'minimum_severity': level, 'blocked': bool(blocked), 'blocking_findings': len(blocked)}
    counts = Counter(((f['rule'], f['severity']) for f in result['findings']))
    tables = [table('Scan policy gate', ['Minimum severity', 'Gate', 'Blocking findings'], [[level, 'BLOCK' if blocked else 'PASS', len(blocked)]]), table('Rule summary', ['Rule', 'Severity', 'Count'], [[r, s, c] for (r, s), c in sorted(counts.items())])]
    result['findings_csv'] = data_apps.safe_csv(['rule', 'severity', 'line', 'action'], [[f['rule'], f['severity'], str(f['line']), f['action']] for f in result['findings']])
    notes = ['PASS means no matching findings at the configured severity; it is not proof that the text contains no secrets. Exported findings contain locations and remediation, never matched values.']
    if tables or notes:
        result['capabilities'] = {'tables': tables, 'notes': notes}
    return result
