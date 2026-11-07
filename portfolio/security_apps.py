from bisect import bisect_right
import re
from .validation import ValidationError

def source(data):
    value = data.get('text')
    if not isinstance(value, str) or not value.strip() or len(value.encode('utf-8')) > 500000:
        raise ValidationError('Provide nonempty text of at most 500 KB')
    if len(value.splitlines()) > 5000:
        raise ValidationError('Limit input to 5,000 lines')
    return value
SECRET_RULES = [('Private key block', re.compile('-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[\\s\\S]*?(?:-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----|\\Z)'), 'high'), ('Fine-grained GitHub-style token', re.compile('\\bgithub_pat_[A-Za-z0-9_]{20,255}\\b'), 'high'), ('GitHub-style token', re.compile('\\bgh[pousr]_[A-Za-z0-9]{20,255}\\b'), 'high'), ('AWS-style access key ID', re.compile('\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b'), 'medium'), ('Secret assignment', re.compile('(?im)\\b(?:api[_-]?key|client[_-]?secret|password|access[_-]?token|refresh[_-]?token|secret[_-]?key|aws[_-]?secret[_-]?access[_-]?key|aws[_-]?session[_-]?token)\\b["\']?\\s*[:=]\\s*["\']?([^\\s"\'`,;#]{8,256})'), 'medium'), ('Bearer credential', re.compile('(?i)\\bBearer\\s+([A-Za-z0-9._~+/-]{12,512}=*)'), 'high')]

def scan_secrets(data):
    text = source(data)
    spans = []
    for name, pattern, severity in SECRET_RULES:
        for match in pattern.finditer(text):
            start, end = match.span(1) if match.lastindex else match.span()
            spans.append((start, end, name, severity))
    spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    merged = []
    for start, end, name, severity in spans:
        if merged and start < merged[-1][1]:
            old = merged[-1]
            merged[-1] = (old[0], max(end, old[1]), old[2], 'high' if 'high' in (old[3], severity) else 'medium')
        else:
            merged.append((start, end, name, severity))
    line_starts = [0]
    offset = 0
    for line in text.splitlines(keepends=True):
        offset += len(line)
        if offset < len(text):
            line_starts.append(offset)
    findings = [{'rule': name, 'severity': severity, 'line': bisect_right(line_starts, start), 'action': 'Verify locally. If real and exposed, revoke/rotate it and remove it from source and history.'} for start, end, name, severity in merged]
    return {'findings': findings, 'count': len(findings), 'lines_scanned': len(text.splitlines()), 'note': 'Pattern-based review; false positives and missed secrets are possible. No raw values, snippets, hashes, or original text are returned. Results do not establish whether credentials are live.'}
