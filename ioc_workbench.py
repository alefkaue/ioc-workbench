"""Normalize a line-oriented IOC list without DNS lookups or external enrichment."""
import argparse
from collections import Counter
import ipaddress
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit, urlunsplit


def hostname(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if re.fullmatch(r'[0-9.]+', value):
        raise ValueError('invalid IP address')
    domain = value.rstrip('.').encode('idna').decode('ascii').lower()
    labels = domain.split('.')
    if len(domain) > 253 or len(labels) < 2 or any(
        not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels
    ) or labels[-1].isdigit():
        raise ValueError('invalid domain')
    return domain


def normalize(raw):
    value = raw.strip().replace('[.]', '.').replace('[:]', ':')
    value = re.sub(r'^hxxps:', 'https:', value, flags=re.I)
    value = re.sub(r'^hxxp:', 'http:', value, flags=re.I)
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError('whitespace/control characters are not supported')
    if re.fullmatch('[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}', value):
        return {32: 'md5', 40: 'sha1', 64: 'sha256'}[len(value)], value.lower()
    if '://' in value:
        if '\\' in value:
            raise ValueError('backslashes are not supported in URLs')
        parts = urlsplit(value)
        scheme = parts.scheme.lower()
        if scheme not in ('http', 'https') or not parts.hostname or parts.username is not None or parts.password is not None:
            raise ValueError('expected HTTP(S) URL without credentials')
        host = hostname(parts.hostname)
        port = parts.port
        if parts.netloc.endswith(':') or port == 0:
            raise ValueError('invalid port')
        if ':' in host:
            host = '[' + host + ']'
        authority = host if port is None or (scheme, port) in [('http', 80), ('https', 443)] else f'{host}:{port}'
        # Preserve path/query bytes and fragments; their semantics are context-dependent.
        return 'url', urlunsplit((scheme, authority, parts.path or '/', parts.query, parts.fragment))
    try:
        address = ipaddress.ip_address(value)
        return ('ipv4' if address.version == 4 else 'ipv6'), str(address)
    except ValueError:
        return 'domain', hostname(value)


def analyze(lines):
    unique, rejected = {}, []
    total = 0
    for number, raw in enumerate(lines, 1):
        if not raw.strip() or raw.lstrip().startswith('#'):
            continue
        total += 1
        try:
            kind, value = normalize(raw)
        except (ValueError, UnicodeError) as error:
            rejected.append(dict(line=number, reason=str(error)))
            continue
        key = (kind, value)
        unique.setdefault(key, dict(type=kind, value=value, source_lines=[]))['source_lines'].append(number)
    indicators = sorted(unique.values(), key=lambda item: (item['type'], item['value']))
    return dict(input_count=total, unique_count=len(indicators),
                duplicates=sum(len(i['source_lines']) - 1 for i in indicators),
                counts=dict(sorted(Counter(i['type'] for i in indicators).items())),
                indicators=indicators, rejected=rejected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    args = parser.parse_args()
    try:
        with args.input.open(encoding='utf-8') as stream:
            report = analyze(stream)
    except (OSError, ValueError) as error:
        parser.exit(2, f'Error: {error}\n')
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 1 if report['rejected'] else 0


if __name__ == '__main__':
    sys.exit(main())
