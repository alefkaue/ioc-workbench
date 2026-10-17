import unittest
from ioc_workbench import normalize, analyze


class IOCTests(unittest.TestCase):
    def test_dedup_provenance_and_rejections(self):
        result = analyze(['# lab', 'EXAMPLE[.]ORG', 'example.org.', 'bad input', '192.0.2.1'])
        self.assertEqual(result['unique_count'], 2)
        self.assertEqual(result['duplicates'], 1)
        self.assertEqual(result['indicators'][0]['source_lines'], [2, 3])
        self.assertEqual(result['rejected'][0]['line'], 4)

    def test_url_preserves_case_and_query(self):
        self.assertEqual(normalize('hxxps[:]//EXAMPLE[.]ORG:443/Path?Token=AbC#Part'),
                         ('url', 'https://example.org/Path?Token=AbC#Part'))

    def test_idna_ipv6_and_hashes(self):
        self.assertEqual(normalize('ação.example'), ('domain', 'xn--ao-siap.example'))
        self.assertEqual(normalize('2001:0db8::1'), ('ipv6', '2001:db8::1'))
        self.assertEqual(normalize('https://[2001:db8::1]:8443'), ('url', 'https://[2001:db8::1]:8443/'))
        for length, kind in [(32, 'md5'), (40, 'sha1'), (64, 'sha256')]:
            self.assertEqual(normalize('A' * length), (kind, 'a' * length))

    def test_reject_ambiguous_or_unsafe_formats(self):
        for value in ['999.0.0.1', '-bad.example', 'a..example', 'ftp://example.org',
                      'https://user:pass@example.org', 'https://example.org:99999',
                      'https://example.org:', 'https://example.org:0', 'https://example.org/has space']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize(value)

    def test_empty_and_comments(self):
        result = analyze(['', '# comment'])
        self.assertEqual(result['input_count'], 0)
        self.assertEqual(result['indicators'], [])
