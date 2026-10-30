from pathlib import Path
import json
import unittest
import cargo_locked

ROOT = Path(__file__).resolve().parents[2]


class SafetyRunnerContracts(unittest.TestCase):
    def test_fuzz_child_build_and_metadata_are_locked_without_changing_scope(self):
        for command in ('build', 'metadata'):
            args = [command, '--manifest-path', 'fuzz/Cargo.toml', '--features', 'libfuzzer']
            guarded = cargo_locked.locked_args(args)
            self.assertEqual(guarded[:-1], args)
            self.assertEqual(guarded[-1], '--locked')
        with self.assertRaises(RuntimeError):
            cargo_locked.locked_args(['install', 'unreviewed-tool'])
        run = ['run', '--manifest-path', 'fuzz/Cargo.toml', '--', '-max_total_time=15', 'corpus']
        self.assertEqual(cargo_locked.locked_args(run), run[:3] + ['--locked'] + run[3:])
        # A similarly named fuzzer flag after -- never satisfies Cargo's lock gate.
        trailing = ['run', '--', '--locked']
        self.assertEqual(cargo_locked.locked_args(trailing), ['run', '--locked', '--', '--locked'])

    def test_corpus_is_exactly_manifested_and_public_synthetic(self):
        import hashlib
        manifest = json.loads((ROOT / 'conformance/sanitizers/corpus-manifest.json').read_text())
        self.assertFalse(manifest['private_inputs'])
        grouped = {}
        for entry in manifest['files']:
            data = (ROOT / entry['path']).read_bytes()
            self.assertLessEqual(len(data), 65536)
            self.assertEqual(hashlib.sha256(data).hexdigest(), entry['sha256'])
            self.assertTrue(entry['source'].startswith(('tests/fixtures/', 'handwritten-')))
            if entry['source'].startswith('tests/fixtures/'):
                self.assertEqual(hashlib.sha256((ROOT / entry['source']).read_bytes()).hexdigest(),
                                 entry['sha256'])
            grouped.setdefault(entry['target'], set()).add(Path(entry['path']).name)
        self.assertEqual(len(grouped), 6)
        for target, files in grouped.items():
            self.assertEqual({p.name for p in (ROOT / 'fuzz/corpus' / target).iterdir()}, files)


if __name__ == '__main__':
    unittest.main()
