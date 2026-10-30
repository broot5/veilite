"""Run with python3 -O -m unittest discover -s <fixtures directory>."""
import pathlib
import io
from contextlib import redirect_stderr
import sys
import tempfile
import textwrap
import unittest
from types import SimpleNamespace

from support import expect_tail, require, writer


class GenerationSupportTests(unittest.TestCase):
    def test_validation_remains_enabled_with_optimization(self):
        with self.assertRaises(RuntimeError):
            require(False, "invalid fixture")
        with self.assertRaises(RuntimeError):
            expect_tail("not ok\n", ["ok"], "integrity")

    def script(self, directory, source):
        path = pathlib.Path(directory) / "engine.py"
        path.write_text(textwrap.dedent(source), encoding="utf-8")
        return path

    def test_writer_drains_both_streams_and_exits(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.script(directory, '''
                import sys
                for line in sys.stdin:
                    if line.startswith('.print'):
                        sys.stdout.write('output\\n' * 10000)
                        sys.stderr.write('diagnostic\\n' * 10000)
                        print('FIXTURE_READY', flush=True)
            ''')
            args = SimpleNamespace(engine=sys.executable, timeout=5)
            with redirect_stderr(io.StringIO()) as diagnostics:
                with writer(args, path) as session:
                    session.barrier("SELECT 1;")
            self.assertEqual(session.process.returncode, 0)
            self.assertIn("diagnostic", diagnostics.getvalue())
            self.assertTrue(all(not thread.is_alive() for thread in session.threads))

    def test_stalled_writer_is_killed_and_reaped(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.script(directory, '''
                import signal
                import time
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                print('FIXTURE_READY', flush=True)
                time.sleep(60)
            ''')
            args = SimpleNamespace(engine=sys.executable, timeout=1)
            with self.assertRaises(TimeoutError):
                with writer(args, path) as session:
                    session.barrier("SELECT 1;")
                    # Also exercise a write larger than the pipe's capacity.
                    session.barrier("x" * 1_000_000)
            self.assertIsNotNone(session.process.returncode)
            self.assertTrue(all(not thread.is_alive() for thread in session.threads))

    def test_early_exit_is_reported_and_reaped(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.script(directory, "raise SystemExit(7)")
            args = SimpleNamespace(engine=sys.executable, timeout=5)
            with self.assertRaises(RuntimeError):
                with writer(args, path) as session:
                    session.barrier("SELECT 1;")
            self.assertEqual(session.process.returncode, 7)
