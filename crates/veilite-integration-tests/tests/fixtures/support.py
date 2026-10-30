"""Shared SQLCipher fixture generation utilities (standard library only)."""
import argparse
from contextlib import contextmanager
import pathlib
import queue
import subprocess
import threading


def options(root):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("engine", nargs="?", default="sqlcipher")
    parser.add_argument("--output-dir", type=pathlib.Path, default=root)
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
    if not 0 < args.timeout < float("inf"):
        parser.error("--timeout must be finite and positive")
    return args


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(args, path, sql, *, check=True, cwd=None):
    return subprocess.run(
        [args.engine, str(path)], input=".bail on\n" + sql,
        text=True, encoding="utf-8", capture_output=True, check=check,
        timeout=args.timeout, cwd=cwd,
    )


def versions(args):
    lines = run(args, ":memory:", "PRAGMA cipher_version; SELECT sqlite_version();").stdout.strip().splitlines()
    require(len(lines) == 2, "SQLCipher is required")
    print(f"SQLCipher {lines[0]} / SQLite {lines[1]}", flush=True)


def expect_tail(output, expected, context):
    require(output.strip().splitlines()[-len(expected):] == expected,
            f"{context}: unexpected output: {output!r}")


def require_encrypted(args, path):
    result = run(args, path, "SELECT count(*) FROM sqlite_master;", check=False)
    require(result.returncode != 0, f"{path}: readable without a key")


class Writer:
    def __init__(self, process, timeout):
        self.process = process
        self.timeout = timeout
        self.lines = queue.Queue()
        self.errors = []
        self.threads = [
            threading.Thread(target=self._stdout, daemon=True),
            threading.Thread(target=self._stderr, daemon=True),
        ]
        for thread in self.threads:
            thread.start()

    def _stdout(self):
        try:
            for line in self.process.stdout:
                self.lines.put(line)
        finally:
            self.lines.put(None)

    def _stderr(self):
        self.errors.extend(self.process.stderr)

    def barrier(self, sql):
        # Writing also runs in the worker so a stalled reader cannot block the caller.
        def send():
            try:
                self.process.stdin.write(sql + "\n.print FIXTURE_READY\n")
                self.process.stdin.flush()
            except (OSError, ValueError) as error:
                self.lines.put(error)
        sender = threading.Thread(target=send, daemon=True)
        self.threads.append(sender)
        sender.start()
        import time
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                line = self.lines.get(timeout=max(0, deadline - time.monotonic()))
            except queue.Empty:
                raise TimeoutError("SQLCipher writer did not reach the copy barrier") from None
            if isinstance(line, Exception):
                raise RuntimeError("SQLCipher writer input failed") from line
            if line is None:
                raise RuntimeError("SQLCipher writer exited before the copy barrier")
            if line.strip() == "FIXTURE_READY":
                sender.join()
                return


@contextmanager
def writer(args, path):
    process = subprocess.Popen(
        [args.engine, str(path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, encoding="utf-8", bufsize=1,
    )
    session = Writer(process, args.timeout)
    try:
        yield session
        process.stdin.close()
        process.wait(timeout=args.timeout)
        require(process.returncode == 0, "SQLCipher writer failed")
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=min(5, args.timeout))
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for thread in session.threads:
            thread.join()
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
        if session.errors:
            import sys
            print("".join(session.errors), file=sys.stderr, end="")
