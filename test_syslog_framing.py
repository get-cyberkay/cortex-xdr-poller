import os
import subprocess
import sys
import tempfile
import textwrap
import unittest


class SyslogFramingTests(unittest.TestCase):
    def test_tcp_framing_defaults_to_newline_delimited_messages(self) -> None:
        env = os.environ.copy()
        env.pop("SYSLOG_TCP_FRAMING", None)
        env["PYTHONPATH"] = os.getcwd()
        env["SYSLOG_TRANSPORT"] = "tcp"

        code = textwrap.dedent(
            """
            from syslog_handler import _format_rfc5424

            frames = [
                _format_rfc5424("event-1", "cortex-alerts"),
                _format_rfc5424("event-2", "cortex-incidents"),
            ]
            blob = b"".join(frames)
            print(blob.count(b"\\n"))
            print(len(blob.splitlines()))
            print(frames[0].startswith(b"<"))
            """
        )

        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, "-c", code],
                cwd=tmp,
                env=env,
                text=True,
                capture_output=True,
                check=True,
            )

        self.assertEqual(result.stdout.splitlines(), ["2", "2", "True"])

    def test_newline_framing_normalizes_payload_to_one_trailing_lf(self) -> None:
        env = os.environ.copy()
        env["PYTHONPATH"] = os.getcwd()
        env["SYSLOG_TRANSPORT"] = "tcp"
        env["SYSLOG_TCP_FRAMING"] = "newline"

        code = textwrap.dedent(
            """
            from syslog_handler import _format_rfc5424

            frame = _format_rfc5424("event-with-existing-newline\\r\\n", "cortex-alerts")
            print(frame.endswith(b"\\n"))
            print(frame.endswith(b"\\r\\n"))
            print(frame.count(b"\\n"))
            print(frame.rstrip(b"\\n").endswith(b"\\r"))
            """
        )

        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, "-c", code],
                cwd=tmp,
                env=env,
                text=True,
                capture_output=True,
                check=True,
            )

        self.assertEqual(result.stdout.splitlines(), ["True", "False", "1", "False"])


if __name__ == "__main__":
    unittest.main()
