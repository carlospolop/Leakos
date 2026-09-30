import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import leakos


class GGShieldIntegrationTests(unittest.TestCase):
    def setUp(self):
        leakos.ALL_LEAKS = {}
        leakos.MAX_SECRET_LENGTH = 1500
        leakos.TIMEOUT = 30
        self.repo = SimpleNamespace(full_name="example/repo")

    def test_detects_incident_and_uses_supported_cli_flags(self):
        output = {
            "scans": [{
                "entities_with_incidents": [{
                    "incidents": [{
                        "type": "Test Key",
                        "occurrences": [{"match": "synthetic-test-key"}],
                    }],
                }],
            }],
        }
        completed = SimpleNamespace(returncode=1, stdout=json.dumps(output).encode())
        with patch.object(leakos.subprocess, "run", return_value=completed) as run:
            leakos.get_ggshield_repo_leaks(self.repo, "token", set(), False, "/tmp/fixture")

        self.assertEqual(leakos.ALL_LEAKS["synthetic-test-key"]["tool"], "ggshield")
        command = run.call_args.args[0]
        self.assertIn("--show-secrets", command)
        self.assertNotIn("--recursive", command)
        self.assertNotIn("env", run.call_args.kwargs)

    def test_authentication_error_fails_scan(self):
        completed = SimpleNamespace(returncode=3, stdout=b"")
        with patch.object(leakos.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(RuntimeError, "exit code 3"):
                leakos.get_ggshield_repo_leaks(self.repo, "token", set(), False, "/tmp/fixture")


if __name__ == "__main__":
    unittest.main()
