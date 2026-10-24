from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON_SOURCE = ROOT / "anti_cheat.py"
CPP_SOURCE = ROOT / "AntiCheat.cpp"


def load_module():
    spec = importlib.util.spec_from_file_location("anti_cheat", PYTHON_SOURCE)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class PythonIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.script = Path(self.temp_dir.name) / "anti_cheat.py"
        self.script.write_bytes(PYTHON_SOURCE.read_bytes())

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_unconfigured_integrity_is_optional(self):
        self.assertTrue(self.module.verify_integrity(self.script, {}))

    def test_matching_hash_is_accepted(self):
        expected = hashlib.sha256(self.script.read_bytes()).hexdigest()
        self.assertTrue(
            self.module.verify_integrity(
                self.script,
                {"JAVELIN_EXPECTED_SHA256": expected},
            )
        )

    def test_non_matching_hash_is_rejected(self):
        self.assertFalse(
            self.module.verify_integrity(
                self.script,
                {"JAVELIN_EXPECTED_SHA256": "0" * 64},
            )
        )

    def test_malformed_hash_is_rejected(self):
        self.assertFalse(
            self.module.verify_integrity(
                self.script,
                {"JAVELIN_EXPECTED_SHA256": "not-a-sha256"},
            )
        )

    def test_modified_script_exits_with_guarded_code(self):
        expected = hashlib.sha256(self.script.read_bytes()).hexdigest()
        self.script.write_bytes(self.script.read_bytes() + b"\n# modified\n")

        environment = os.environ.copy()
        environment["JAVELIN_EXPECTED_SHA256"] = expected

        completed = subprocess.run(
            [sys.executable, str(self.script)],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 3)
        self.assertIn("Integrity check failed", completed.stderr)


class CppIntegritySourceTests(unittest.TestCase):
    def test_integrity_slot_and_guarded_exit_are_present(self):
        source = CPP_SOURCE.read_text(encoding="utf-8")
        self.assertIn("JAVELIN_EXPECTED_CRC32", source)
        self.assertIn("canonicalExecutableCrc", source)
        self.assertIn("verifySelfIntegrity", source)
        self.assertIn("kIntegrityFailureExitCode = 3", source)

    @unittest.skipUnless(shutil.which("cl"), "MSVC cl.exe is required for native Windows build")
    def test_windows_source_compiles(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "AntiCheat.exe"
            completed = subprocess.run(
                [
                    "cl",
                    "/nologo",
                    "/std:c++17",
                    "/EHsc",
                    str(CPP_SOURCE),
                    f"/Fe:{output}",
                ],
                cwd=directory,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertTrue(output.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
