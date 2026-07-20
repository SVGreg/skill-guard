"""Unit tests for the pure decision logic in skillguard_hook.

Run: python3 -m unittest discover -s hooks/tests
(Stdlib only — no pytest required.)
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import skillguard_hook as hook  # noqa: E402


class TestClassify(unittest.TestCase):
    def test_unsigned_short_circuits(self):
        self.assertEqual(hook.classify(3, "", "no .skillsig", False), hook.UNSIGNED)

    def test_tampered_wins_over_everything(self):
        out = "  SG-PRV-003  critical  Merkle root mismatch\n  SG-PRV-002  ..."
        self.assertEqual(hook.classify(2, out, "", True), hook.TAMPERED)

    def test_invalid_signature(self):
        self.assertEqual(hook.classify(2, "  SG-PRV-002  critical", "", True), hook.INVALID)

    def test_revoked(self):
        self.assertEqual(hook.classify(0, "  SG-PRV-004  high", "", True), hook.REVOKED)

    def test_unverified_no_roster(self):
        self.assertEqual(hook.classify(0, "  SG-PRV-005  medium", "", True), hook.UNVERIFIED)

    def test_trusted_clean_exit(self):
        out = "attestation: present, signature VALID (trusted key)\nmerkle root: MATCH"
        self.assertEqual(hook.classify(0, out, "", True), hook.TRUSTED)

    def test_unexpected_exit_is_error(self):
        self.assertEqual(hook.classify(3, "boom", "usage", True), hook.ERROR)


class TestDecide(unittest.TestCase):
    def test_trusted_always_allowed(self):
        for mode in ("log", "block-invalid", "enforce"):
            self.assertEqual(hook.decide(hook.TRUSTED, mode, "warn"), (False, ""))

    def test_log_mode_never_blocks(self):
        for state in (hook.TAMPERED, hook.INVALID, hook.UNSIGNED, hook.UNVERIFIED):
            block, _ = hook.decide(state, "log", "deny")
            self.assertFalse(block, state)

    def test_block_invalid_blocks_compromised_only(self):
        self.assertTrue(hook.decide(hook.TAMPERED, "block-invalid", "warn")[0])
        self.assertTrue(hook.decide(hook.INVALID, "block-invalid", "warn")[0])
        self.assertTrue(hook.decide(hook.REVOKED, "block-invalid", "warn")[0])
        # unsigned / unverified are allowed in block-invalid
        self.assertFalse(hook.decide(hook.UNSIGNED, "block-invalid", "warn")[0])
        self.assertFalse(hook.decide(hook.UNVERIFIED, "block-invalid", "warn")[0])

    def test_enforce_requires_valid_and_trusted(self):
        for state in (hook.TAMPERED, hook.INVALID, hook.REVOKED,
                      hook.UNVERIFIED, hook.UNSIGNED):
            self.assertTrue(hook.decide(state, "enforce", "warn")[0], state)

    def test_unresolved_respects_action(self):
        self.assertFalse(hook.decide(hook.UNRESOLVED, "enforce", "allow")[0])
        self.assertFalse(hook.decide(hook.UNRESOLVED, "enforce", "warn")[0])
        self.assertTrue(hook.decide(hook.UNRESOLVED, "enforce", "deny")[0])
        # log mode never blocks, even with unresolved_action=deny
        self.assertFalse(hook.decide(hook.UNRESOLVED, "log", "deny")[0])


class TestExpand(unittest.TestCase):
    def test_expands_known_vars(self):
        os.environ["CLAUDE_PROJECT_DIR"] = "/proj"
        self.assertEqual(hook.expand("${CLAUDE_PROJECT_DIR}/x"), "/proj/x")

    def test_leaves_unknown_untouched(self):
        self.assertEqual(hook.expand("${NOPE_UNSET_VAR}/y"), "${NOPE_UNSET_VAR}/y")


if __name__ == "__main__":
    unittest.main()
