"""Unit tests for the pure decision logic in skillguard_hook.

Run: python3 -m unittest discover -s hooks/tests
(Stdlib only — no pytest required.)
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import skillguard_hook as hook  # noqa: E402


def decision_json(outcome, **extra):
    """A `skill-guard guard --format json` document, trimmed to what we read."""
    doc = {
        "outcome": outcome,
        "reason": "because",
        "path": "./skill",
        "content_hash": "sha256:abcd",
        "signature": {"present": False, "valid": False, "trusted": False},
        "mode": "load",
        "scanned": True,
    }
    doc.update(extra)
    return json.dumps(doc)


class TestOutcomeOf(unittest.TestCase):
    """The hook reads one field. These pin that it reads it, and that it
    refuses to guess when the document is not the contract."""

    def test_reads_each_outcome(self):
        for outcome, rc in ((hook.ALLOW, 0), (hook.WARN, 0), (hook.DENY, 1)):
            state, d = hook.outcome_of(rc, decision_json(outcome))
            self.assertEqual(state, outcome)
            self.assertEqual(d["reason"], "because")

    def test_not_json_is_error(self):
        state, _ = hook.outcome_of(0, "attestation: present, signature VALID")
        self.assertEqual(state, hook.ERROR)

    def test_unknown_outcome_is_error(self):
        state, _ = hook.outcome_of(0, decision_json("maybe"))
        self.assertEqual(state, hook.ERROR)

    def test_empty_output_is_error(self):
        self.assertEqual(hook.outcome_of(4, "")[0], hook.ERROR)

    def test_exit_code_must_agree_with_the_outcome(self):
        # A deny that exits 0, or an allow that exits 1, means we are not
        # talking to the documented contract — believing half of it is how a
        # gate silently stops gating.
        self.assertEqual(hook.outcome_of(0, decision_json(hook.DENY))[0], hook.ERROR)
        self.assertEqual(hook.outcome_of(1, decision_json(hook.ALLOW))[0], hook.ERROR)

    def test_json_array_is_error(self):
        self.assertEqual(hook.outcome_of(0, "[1,2,3]")[0], hook.ERROR)


class TestDecide(unittest.TestCase):
    def test_allow_always_allowed(self):
        for mode in ("log", "block-invalid", "enforce"):
            self.assertEqual(hook.decide(hook.ALLOW, mode, "warn"), (False, ""))
            self.assertEqual(hook.decide(hook.BUILTIN, mode, "warn"), (False, ""))

    def test_log_mode_never_blocks(self):
        for state in (hook.DENY, hook.WARN, hook.UNRESOLVED):
            block, _ = hook.decide(state, "log", "deny")
            self.assertFalse(block, state)

    def test_block_invalid_blocks_denials_only(self):
        # A denial is a compromised signature or a failing scan verdict; a
        # warning (unsigned, unverified, warn verdict) still runs.
        self.assertTrue(hook.decide(hook.DENY, "block-invalid", "warn")[0])
        self.assertFalse(hook.decide(hook.WARN, "block-invalid", "warn")[0])

    def test_enforce_blocks_warnings_too(self):
        self.assertTrue(hook.decide(hook.DENY, "enforce", "warn")[0])
        self.assertTrue(hook.decide(hook.WARN, "enforce", "warn")[0])

    def test_enforce_is_never_laxer_than_block_invalid(self):
        for state in (hook.ALLOW, hook.WARN, hook.DENY):
            lax = hook.decide(state, "block-invalid", "warn")[0]
            strict = hook.decide(state, "enforce", "warn")[0]
            self.assertTrue(strict or not lax, f"{state}: enforce laxer than block-invalid")

    def test_unresolved_respects_action(self):
        self.assertFalse(hook.decide(hook.UNRESOLVED, "enforce", "allow")[0])
        self.assertFalse(hook.decide(hook.UNRESOLVED, "enforce", "warn")[0])
        self.assertTrue(hook.decide(hook.UNRESOLVED, "enforce", "deny")[0])
        # log mode never blocks, even with unresolved_action=deny
        self.assertFalse(hook.decide(hook.UNRESOLVED, "log", "deny")[0])

    def test_error_defers_to_on_error(self):
        # decide() never blocks on ERROR; the on_error policy is applied by the
        # caller, so that fail-open/closed is decided in exactly one place.
        self.assertFalse(hook.decide(hook.ERROR, "enforce", "deny")[0])


class TestGuardCommand(unittest.TestCase):
    def test_asks_for_a_json_decision_at_load(self):
        cmd = hook.guard_command({"skill_guard_bin": "skill-guard", "policy": "",
                                  "cache_dir": ""}, "/b/skill")
        self.assertIn("guard", cmd)
        self.assertEqual(cmd[cmd.index("--format") + 1], "json")
        self.assertEqual(cmd[cmd.index("--mode") + 1], "load")
        self.assertNotIn("--cache-dir", cmd)

    def test_cache_dir_is_passed_through(self):
        cmd = hook.guard_command({"skill_guard_bin": "skill-guard", "policy": "",
                                  "cache_dir": "-"}, "/b/skill")
        self.assertEqual(cmd[cmd.index("--cache-dir") + 1], "-")


class TestTimeout(unittest.TestCase):
    def test_prefers_the_new_key(self):
        self.assertEqual(hook._timeout({"timeout_seconds": 5, "verify_timeout_seconds": 9}), 5)

    def test_honours_the_legacy_key(self):
        # An existing config written before the hook called `guard` must keep
        # working rather than silently reverting to the default.
        self.assertEqual(hook._timeout({"verify_timeout_seconds": 9}), 9)

    def test_default(self):
        self.assertEqual(hook._timeout({}), 20)


class TestExpand(unittest.TestCase):
    def test_expands_known_vars(self):
        os.environ["CLAUDE_PROJECT_DIR"] = "/proj"
        self.assertEqual(hook.expand("${CLAUDE_PROJECT_DIR}/x"), "/proj/x")

    def test_leaves_unknown_untouched(self):
        self.assertEqual(hook.expand("${NOPE_UNSET_VAR}/y"), "${NOPE_UNSET_VAR}/y")


if __name__ == "__main__":
    unittest.main()
