# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from import_proofs import safety_slice
from omit_unused_sections import apply_repairs, repairs


class ProofToolTests(unittest.TestCase):
    def test_retirement_guarantees_are_not_in_the_safety_slice(self):
        source = (
            "namespace CCFRaft\n"
            "/-- Retirement-only fact. -/\ndef HasCommittedRemovalBefore := True\n"
            "structure RetirementInvariantFacts where\n  unrelated : True\n"
            "/-- Existentially package every consensus-safety invariant component. -/\n"
            "def SafetyInductiveInvariant := True\n"
            "/-- The complete inductive invariant includes retirement consistency. -/\n"
            "def SystemInductiveInvariant := SafetyInductiveInvariant\n"
            "\nend CCFRaft\n"
        )
        result = safety_slice("Invariant", source)
        self.assertNotIn("RetirementInvariantFacts", result)
        self.assertNotIn("HasCommittedRemovalBefore", result)
        self.assertEqual(result.count("def SystemInductiveInvariant"), 1)
        self.assertEqual(safety_slice("Invariant", result), result)

    def test_safety_preservation_and_reachability_are_retained(self):
        source = (
            "lemma safetyInductiveInvariantPreserved : True := trivial\n"
            "lemma retirementInvariantFacts_refreshNode : True := trivial\n"
            "lemma unrelatedRetirementGuarantee : True := trivial\n"
            "/-! ## Reachable safety exports -/\n"
            "lemma reachableSafetyInductiveInvariant : True := trivial\n"
        )
        result = safety_slice("ReconfigurationPreservation", source)
        self.assertIn("systemInductiveInvariantPreserved", result)
        self.assertIn("reachableSystemInductiveInvariant", result)
        self.assertNotIn("unrelatedRetirementGuarantee", result)
        self.assertEqual(safety_slice("ReconfigurationPreservation", result), result)

    def test_scoped_omission_preserves_doc_and_attributes(self):
        source = "/-- A fact. -/\n@[simp]\nlemma fact (n : Nat) : n = n := by rfl\n"
        fixed = apply_repairs(source, {2: ("fact", ["[DecidableEq Node]"])})
        self.assertEqual(fixed, "omit [DecidableEq Node] in\n" + source)

    def test_stale_diagnostic_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Stale diagnostic"):
            apply_repairs(
                "lemma different : True := trivial\n", {0: ("fact", ["[BEq Node]"])}
            )

    def test_only_selected_proof_is_changed(self):
        target = Path("CCFRaft/Proofs/Target.lean").resolve()
        log = (
            "error: CCFRaft/Proofs/Other.lean:2:0: automatically included section variable(s) unused in theorem `Other.fact`:\n"
            "  [DecidableEq Node]\n"
            "error: CCFRaft/Proofs/Target.lean:4:0: automatically included section variable(s) unused in theorem `Target.fact`:\n"
            "  [DecidableEq Node]\n"
            "  [DecidableEq TxId]\n"
        )
        self.assertEqual(
            repairs(log, target),
            {3: ("fact", ["[DecidableEq Node]", "[DecidableEq TxId]"])},
        )

    def test_existing_omission_is_extended(self):
        source = "omit [DecidableEq Node] in\nlemma fact : True := trivial\n"
        fixed = apply_repairs(source, {1: ("fact", ["[DecidableEq TxId]"])})
        self.assertEqual(
            fixed,
            "omit [DecidableEq Node] [DecidableEq TxId] in\nlemma fact : True := trivial\n",
        )
        self.assertEqual(
            apply_repairs(fixed, {1: ("fact", ["[DecidableEq TxId]"])}), fixed
        )


if __name__ == "__main__":
    unittest.main()
