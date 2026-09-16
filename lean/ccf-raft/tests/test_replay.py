# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Negative wire-contract tests against the actual canonical executable."""

import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE))

from reduction import reduce_trace
from trace_io import read_trace

REPLAYER = PACKAGE / ".lake/build/bin/ccfraft-replay"
FIXTURE = Path(__file__).parent / "fixtures/bootstrap.ndjson"


class CanonicalReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not REPLAYER.is_file():
            raise RuntimeError(
                f"Build the canonical ccfraft-replay target before running {__file__}"
            )

    def replay(self, document):
        return subprocess.run(
            [str(REPLAYER), "-"],
            input=json.dumps(document, sort_keys=True),
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    def bootstrap(self):
        return reduce_trace(read_trace(FIXTURE))

    def test_source_bootstrap_is_accepted(self):
        document = self.bootstrap()
        result = self.replay(document)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(result.stdout),
            {
                "status": "ok",
                "instructions": 10,
                "actions": 3,
                "observations": 7,
            },
        )

    def test_offset_bootstrap_term_is_rejected(self):
        document = self.bootstrap()
        observation = document["instructions"][0]
        self.assertEqual(observation["fields"]["currentTerm"], 2)
        observation["fields"]["currentTerm"] = 1
        result = self.replay(document)
        self.assertEqual(result.returncode, 1)
        self.assertIn("currentTerm: observed 1, canonical 2", result.stderr)

    def test_recorded_pre_vote_mode_is_checked_by_the_model(self):
        records = read_trace(FIXTURE)
        records[-1].value["msg"]["state"]["pre_vote_enabled"] = True
        document = reduce_trace(records)
        self.assertEqual(document["bootstrap"]["pre_vote_enabled"], {"0": False})
        result = self.replay(document)
        self.assertEqual(result.returncode, 1)
        self.assertIn("preVoteEnabled", result.stderr)

    def test_startup_retains_physical_prefix_before_next_signature(self):
        document = reduce_trace(read_trace(FIXTURE.with_name("startup.ndjson")))
        signature = next(
            n
            for n, i in enumerate(document["instructions"])
            if i.get("action") == "signCommittableMessages"
            and i["origin"][0]["rule"] == "write-pre"
        )
        preceding = document["instructions"][signature - 1]
        self.assertEqual(preceding["fields"]["logLength"], 2)
        self.assertEqual(preceding["fields"]["commitIndex"], 2)
        self.assertEqual(preceding["fields"]["currentTerm"], 2)
        result = self.replay(document)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(result.stdout),
            {
                "status": "ok",
                "instructions": 16,
                "actions": 5,
                "observations": 11,
            },
        )
        preceding["fields"]["logLength"] = 0
        negative = self.replay(document)
        self.assertNotEqual(negative.returncode, 0)
        self.assertIn("logLength: observed 0, canonical 2", negative.stderr)

    def test_recorded_signature_marker_must_point_to_a_signature(self):
        records = read_trace(FIXTURE.with_name("startup.ndjson"))
        post_bootstrap_write = next(
            row.value["msg"]
            for row in records
            if row.value.get("msg", {}).get("function") == "replicate"
            and row.value["msg"]["seqno"] == 3
        )
        post_bootstrap_write["state"]["committable_indices"] = [1]
        result = self.replay(reduce_trace(records))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signature-marker", result.stderr)
        self.assertIn("signature", result.stderr)
        self.assertIn("configuration", result.stderr)

    def test_terminal_retirement_and_nomination_match_driver(self):
        document = reduce_trace(
            read_trace(FIXTURE.with_name("terminal_retirement.stdout"))
        )
        result = self.replay(document)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(result.stdout)["instructions"], len(document["instructions"])
        )

    def test_recorded_nomination_destination_is_checked_by_the_model(self):
        records = read_trace(FIXTURE.with_name("terminal_retirement.stdout"))
        nomination = next(
            row.value["msg"]
            for row in records
            if row.value.get("msg", {}).get("function")
            == "step_down_and_nominate_successor"
        )
        nomination["to_node_id"] = nomination["state"]["node_id"]
        negative = self.replay(reduce_trace(records))
        self.assertEqual(negative.returncode, 1)
        self.assertIn(
            "disabled canonical action 'advanceCommitIndexAndProposeVote'",
            negative.stderr,
        )

    def test_callback_property_mutations_are_rejected(self):
        records = read_trace(FIXTURE.with_name("terminal_retirement.stdout"))
        document = reduce_trace(records)
        positive = self.replay(document)
        self.assertEqual(positive.returncode, 0, positive.stderr)
        cases = [
            ("become_follower", "last_idx", 999, "logLength"),
            ("become_follower", "commit_idx", 999, "commitIndex"),
            ("execute_append_entries_sync", "current_view", 999, "currentTerm"),
            ("execute_append_entries_sync", "commit_idx", 999, "commitIndex"),
            ("add_configuration", "current_view", 999, "currentTerm"),
            ("commit", "current_view", 999, "currentTerm"),
            ("commit", "last_idx", 999, "logLength"),
            (
                "execute_append_entries_sync",
                "committable_indices",
                [1],
                "signature-marker",
            ),
        ]
        for function, field, value, diagnostic in cases:
            with self.subTest(function=function, field=field):
                callback = next(
                    i
                    for i in document["instructions"]
                    if i["origin"][0]["function"] == function
                    and i["origin"][0]["rule"]
                    in {"tla-callback-stutter", "receive-follower-post"}
                    and (field == "committable_indices" or diagnostic in i["fields"])
                )
                mutated = copy.deepcopy(records)
                record = next(
                    row for row in mutated if row.line == callback["origin"][0]["line"]
                )
                record.value["msg"]["state"][field] = value
                negative = self.replay(reduce_trace(mutated))
                self.assertNotEqual(negative.returncode, 0)
                self.assertIn(diagnostic, negative.stderr)
                self.assertIn(f":{record.line} [", negative.stderr)

    def test_callback_configuration_cache_entries_are_observed(self):
        records = read_trace(FIXTURE.with_name("terminal_retirement.stdout"))
        document = reduce_trace(records)
        observation = next(
            i
            for i in document["instructions"]
            if i["origin"][0]["rule"] == "callback-configuration"
        )
        record = next(
            row for row in records if row.line == observation["origin"][0]["line"]
        )
        record.value["msg"]["configurations"][0]["nodes"] = {
            "unexpected-node": {"address": ":"}
        }
        negative = self.replay(reduce_trace(records))
        self.assertNotEqual(negative.returncode, 0)
        self.assertIn("callback-configuration", negative.stderr)
        self.assertIn("unexpected-node", negative.stderr)

    def test_callback_committed_prefix_is_independent_observed_evidence(self):
        records = read_trace(FIXTURE.with_name("terminal_retirement.stdout"))
        document = reduce_trace(records)
        observation = next(
            i
            for i in document["instructions"]
            if i["origin"][0]["rule"] == "callback-committed-prefix"
        )
        record = next(
            row for row in records if row.line == observation["origin"][0]["line"]
        )
        # The earlier receive snapshot and commit args remain untouched. Neither
        # establishes that this separate callback reported a valid commit index.
        record.value["msg"]["state"]["commit_idx"] = 999
        negative = self.replay(reduce_trace(records))
        self.assertNotEqual(negative.returncode, 0)
        self.assertIn("callback-committed-prefix", negative.stderr)
        self.assertIn("999", negative.stderr)

    def test_callback_present_retirement_indices_are_observed(self):
        original = read_trace(FIXTURE.with_name("retire_follower.stdout"))
        document = reduce_trace(original)
        positive = self.replay(document)
        self.assertEqual(positive.returncode, 0, positive.stderr)
        for raw, field in (
            ("retirement_idx", "retirementIndex"),
            ("retirement_committable_idx", "retirementCommittableIndex"),
        ):
            with self.subTest(field=field):
                observation = next(
                    i
                    for i in document["instructions"]
                    if i["origin"][0]["rule"] == "tla-callback-stutter"
                    and field in i["fields"]
                )
                records = copy.deepcopy(original)
                record = next(
                    row
                    for row in records
                    if row.line == observation["origin"][0]["line"]
                )
                record.value["msg"]["state"][raw] = 999
                negative = self.replay(reduce_trace(records))
                self.assertNotEqual(negative.returncode, 0)
                self.assertIn("tla-callback-stutter", negative.stderr)
                self.assertIn(field, negative.stderr)

    def test_recorded_missing_bootstrap_prefix_produces_nack(self):
        records = read_trace(FIXTURE)
        records += read_trace(FIXTURE.with_name("configuration_callback.ndjson"))
        records += read_trace(FIXTURE.with_name("missing_prefix_response.ndjson"))
        document = reduce_trace(records)
        packets = [
            i["packet"]
            for i in document["instructions"]
            if i.get("observation") == "message"
        ]
        self.assertTrue(any(p.get("prev_idx") == 2 for p in packets))
        self.assertTrue(
            any(p.get("success") == "FAIL" and p["last_log_idx"] == 0 for p in packets)
        )
        result = self.replay(document)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(result.stdout)["instructions"], len(document["instructions"])
        )

    def test_falsified_observation_is_rejected_with_origin(self):
        document = self.bootstrap()
        document["instructions"][0]["fields"]["currentTerm"] = 999
        result = self.replay(document)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("instruction 1", result.stderr)
        self.assertIn("bootstrap.ndjson:3 [bootstrap]", result.stderr)
        self.assertIn("currentTerm", result.stderr)
        self.assertIn("999", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_erased_index_schema_is_rejected(self):
        document = self.bootstrap()
        document["schema"] = "ccfraft-replay/v1"
        result = self.replay(document)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("physical ledger indices", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_empty_instruction_array_is_rejected(self):
        document = self.bootstrap()
        document["instructions"] = []
        result = self.replay(document)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must not be empty", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_disabled_action_is_rejected_with_origin(self):
        document = self.bootstrap()
        origin = document["instructions"][0]["origin"]
        document["instructions"] = [
            {
                "kind": "action",
                "action": "receive",
                "source": "0",
                "destination": "0",
                "origin": origin,
            }
        ]
        result = self.replay(document)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("disabled canonical action 'receive'", result.stderr)
        self.assertIn("bootstrap.ndjson:3 [bootstrap]", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_drop_checks_and_removes_only_the_sender_queue_head(self):
        document = self.bootstrap()
        document["bootstrap"]["pre_vote_enabled"]["1"] = False
        origin = document["instructions"][0]["origin"]
        configure = {
            "kind": "action",
            "action": "changeConfiguration",
            "source": "0",
            "configuration": ["0", "1"],
            "origin": origin,
        }
        send = {
            "kind": "action",
            "action": "appendEntries",
            "source": "0",
            "destination": "1",
            "batchEnd": 1,
            "origin": origin,
        }
        observe = {
            "kind": "observation",
            "observation": "message",
            "source": "0",
            "destination": "1",
            "occurrence": 0,
            "packet": {"msg": "raft_append_entries", "prev_idx": 0},
            "origin": origin,
        }
        drop = {
            "kind": "action",
            "action": "drop",
            "source": "0",
            "destination": "1",
            "occurrence": 0,
            "origin": origin,
        }
        second = copy.deepcopy(observe)
        second["packet"]["prev_idx"] = 1
        document["instructions"] = [configure, send, send, observe, drop, second, drop]
        positive = self.replay(document)
        self.assertEqual(positive.returncode, 0, positive.stderr)

        document["instructions"] = [configure, send, send, second, drop]
        wrong_head = self.replay(document)
        self.assertEqual(wrong_head.returncode, 1)
        self.assertIn("prev_idx: observed 1, canonical 0", wrong_head.stderr)

        document["instructions"] = [configure, observe, drop]
        empty_queue = self.replay(document)
        self.assertEqual(empty_queue.returncode, 1)
        self.assertIn("no pending packet", empty_queue.stderr)

    def test_malformed_packet_rejected_after_valid_canonical_send(self):
        document = self.bootstrap()
        document["bootstrap"]["pre_vote_enabled"]["1"] = False
        origin = document["instructions"][0]["origin"]
        document["instructions"] = [
            {
                "kind": "action",
                "action": "changeConfiguration",
                "source": "0",
                "configuration": ["0", "1"],
                "origin": origin,
            },
            {
                "kind": "action",
                "action": "appendEntries",
                "source": "0",
                "destination": "1",
                "batchEnd": 1,
                "origin": origin,
            },
            {
                "kind": "observation",
                "observation": "message",
                "source": "0",
                "destination": "1",
                "origin": origin,
                "packet": {"msg": "raft_append_entries", "term": 2},
            },
        ]
        positive = self.replay(document)
        self.assertEqual(positive.returncode, 0, positive.stderr)
        malformed = copy.deepcopy(document)
        malformed["instructions"][-1]["packet"]["term"] = "not-a-term"
        result = self.replay(malformed)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("instruction 3", result.stderr)
        self.assertIn("not-a-term", result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
