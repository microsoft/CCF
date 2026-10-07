# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reduction import Instructions, associate, packet, reduce_trace, state_facts
from run_scenarios import capture, inventory, run_suite
from trace_io import TraceError, parse_ndjson, read_trace

FIXTURE = Path(__file__).parent / "fixtures/bootstrap.ndjson"


def state(**changes):
    result = {
        "node_id": "0",
        "leadership_state": "Leader",
        "membership_state": "Active",
        "current_view": 2,
        "last_idx": 2,
        "commit_idx": 2,
        "pre_vote_enabled": False,
        "committable_indices": [],
    }
    result.update(changes)
    return result


def append_packet(**changes):
    result = {
        "msg": "raft_append_entries",
        "term": 2,
        "prev_idx": 2,
        "idx": 6,
        "prev_term": 2,
        "term_of_idx": 2,
        "leader_commit_idx": 2,
        "contains_new_view": False,
    }
    result.update(changes)
    return result


def trace(*messages):
    records = [record.value for record in read_trace(FIXTURE)]
    records.append({"tag": "raft_trace", "cmd": "dispatch_all"})
    for timestamp, message in enumerate(messages, 20):
        records.append({"tag": "raft_trace", "h_ts": str(timestamp), "msg": message})
    return parse_ndjson([json.dumps(row) for row in records], "fixture.stdout")


def later_actions(document):
    return [
        instruction
        for instruction in document["instructions"]
        if instruction["kind"] == "action"
        and instruction["origin"][0]["rule"] != "bootstrap"
    ]


class ReductionTests(unittest.TestCase):
    def test_vote_response_sends_observe_receive_without_an_extra_action(self):
        records = read_trace(FIXTURE.with_name("vote_responses.ndjson"))
        document = reduce_trace(records)
        events, _ = associate(records)
        responses = [e for e in events if e.function == "send_request_vote_response"]
        self.assertEqual(
            {
                (e.message["packet"]["msg"], e.message["packet"]["vote_granted"])
                for e in responses
            },
            {
                ("raft_request_vote_response", True),
                ("raft_request_pre_vote_response", True),
                ("raft_request_pre_vote_response", False),
            },
        )
        without_responses = reduce_trace(
            [
                r
                for r in records
                if r.value.get("msg", {}).get("function")
                != "send_request_vote_response"
            ]
        )
        self.assertEqual(
            [
                {k: v for k, v in i.items() if k != "origin"}
                for i in document["instructions"]
                if i["kind"] == "action"
            ],
            [
                {k: v for k, v in i.items() if k != "origin"}
                for i in without_responses["instructions"]
                if i["kind"] == "action"
            ],
        )
        for response in responses:
            observations = [
                i
                for i in document["instructions"]
                if i["origin"][0]["line"] == response.record.line
            ]
            self.assertEqual(
                [i["observation"] for i in observations], ["state", "message"]
            )
            self.assertEqual(observations[1]["packet"], packet(response))
            self.assertEqual(observations[1]["selection"], "last")
            self.assertNotIn("omissionReasons", observations[0]["origin"][0])

    def test_vote_response_callback_requires_matching_request(self):
        original = read_trace(FIXTURE.with_name("vote_responses.ndjson"))
        for field, value in (
            ("to_node_id", "unexpected"),
            ("msg", "raft_request_vote_response"),
        ):
            with self.subTest(field=field):
                records = copy.deepcopy(original)
                response = next(
                    r.value["msg"]
                    for r in records
                    if r.value.get("msg", {}).get("function")
                    == "send_request_vote_response"
                )
                if field == "msg":
                    response["packet"][field] = value
                else:
                    response[field] = value
                with self.assertRaisesRegex(
                    TraceError, "vote response does not match request"
                ):
                    reduce_trace(records)

    def test_explicit_nomination_after_commit_is_not_a_terminal_commit(self):
        commit = {
            "function": "commit",
            "state": state(last_idx=3, committable_indices=[3]),
            "args": {"idx": 3},
        }
        nomination = {
            "function": "step_down_and_nominate_successor",
            "state": state(last_idx=3, commit_idx=3),
            "to_node_id": "1",
        }
        records = trace(commit)
        records += parse_ndjson(
            [
                '{"tag":"raft_trace","cmd":"nominate_successor,0"}',
                json.dumps({"tag": "raft_trace", "msg": nomination}),
            ]
        )
        self.assertEqual(
            [action["action"] for action in later_actions(reduce_trace(records))],
            ["advanceCommitIndex", "proposeVote"],
        )
        with self.assertRaisesRegex(TraceError, "terminal-retirement nomination"):
            reduce_trace(trace(commit, nomination))

    def test_state_and_packet_terms_preserve_implementation_numbers(self):
        event = associate(read_trace(FIXTURE))[0][0]
        for value in (0, 1, 2, 4, 999):
            with self.subTest(term=value, field="current_view"):
                event.state["current_view"] = value
                self.assertEqual(state_facts(event)["currentTerm"], value)
            packets = [
                append_packet(term=value, prev_term=value, term_of_idx=value),
                {
                    "msg": "raft_append_entries_response",
                    "term": value,
                    "last_log_idx": 6,
                    "success": "OK",
                },
                {"msg": "raft_propose_request_vote", "term": value},
            ]
            for family in ("raft_request_vote", "raft_request_pre_vote"):
                packets.extend(
                    [
                        {
                            "msg": family,
                            "term": value,
                            "last_committable_idx": 2,
                            "term_of_last_committable_idx": value,
                        },
                        {
                            "msg": f"{family}_response",
                            "term": value,
                            "vote_granted": True,
                        },
                    ]
                )
            for raw in packets:
                with self.subTest(term=value, packet=raw["msg"]):
                    event.message["packet"] = raw
                    self.assertEqual(packet(event), raw)

    def test_state_and_packet_terms_require_natural_numbers(self):
        event = associate(read_trace(FIXTURE))[0][0]
        for value in (-1, True, 1.5, "1", None):
            with self.subTest(term=value, field="current_view"):
                event.state["current_view"] = value
                with self.assertRaisesRegex(TraceError, "expected natural number"):
                    state_facts(event)
            for field in ("term", "prev_term", "term_of_idx"):
                with self.subTest(term=value, field=field):
                    event.message["packet"] = append_packet(**{field: value})
                    with self.assertRaisesRegex(TraceError, "expected natural number"):
                        packet(event)

    def test_capture_order_does_not_depend_on_timestamps(self):
        records = read_trace(FIXTURE)
        expected = reduce_trace(records)
        for record in records:
            record.value.pop("h_ts", None)
        self.assertEqual(reduce_trace(records), expected)

    def test_creation_commands_declare_future_nodes_with_mixed_modes(self):
        records = read_trace(FIXTURE)
        records += parse_ndjson(
            [
                '{"tag":"raft_trace","cmd":"pre_vote_enabled,true"}',
                '{"tag":"raft_trace","cmd":"create_new_node,1"}',
            ]
        )
        events, modes = associate(records)
        self.assertEqual(modes, {"0": False, "1": True})
        self.assertEqual({event.node for event in events}, {"0"})
        self.assertEqual(events[0].command.value["cmd"], "start_node,0")
        self.assertEqual(events[-1].command.value["cmd"], "emit_signature,2")
        self.assertEqual(reduce_trace(records)["bootstrap"]["pre_vote_enabled"], modes)

    def test_write_coordinates_must_match_the_pre_state(self):
        for changes in ({"seqno": 4}, {"view": 3}):
            write = {
                "function": "replicate",
                "state": state(),
                "seqno": 3,
                "view": 2,
                "globally_committable": False,
                **changes,
            }
            with self.subTest(changes=changes), self.assertRaisesRegex(
                TraceError, "write coordinates"
            ):
                reduce_trace(trace(write))

    def test_observations_default_to_every_supplied_property(self):
        reducer = Instructions()
        event = associate(read_trace(FIXTURE))[0][0]
        properties = {"currentTerm": 1, "logLength": 0, "allocated": True}
        reducer.emit_observations(event, "all-properties", properties)
        self.assertEqual(reducer.instructions[-1]["fields"], properties)

        reason = "Observed before the action; this example checks the post-state."
        reducer.emit_observations(
            event, "explicit-exclusion", properties, exclusions={"logLength": reason}
        )
        observation = reducer.instructions[-1]
        self.assertEqual(observation["fields"], {"currentTerm": 1, "allocated": True})
        self.assertEqual(
            observation["origin"][0]["omittedTransientFields"], {"logLength": 0}
        )
        self.assertEqual(
            observation["origin"][0]["omissionReasons"], {"logLength": reason}
        )
        self.assertEqual(observation["origin"][0]["rawRecord"], event.record.value)

    def test_observation_exclusions_require_known_names_and_reasons(self):
        reducer = Instructions()
        event = associate(read_trace(FIXTURE))[0][0]
        for reason in ("", " ", None):
            with self.subTest(reason=reason), self.assertRaisesRegex(
                TraceError, "requires a reason"
            ):
                reducer.emit_observations(
                    event, "invalid-exclusion", exclusions={"logLength": reason}
                )
        with self.assertRaisesRegex(TraceError, "unknown properties"):
            reducer.emit_observations(
                event, "invalid-exclusion", exclusions={"logLenght": "Typo"}
            )
        self.assertEqual(reducer.instructions, [])

    def test_empty_observations_and_origin_overrides_are_rejected(self):
        reducer = Instructions()
        event = associate(read_trace(FIXTURE))[0][0]
        for properties, exclusions in (
            ({}, {}),
            ({"logLength": 0}, {"logLength": "Checked at the pre-state"}),
        ):
            with self.subTest(properties=properties), self.assertRaisesRegex(
                TraceError, "no state properties"
            ):
                reducer.emit_observations(
                    event, "empty", properties, exclusions=exclusions
                )
        with self.assertRaises(TypeError):
            reducer.emit_observations(event, "override", origin=[])
        self.assertEqual(reducer.instructions, [])

    def test_callback_observes_new_properties_by_default(self):
        records = read_trace(FIXTURE.with_name("retire_follower.stdout"))
        with patch(
            "reduction.state_facts",
            side_effect=lambda event: {**state_facts(event), "allocated": True},
        ):
            document = reduce_trace(records)
        observation = next(
            i
            for i in document["instructions"]
            if i["origin"][0]["rule"] == "tla-callback-stutter"
        )
        event = next(
            e
            for e in associate(records)[0]
            if e.record.line == observation["origin"][0]["line"]
        )
        properties = {**state_facts(event), "allocated": True}
        self.assertTrue(observation["fields"]["allocated"])
        self.assertEqual(
            set(observation["origin"][0]["omissionReasons"]),
            set(properties) - set(observation["fields"]) - {"committableIndices"},
        )

    def test_receive_follower_boundary_is_observed_after_the_receive(self):
        records = read_trace(FIXTURE)
        records += read_trace(FIXTURE.with_name("configuration_callback.ndjson"))
        records += read_trace(FIXTURE.with_name("missing_prefix_response.ndjson"))
        events, _ = associate(records)
        event = next(e for e in events if e.function == "become_follower")
        document = reduce_trace(records)
        position, observation = next(
            (position, i)
            for position, i in enumerate(document["instructions"])
            if i["origin"][0]["rule"] == "receive-follower-post"
        )
        facts = state_facts(event)
        self.assertEqual(
            observation["fields"],
            {k: facts[k] for k in ("role", "currentTerm")},
        )
        self.assertEqual(
            set(observation["origin"][0]["omissionReasons"]),
            set(facts) - {"role", "currentTerm"},
        )
        # The term update and the handling are one receive, before the observation.
        receive = document["instructions"][position - 1]
        self.assertEqual(receive["action"], "receive")
        self.assertIn("become_follower", [o["function"] for o in receive["origin"]])
        self.assertEqual(
            [
                i["action"]
                for i in document["instructions"]
                if i.get("action") in {"receive", "updateTerm"}
            ],
            ["receive", "receive"],
        )
        # A same-term candidate also steps down inside the one receive.
        packet = next(e for e in events if e.function == "recv_append_entries")
        packet.state.update(current_view=2, leadership_state="Candidate")
        same_term = reduce_trace(records)
        self.assertEqual(
            [
                i["action"]
                for i in same_term["instructions"]
                if i.get("action") in {"receive", "updateTerm"}
            ],
            ["receive", "receive"],
        )

    def test_exact_source_bootstrap(self):
        result = reduce_trace(read_trace(FIXTURE))
        self.assertEqual(result["bootstrap"]["configuration"], ["0"])
        self.assertEqual(len(result["instructions"]), 10)
        observed = [
            i["fields"]
            for i in result["instructions"]
            if i.get("observation") == "state"
        ]
        self.assertEqual(
            [f["currentTerm"] for f in observed if "currentTerm" in f], [2] * 5
        )
        self.assertEqual(
            [f["logLength"] for f in observed if "logLength" in f], [0, 0, 0, 1, 2]
        )
        self.assertEqual([f["commitIndex"] for f in observed], [0, 0, 0, 0, 0, 2])
        self.assertEqual(
            [i["action"] for i in result["instructions"] if i["kind"] == "action"],
            [
                "initializeConfiguration",
                "signCommittableMessages",
                "advanceCommitIndex",
            ],
        )
        markers = [
            i
            for i in result["instructions"]
            if i["origin"][0]["rule"] == "signature-marker"
        ]
        self.assertEqual([i["index"] for i in markers], [2])
        self.assertEqual(markers[0]["fields"], {"kind": "signature"})
        self.assertEqual(observed[-2]["configurations"], [{"index": 1, "nodes": ["0"]}])
        self.assertEqual(result["instructions"][-1]["origin"][0]["line"], 9)

    def test_recorded_signature_cache_is_not_complete_log_enumeration(self):
        write = {
            "function": "replicate",
            "state": state(last_idx=5, committable_indices=[3, 5]),
            "seqno": 6,
            "view": 2,
            "globally_committable": True,
        }
        instructions = reduce_trace(trace(write))["instructions"]
        markers = [
            i["index"]
            for i in instructions
            if i["origin"][0]["rule"] == "signature-marker"
        ]
        self.assertEqual(markers, [2, 3, 5])
        self.assertTrue(
            all(
                "committableIndices" not in i["fields"]
                for i in instructions
                if i.get("observation") == "state"
            )
        )

    def test_bootstrap_mutation_rejected(self):
        records = read_trace(FIXTURE)
        records[-1].value["msg"]["args"]["idx"] = 3
        with self.assertRaisesRegex(TraceError, "bootstrap commit target"):
            reduce_trace(records)

    def test_unknown_event_state_and_command_rejected(self):
        for message, expected in (
            ({"function": "new_function", "state": state()}, "unsupported function"),
            (
                {
                    "function": "replicate",
                    "state": state(secret_state=1),
                    "seqno": 3,
                    "view": 2,
                    "globally_committable": False,
                },
                "unsupported state",
            ),
        ):
            with self.subTest(expected=expected), self.assertRaisesRegex(
                TraceError, expected
            ):
                reduce_trace(trace(message))
        records = read_trace(FIXTURE)
        records[0].value["cmd"] = "new_command,0"
        with self.assertRaisesRegex(TraceError, "unsupported command"):
            reduce_trace(records)

    def test_unknown_trace_record_rejected(self):
        records = read_trace(FIXTURE)
        records += parse_ndjson(['{"tag":"raft_trace","h_ts":"20","future_record":{}}'])
        with self.assertRaisesRegex(TraceError, "unknown record fields"):
            reduce_trace(records)

    def test_malformed_packet_coordinate_rejected(self):
        send = {
            "function": "send_append_entries",
            "state": state(last_idx=6),
            "to_node_id": "1",
            "packet": append_packet(term="not-a-term"),
        }
        with self.assertRaisesRegex(TraceError, "expected natural number"):
            reduce_trace(trace(send))
        records = trace(
            {
                "function": "send_append_entries",
                "state": state(),
                "to_node_id": "1",
                "packet": append_packet(new_field=1),
            }
        )
        with self.assertRaisesRegex(TraceError, "packet fields"):
            reduce_trace(records)

    def test_atomic_batch_drop_resend_preserves_occurrences(self):
        send = {
            "function": "send_append_entries",
            "state": state(last_idx=6),
            "to_node_id": "1",
            "packet": append_packet(),
            "sent_idx": 2,
            "match_idx": 0,
        }
        drop = {
            "function": "drop_pending_to",
            "state": state(last_idx=6),
            "from_node_id": "0",
            "to_node_id": "1",
            "packet": append_packet(),
        }
        result = reduce_trace(trace(send, drop, copy.deepcopy(send)))
        actions = later_actions(result)
        self.assertEqual(
            [i["action"] for i in actions], ["appendEntries", "drop", "appendEntries"]
        )
        self.assertEqual([i["batchEnd"] for i in actions if "batchEnd" in i], [6, 6])
        drop_index = next(
            i
            for i, item in enumerate(result["instructions"])
            if item.get("action") == "drop"
        )
        observed = result["instructions"][drop_index - 1]
        self.assertEqual(observed["observation"], "message")
        self.assertEqual(observed["packet"]["idx"], 6)
        self.assertEqual(observed["packet"]["prev_idx"], 2)
        self.assertEqual(observed["packet"]["prev_term"], 2)
        self.assertNotEqual(actions[0]["origin"], actions[-1]["origin"])

    def test_receive_transient_facts_are_explicitly_audited(self):
        send = {
            "function": "send_append_entries",
            "state": state(last_idx=6),
            "to_node_id": "1",
            "packet": append_packet(),
        }
        receive = {
            "function": "recv_append_entries",
            "state": state(node_id="1", leadership_state="Follower", last_idx=2),
            "from_node_id": "0",
            "packet": append_packet(),
        }
        helper = {
            "function": "execute_append_entries_sync",
            "state": state(node_id="1", leadership_state="Follower", last_idx=3),
            "from_node_id": "0",
        }
        first_helper = copy.deepcopy(helper)
        first_helper["state"]["last_idx"] = 2
        response = {
            "function": "send_append_entries_response",
            "state": state(node_id="1", leadership_state="Follower", last_idx=6),
            "to_node_id": "0",
            "packet": {
                "msg": "raft_append_entries_response",
                "term": 2,
                "last_log_idx": 6,
                "success": "OK",
            },
        }
        result = reduce_trace(trace(send, receive, first_helper, helper, response))
        callbacks = [
            i
            for i in result["instructions"]
            if i["origin"][0]["rule"] == "tla-callback-stutter"
        ]
        self.assertEqual(len(callbacks), 2)
        self.assertEqual(
            callbacks[-1]["origin"][0]["omittedTransientFields"]["logLength"], 3
        )
        self.assertEqual(
            callbacks[-1]["origin"][0]["rawRecord"]["msg"]["state"]["last_idx"], 3
        )
        self.assertEqual(
            set(callbacks[-1]["fields"]),
            {
                "currentTerm",
                "preVoteEnabled",
                "commitIndex",
                "role",
                "retirementIndex",
                "retiredCommittedIndex",
            },
        )
        self.assertEqual(callbacks[-1]["fields"]["role"], "follower")
        self.assertEqual(callbacks[-1]["fields"]["retirementIndex"], None)
        self.assertIn(
            "pending entry",
            callbacks[-1]["origin"][0]["omissionReasons"]["retirementCommittableIndex"],
        )
        self.assertEqual(
            set(callbacks[-1]["origin"][0]["omissionReasons"]),
            set(callbacks[-1]["origin"][0]["omittedTransientFields"]),
        )
        helper["state"]["leadership_state"] = "Leader"
        with self.assertRaisesRegex(TraceError, "callback requires follower"):
            reduce_trace(trace(send, receive, first_helper, helper, response))

    def test_commit_callback_observes_stable_fields_and_log_entries(self):
        request = append_packet(prev_idx=4, idx=4, leader_commit_idx=4)
        send = {
            "function": "send_append_entries",
            "state": state(last_idx=4, commit_idx=4),
            "to_node_id": "1",
            "packet": request,
        }
        before = state(
            node_id="1",
            leadership_state="Follower",
            last_idx=4,
            committable_indices=[4],
        )
        receive = {
            "function": "recv_append_entries",
            "state": before,
            "from_node_id": "0",
            "packet": request,
        }
        commit = {
            "function": "commit",
            "state": before,
            "args": {"idx": 4},
            "configurations": [
                {"idx": 1, "rid": 1, "nodes": {"0": {"address": ":"}}},
                {
                    "idx": 3,
                    "rid": 3,
                    "nodes": {"0": {"address": ":"}, "1": {"address": ":"}},
                },
            ],
        }
        response = {
            "function": "send_append_entries_response",
            "state": state(
                node_id="1", leadership_state="Follower", last_idx=4, commit_idx=4
            ),
            "to_node_id": "0",
            "packet": {
                "msg": "raft_append_entries_response",
                "term": 2,
                "last_log_idx": 4,
                "success": "OK",
            },
        }
        instructions = reduce_trace(trace(send, receive, commit, response))[
            "instructions"
        ]
        receive_index = next(
            i
            for i, value in enumerate(instructions)
            if value.get("action") == "receive"
        )
        callback_index = next(
            i
            for i, value in enumerate(instructions)
            if value["origin"][0]["rule"] == "tla-callback-stutter"
        )
        self.assertGreater(callback_index, receive_index)
        self.assertEqual(
            set(instructions[callback_index]["fields"]),
            {
                "currentTerm",
                "logLength",
                "preVoteEnabled",
                "retirementIndex",
                "retirementCommittableIndex",
            },
        )
        observed_configurations = [
            i
            for i in instructions
            if i["origin"][0]["rule"] == "callback-configuration"
        ]
        self.assertEqual([i["index"] for i in observed_configurations], [1, 3])
        self.assertEqual(
            observed_configurations[1]["fields"],
            {"kind": "configuration", "configuration": ["0", "1"]},
        )
        prefix = next(
            i
            for i in instructions
            if i["origin"][0]["rule"] == "callback-committed-prefix"
        )
        self.assertEqual(prefix["index"], 2)
        self.assertEqual(prefix["fields"], {"kind": "signature", "committed": True})
        self.assertTrue(
            any(
                i.get("index") == 4
                and i["origin"][0]["rule"] == "signature-marker"
                and i["origin"][0]["function"] == "commit"
                for i in instructions
            )
        )
        entry = next(
            i for i in instructions if i["origin"][0]["rule"] == "callback-entry"
        )
        self.assertEqual(entry["index"], 4)
        self.assertEqual(entry["fields"], {"kind": "signature", "committed": True})
        response_state = next(
            i
            for i in instructions[receive_index + 1 :]
            if i.get("observation") == "state"
            and i["origin"][0]["function"] == "send_append_entries_response"
        )
        self.assertEqual(response_state["fields"]["role"], "follower")
        self.assertEqual(response_state["fields"]["currentTerm"], 2)
        self.assertEqual(response_state["fields"]["logLength"], 4)
        self.assertEqual(response_state["fields"]["commitIndex"], 4)

    def test_callback_boundary_does_not_depend_on_observed_values(self):
        request = append_packet(prev_idx=2, idx=3)
        send = {
            "function": "send_append_entries",
            "state": state(last_idx=3),
            "to_node_id": "1",
            "packet": request,
        }
        receive = {
            "function": "recv_append_entries",
            "state": state(node_id="1", leadership_state="Follower"),
            "from_node_id": "0",
            "packet": request,
        }
        helper = {
            "function": "execute_append_entries_sync",
            "state": state(node_id="1", leadership_state="Follower"),
            "from_node_id": "0",
        }
        response = {
            "function": "send_append_entries_response",
            "state": state(node_id="1", leadership_state="Follower", last_idx=3),
            "to_node_id": "0",
            "packet": {
                "msg": "raft_append_entries_response",
                "term": 2,
                "last_log_idx": 3,
                "success": "OK",
            },
        }
        positive = reduce_trace(trace(send, receive, helper, response))
        helper["state"]["last_idx"] = 3
        mutated = reduce_trace(trace(send, receive, helper, response))

        def boundaries(document):
            return [
                (
                    i["kind"],
                    i.get("action"),
                    i["origin"][0]["rule"],
                    sorted(i.get("fields", {})),
                )
                for i in document["instructions"]
            ]

        self.assertEqual(boundaries(positive), boundaries(mutated))
        callback = next(
            i
            for i in mutated["instructions"]
            if i["origin"][0]["rule"] == "tla-callback-stutter"
        )
        self.assertNotIn("logLength", callback["fields"])
        self.assertEqual(
            callback["origin"][0]["omittedTransientFields"]["logLength"], 3
        )
        self.assertGreater(
            mutated["instructions"].index(callback),
            next(
                n
                for n, i in enumerate(mutated["instructions"])
                if i.get("action") == "receive"
            ),
        )

    def test_drop_does_not_search_for_a_later_matching_packet(self):
        first = {
            "function": "send_append_entries",
            "state": state(last_idx=6),
            "to_node_id": "1",
            "packet": append_packet(idx=4),
        }
        second = {
            "function": "send_append_entries",
            "state": state(last_idx=6),
            "to_node_id": "1",
            "packet": append_packet(),
        }
        drop = {
            "function": "drop_pending_to",
            "state": state(last_idx=6),
            "from_node_id": "0",
            "to_node_id": "1",
            "packet": append_packet(),
        }
        result = reduce_trace(trace(first, second, drop))
        action = next(i for i in result["instructions"] if i.get("action") == "drop")
        self.assertEqual(action["occurrence"], 0)
        observation = result["instructions"][result["instructions"].index(action) - 1]
        self.assertEqual(observation["occurrence"], 0)
        self.assertEqual(observation["packet"]["idx"], 6)

    def test_receive_emits_a_canonical_head_observation_without_a_python_queue(self):
        first = {
            "function": "send_append_entries",
            "state": state(last_idx=6),
            "to_node_id": "1",
            "packet": append_packet(idx=4),
        }
        second = copy.deepcopy(first)
        second["packet"] = append_packet(idx=6)
        receive = {
            "function": "recv_append_entries",
            "state": state(node_id="1", leadership_state="Follower"),
            "from_node_id": "0",
            "packet": second["packet"],
        }
        for messages in ((receive,), (first, second, receive)):
            with self.subTest(messages=len(messages)):
                instructions = reduce_trace(trace(*messages))["instructions"]
                head = next(
                    i
                    for i in instructions
                    if i.get("observation") == "message"
                    and i["origin"][0]["rule"] == "receive-pre"
                )
                self.assertEqual(head.get("occurrence", 0), 0)
                self.assertEqual(head["packet"]["idx"], 6)

    def test_drop_queue_existence_is_checked_by_replay(self):
        drop = {
            "function": "drop_pending_to",
            "state": state(last_idx=6),
            "from_node_id": "0",
            "to_node_id": "1",
            "packet": append_packet(),
        }
        instructions = reduce_trace(trace(drop))["instructions"]
        self.assertEqual(instructions[-1]["action"], "drop")
        self.assertEqual(instructions[-1]["occurrence"], 0)
        self.assertEqual(instructions[-2]["observation"], "message")

    def test_source_configuration_callback_keeps_log_and_peer_facts(self):
        records = read_trace(FIXTURE)
        records += read_trace(FIXTURE.with_name("configuration_callback.ndjson"))
        result = reduce_trace(records)
        callback = [
            i
            for i in result["instructions"]
            if i["origin"][0]["function"] == "send_append_entries"
        ]
        self.assertEqual(callback[0]["fields"]["logLength"], 2)
        peer = next(
            i
            for i in callback
            if i["origin"][0]["rule"] == "configuration-callback-peer"
        )
        send = next(i for i in callback if i.get("action") == "appendEntries")
        self.assertEqual(peer["fields"], {"sentIndex": 2, "matchIndex": 0})
        self.assertEqual(send["batchEnd"], 2)
        change_index = next(
            i
            for i, item in enumerate(result["instructions"])
            if item.get("action") == "changeConfiguration"
        )
        self.assertLess(result["instructions"].index(callback[0]), change_index)
        self.assertGreater(result["instructions"].index(peer), change_index)
        membership = next(
            i
            for i in callback
            if i["origin"][0]["rule"] == "configuration-callback-post"
        )
        self.assertEqual(membership["fields"]["membershipState"], "active")
        self.assertGreater(result["instructions"].index(membership), change_index)
        self.assertEqual(
            result["bootstrap"]["pre_vote_enabled"], {"0": False, "1": False}
        )

    def test_missing_configuration_snapshot_is_a_trace_error(self):
        records = read_trace(FIXTURE)
        callbacks = read_trace(FIXTURE.with_name("configuration_callback.ndjson"))
        config = next(
            row.value["msg"]
            for row in callbacks
            if row.value.get("msg", {}).get("function") == "add_configuration"
        )
        del config["configurations"]
        with self.assertRaisesRegex(TraceError, "missing configurations"):
            reduce_trace(records + callbacks)

    def test_configuration_prefix_requires_all_new_peer_heartbeats(self):
        records = read_trace(FIXTURE)
        callbacks = read_trace(FIXTURE.with_name("configuration_callback.ndjson"))
        callbacks = [
            row
            for row in callbacks
            if row.value.get("msg", {}).get("function") != "send_append_entries"
        ]
        with self.assertRaisesRegex(
            TraceError, "missing new-peer configuration callback"
        ):
            reduce_trace(records + callbacks)

    def test_unmatched_callback_is_not_silently_consumed(self):
        callback = {
            "function": "execute_append_entries_sync",
            "state": state(node_id="1", leadership_state="Follower"),
            "from_node_id": "0",
        }
        with self.assertRaisesRegex(
            TraceError, "ungrouped callback execute_append_entries_sync"
        ):
            reduce_trace(trace(callback))

    def test_terminal_commit_includes_its_nomination_once(self):
        fixture = FIXTURE.with_name("terminal_retirement.stdout")
        document = reduce_trace(read_trace(fixture))
        combined = [
            i
            for i in document["instructions"]
            if i.get("action") == "advanceCommitIndexAndProposeVote"
        ]
        self.assertEqual(len(combined), 1)
        self.assertEqual(
            (combined[0]["source"], combined[0]["destination"]), ("0", "1")
        )
        self.assertFalse(
            any(i.get("action") == "proposeVote" for i in document["instructions"])
        )
        before = next(
            i
            for i in document["instructions"]
            if i["origin"][0]["rule"] == "terminal-nomination-pre"
        )
        after = next(
            i
            for i in document["instructions"]
            if i["origin"][0]["rule"] == "terminal-nomination-post"
        )
        self.assertEqual(
            {
                k: before["origin"][0]["omittedTransientFields"][k]
                for k in ("role", "membershipState")
            },
            {
                "role": "leader",
                "membershipState": "retirementCompleted",
            },
        )
        self.assertNotIn("role", before["fields"])
        self.assertEqual(after["fields"]["commitIndex"], 6)
        self.assertEqual(after["fields"]["retiredCommittedIndex"], 6)
        records = read_trace(fixture)
        nomination = next(
            row.value["msg"]
            for row in records
            if row.value.get("msg", {}).get("function")
            == "step_down_and_nominate_successor"
        )
        nomination["state"]["leadership_state"] = "Follower"
        with self.assertRaisesRegex(
            TraceError, "terminal-retirement nomination boundary"
        ):
            reduce_trace(records)

    def test_configuration_rid_requires_a_natural_number(self):
        records = read_trace(FIXTURE)
        config = next(
            row.value["msg"]["args"]["configuration"]
            for row in records
            if row.value.get("msg", {}).get("function") == "add_configuration"
        )
        config["rid"] = True
        with self.assertRaisesRegex(TraceError, "configuration.rid"):
            reduce_trace(records)

    def test_invalid_response_verdict_is_a_trace_error(self):
        receive = {
            "function": "recv_append_entries",
            "state": state(node_id="1", leadership_state="Follower"),
            "from_node_id": "0",
            "packet": append_packet(idx=2),
        }
        response = {
            "function": "send_append_entries_response",
            "state": state(node_id="1", leadership_state="Follower"),
            "to_node_id": "0",
            "packet": {
                "msg": "raft_append_entries_response",
                "term": 2,
                "last_log_idx": 2,
                "success": [],
            },
        }
        with self.assertRaisesRegex(TraceError, "response success"):
            reduce_trace(trace(receive, response))

    def test_packets_are_validated_without_correlation(self):
        for function in ("drop_pending_to", "recv_propose_request_vote"):
            for malformed in (None, {"msg": "raft_propose_request_vote", "term": []}):
                event = {
                    "function": function,
                    "state": state(),
                    "from_node_id": "0",
                    "packet": malformed,
                }
                if function == "drop_pending_to":
                    event["to_node_id"] = "1"
                with self.subTest(
                    function=function, packet=malformed
                ), self.assertRaises(TraceError):
                    reduce_trace(trace(event))

    def test_historical_drop_resend_packet_rules(self):
        records = read_trace(FIXTURE)
        records += read_trace(FIXTURE.with_name("drop_resend.ndjson"))
        result = reduce_trace(records)
        actions = later_actions(result)
        self.assertEqual(
            [i["action"] for i in actions],
            ["appendEntries", "drop", "appendEntries", "receive"],
        )
        self.assertEqual([i["origin"][0]["line"] for i in actions], [2, 4, 6, 8])
        self.assertEqual(actions[1]["occurrence"], 0)
        requests = [
            i["packet"]
            for i in result["instructions"]
            if i.get("observation") == "message"
            and i["packet"]["msg"] == "raft_append_entries"
        ]
        self.assertEqual(len(requests), 4)
        self.assertTrue(all(request == requests[0] for request in requests))
        self.assertEqual(requests[0]["idx"], 10)
        self.assertEqual(requests[0]["prev_idx"], 10)
        self.assertEqual(requests[0]["leader_commit_idx"], 8)

    def test_newer_nomination_does_not_update_term_or_force_election(self):
        nomination = {
            "function": "step_down_and_nominate_successor",
            "state": state(current_view=4),
            "to_node_id": "1",
        }
        receive = {
            "function": "recv_propose_request_vote",
            "state": state(node_id="1", leadership_state="Follower"),
            "from_node_id": "0",
            "packet": {"msg": "raft_propose_request_vote", "term": 4},
        }
        result = reduce_trace(trace(nomination, receive))
        actions = [i["action"] for i in later_actions(result)]
        self.assertEqual(actions, ["proposeVote", "receive"])

    def test_nomination_uses_recorded_destination_without_future_evidence(self):
        nomination = {
            "function": "step_down_and_nominate_successor",
            "state": state(),
            "to_node_id": "1",
        }
        actions = later_actions(reduce_trace(trace(nomination, nomination)))
        self.assertEqual([i["action"] for i in actions], ["proposeVote", "proposeVote"])
        self.assertEqual([i["destination"] for i in actions], ["1", "1"])
        self.assertTrue(all(len(i["origin"]) == 1 for i in actions))
        del nomination["to_node_id"]
        with self.assertRaisesRegex(TraceError, "missing nomination destination"):
            reduce_trace(trace(nomination))

    def test_shuffle_commands_are_unsupported(self):
        for command in ("shuffle_one,0", "shuffle_all"):
            records = read_trace(FIXTURE) + parse_ndjson(
                [json.dumps({"tag": "raft_trace", "cmd": command})]
            )
            with self.subTest(command=command), self.assertRaisesRegex(
                TraceError, "unsupported command"
            ):
                reduce_trace(records)

    def test_no_actions_invented_for_assertion_commands(self):
        records = read_trace(FIXTURE)
        records += parse_ndjson(['{"tag":"raft_trace","cmd":"assert_commit_idx,0,2"}'])
        self.assertEqual(later_actions(reduce_trace(records)), [])

    def test_deterministic_serialization(self):
        self.assertEqual(
            json.dumps(reduce_trace(read_trace(FIXTURE)), sort_keys=True),
            json.dumps(reduce_trace(read_trace(FIXTURE)), sort_keys=True),
        )


class InputTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch("run_scenarios.print", create=True))

    def test_malformed_nomination_packets_do_not_abort_the_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scenarios, raw = root / "scenarios", root / "raw"
            scenarios.mkdir()
            raw.mkdir()
            for name, malformed in (
                ("a", None),
                ("b", {"msg": "raft_propose_request_vote", "term": []}),
            ):
                (scenarios / name).write_text("scenario\n")
                records = trace(
                    {
                        "function": "drop_pending_to",
                        "state": state(),
                        "from_node_id": "0",
                        "to_node_id": "1",
                        "packet": malformed,
                    }
                )
                (raw / f"{name}.stdout").write_text(
                    "".join(json.dumps(record.value) + "\n" for record in records)
                )
            with patch("run_scenarios.subprocess.run") as replayer:
                summary = run_suite(
                    None, root / "replayer", scenarios, root / "out", raw_directory=raw
                )
            replayer.assert_not_called()
            self.assertEqual((summary["selected"], summary["failed"]), (2, 2))
            for result in summary["results"]:
                self.assertEqual(result["stage"], "reduction")
                self.assertIn(str(raw), result["error"])

    def test_invalid_inventory_removes_stale_success_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scenarios, output = root / "scenarios", root / "out"
            scenarios.mkdir()
            output.mkdir()
            summary = output / "summary.json"
            summary.write_text('{"passed":53,"failed":0}\n')
            with self.assertRaisesRegex(TraceError, "empty scenario inventory"):
                run_suite(root / "driver", root / "replayer", scenarios, output)
            self.assertFalse(summary.exists())

    def test_interrupted_suite_cannot_reuse_an_old_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scenarios, output = root / "scenarios", root / "out"
            scenarios.mkdir()
            output.mkdir()
            (scenarios / "a").write_text("scenario\n")
            summary = output / "summary.json"
            summary.write_text('{"passed":53,"failed":0}\n')
            with patch(
                "run_scenarios.capture", side_effect=KeyboardInterrupt
            ), self.assertRaises(KeyboardInterrupt):
                run_suite(root / "driver", root / "replayer", scenarios, output)
            self.assertFalse(summary.exists())

    def test_file_provenance_does_not_depend_on_replay_working_directory(self):
        relative = Path(os.path.relpath(FIXTURE))
        records = read_trace(relative)
        self.assertEqual(records[0].file, str(FIXTURE.resolve()))

    def test_invalid_encoding_does_not_abort_the_corpus(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scenarios, raw = root / "scenarios", root / "raw"
            scenarios.mkdir()
            raw.mkdir()
            for name in ("a", "b"):
                (scenarios / name).write_text("scenario\n")
                (raw / f"{name}.stdout").write_bytes(b"\xff\n")
            summary = run_suite(
                None, root / "replayer", scenarios, root / "out", raw_directory=raw
            )
            self.assertEqual((summary["selected"], summary["failed"]), (2, 2))
            for result in summary["results"]:
                self.assertIn("invalid UTF-8", result["error"])

    def test_empty_scenario_inventory_cannot_succeed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scenarios = root / "scenarios"
            scenarios.mkdir()
            with patch("run_scenarios.capture") as capture_mock, self.assertRaisesRegex(
                TraceError, "empty scenario inventory"
            ):
                run_suite(root / "driver", root / "replayer", scenarios, root / "out")
            capture_mock.assert_not_called()
            self.assertFalse((root / "out/summary.json").exists())

    def test_empty_raw_corpus_cannot_succeed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scenarios = root / "scenarios"
            raw = root / "raw"
            scenarios.mkdir()
            raw.mkdir()
            for name in ("a", "b"):
                (scenarios / name).write_text("scenario\n")
            with patch("run_scenarios.subprocess.run") as replay_mock:
                summary = run_suite(
                    None, root / "replayer", scenarios, root / "out", raw_directory=raw
                )
            replay_mock.assert_not_called()
            self.assertEqual(
                (summary["selected"], summary["passed"], summary["failed"]), (2, 0, 2)
            )

    def test_strict_ndjson(self):
        for text in ("", "\n", "[]", '{"x":1,"x":2}', '{"x":NaN}', '{"x":1e9999}'):
            with self.subTest(text=text), self.assertRaises(TraceError):
                parse_ndjson(text.splitlines(keepends=True))

    def test_capture_preserves_stdout_and_original_line_numbers(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            script = directory / "fake_driver_input.py"
            output = directory / "capture.stdout"
            content = b"<RaftDriver> diagram\r\n" + FIXTURE.read_bytes()
            script.write_text(f"import sys\nsys.stdout.buffer.write({content!r})\n")
            capture(Path(sys.executable), script, output)
            self.assertEqual(output.read_bytes(), content)
            records = read_trace(output)
            self.assertEqual(records[0].line, 2)
            self.assertEqual(records[-1].line, 10)
            self.assertEqual(records[-1].file, str(output))

    def test_empty_capture_is_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scenarios = root / "scenarios"
            scenarios.mkdir()
            script = scenarios / "empty.py"
            script.write_text("pass\n")
            summary = run_suite(
                Path(sys.executable), root / "replayer", scenarios, root / "out"
            )
            self.assertEqual(summary["failed"], 1)
            self.assertEqual(summary["results"][0]["stage"], "reduction")
            self.assertIn("no Raft events", summary["results"][0]["error"])

    def test_capture_retains_output_on_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "driver.py"
            script.write_text(
                "import sys\nprint('partial trace')\n"
                "print('driver error', file=sys.stderr)\nsys.exit(3)\n"
            )
            output = root / "capture.stdout"
            with self.assertRaisesRegex(TraceError, "exited 3"):
                capture(Path(sys.executable), script, output)
            self.assertEqual(output.read_text(), "partial trace\n")
            self.assertEqual(
                output.with_suffix(".stderr").read_text(), "driver error\n"
            )

    def test_capture_timeout_retains_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "capture.stdout"

            def timeout(*args, **kwargs):
                kwargs["stdout"].write(b"partial trace\n")
                kwargs["stderr"].write(b"partial error\n")
                raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

            with patch(
                "run_scenarios.subprocess.run", side_effect=timeout
            ), self.assertRaisesRegex(TraceError, "exceeded 5s"):
                capture(root / "driver", root / "scenario", output, timeout=5)
            self.assertEqual(output.read_bytes(), b"partial trace\n")
            self.assertEqual(
                output.with_suffix(".stderr").read_bytes(), b"partial error\n"
            )

    def test_driver_stderr_is_an_issue_even_with_zero_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "driver.py"
            script.write_text(
                "import sys\n"
                f"sys.stdout.buffer.write({FIXTURE.read_bytes()!r})\n"
                "print('driver issue', file=sys.stderr)\n"
            )
            output = root / "capture.stdout"
            with self.assertRaisesRegex(TraceError, "wrote to stderr"):
                capture(Path(sys.executable), script, output)
            self.assertEqual(
                output.with_suffix(".stderr").read_text(), "driver issue\n"
            )

    def test_inventory_includes_extensionless_dotted_and_nested_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "nested").mkdir()
            for name in ("startup", "suffix_collision.1", "nested/input"):
                (root / name).write_text("scenario\n")
            self.assertEqual(
                [str(p.relative_to(root)) for p in inventory(root)],
                ["nested/input", "startup", "suffix_collision.1"],
            )

    def test_suite_attempts_every_failure_and_returns_failure_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scenarios = root / "scenarios"
            scenarios.mkdir()
            for name in ("a", "b.1"):
                (scenarios / name).write_text("scenario\n")
            with patch(
                "run_scenarios.capture", side_effect=TraceError("driver unavailable")
            ) as mocked:
                summary = run_suite(
                    root / "driver", root / "replayer", scenarios, root / "out"
                )
            self.assertEqual(mocked.call_count, 2)
            self.assertEqual(
                (summary["selected"], summary["passed"], summary["failed"]), (2, 0, 2)
            )
            self.assertTrue((root / "out/summary.json").is_file())

    def test_suite_rejects_empty_success_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scenarios = root / "scenarios"
            scenarios.mkdir()
            (scenarios / "a").write_text("scenario\n")

            def fake_capture(driver, scenario, output, timeout):
                output.write_bytes(FIXTURE.read_bytes())

            with patch("run_scenarios.capture", side_effect=fake_capture), patch(
                "run_scenarios.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0),
            ):
                summary = run_suite(
                    root / "driver", root / "replayer", scenarios, root / "out"
                )
            self.assertEqual(summary["failed"], 1)
            self.assertEqual(summary["results"][0]["stage"], "replay")
            self.assertIn("Expecting value", summary["results"][0]["error"])

    def test_existing_corpus_mode_never_recaptures_or_omits_missing_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scenarios = root / "scenarios"
            raw = root / "raw"
            scenarios.mkdir()
            raw.mkdir()
            for name in ("a", "missing"):
                (scenarios / name).write_text("scenario\n")
            (raw / "a.stdout").write_bytes(FIXTURE.read_bytes())
            with patch("run_scenarios.capture") as mocked, patch(
                "run_scenarios.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0),
            ):
                summary = run_suite(
                    None,
                    root / "replayer",
                    scenarios,
                    root / "out",
                    raw_directory=raw,
                )
            mocked.assert_not_called()
            self.assertEqual(summary["selected"], 2)
            self.assertEqual(summary["failed"], 2)
            self.assertEqual(summary["results"][0]["stage"], "replay")
            self.assertEqual(summary["results"][1]["stage"], "reduction")
            replay = json.loads((root / "out/a.replay.json").read_text())
            self.assertEqual(
                replay["instructions"][0]["origin"][0]["file"], str(raw / "a.stdout")
            )


if __name__ == "__main__":
    unittest.main()
