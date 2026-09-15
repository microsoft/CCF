-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.


import CCFRaft.Protocol.Model

set_option autoImplicit false

namespace CCFRaft.Protocol.Safety

open Model

variable {Node TxId : Type}
variable [DecidableEq Node] [DecidableEq TxId]

/-- Every positive node commit frontier points to a signature entry. -/
def CommittedFrontierIsSignature (state : State Node TxId) : Prop :=
  forall node,
    0 < (state.nodes node).commitIndex ->
      isSignatureAt
        (state.nodes node).log
        (state.nodes node).commitIndex = true

/-- No two distinct nodes lead in the same term. -/
def ElectionSafety (state : State Node TxId) : Prop :=
  forall left right,
    (state.nodes left).role = .leader ->
      (state.nodes right).role = .leader ->
        (state.nodes left).currentTerm =
          (state.nodes right).currentTerm ->
          left = right

/-- Any two node-local committed logs are prefix-comparable. -/
def CommittedLogsPrefix (state : State Node TxId) : Prop :=
  forall left right,
    (state.nodes left).committedLog <+:
        (state.nodes right).committedLog \/
      (state.nodes right).committedLog <+:
        (state.nodes left).committedLog

/-- Core public safety mirrors committed-log, signature, and election safety. -/
structure ConsensusSafety (state : State Node TxId) : Prop where
  committedLogsPrefix : CommittedLogsPrefix state
  committedFrontierIsSignature : CommittedFrontierIsSignature state
  electionSafety : ElectionSafety state

end CCFRaft.Protocol.Safety
