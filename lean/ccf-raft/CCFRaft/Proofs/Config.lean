-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Model.Node

/-!
Proof-only configuration shorthand. The model takes an explicit `InitialConfig`
value; proofs may use instance inference to avoid repeating that value in every
supporting lemma. These conveniences do not change the model or its properties.
-/

attribute [class] CCFRaft.Model.Local.InitialConfig

namespace CCFRaft.Proofs.Config

open Model.Local

variable {Node : Type} [DecidableEq Node] [config : InitialConfig Node]

def INITIAL_LEADER : Node := config.leader

def INITIAL_CONFIGURATION : Finset Node := config.configuration

def INITIAL_PRE_VOTE_STATUS : Node -> PreVoteStatus := config.preVoteStatus

end CCFRaft.Proofs.Config
