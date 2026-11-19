module

public import Consensus.Model

@[expose] public section

namespace Consensus.Properties

/-- Initial memberships admitted by the model's initialization predicate. -/
abbrev ValidConfig := { config : CCF.Finset Model.Node.NodeID // config.Nonempty }

end Consensus.Properties
