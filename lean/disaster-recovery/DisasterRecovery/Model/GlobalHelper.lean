import DisasterRecovery.Model.Local

namespace DisasterRecovery.Model.GlobalHelper

open Local

def receive (source : Location) : Message -> Event
  | .gossip txid => .receiveGossip source txid .accepted
  | .vote => .receiveVote source .accepted
  | .iAmOpen => .receiveIAmOpen source .accepted

end DisasterRecovery.Model.GlobalHelper
