# TLA+ model of CCF's implementation of Raft

The given model consists of three files:

- `ccfraft.tla` : The core specification that implements the features as seen below.
- `MCraft.tla` : The model checking implementation for the spec. Sets the constants and can be modified for each run to
  fine tune the settings.
- `MCraft.cfg` : The core configuration which invariants are to be checked etc. Usually stays untouched during normal
  model checking.

To run this spec, run the `MCraft.tla` with the `-deadlock` parameter to disable liveness checking (see explanation
below): `tlc MCraft.tla -deadlock`. See the Readme in the parent folder for a full explanation on running the model checker.

## Implemented features

| Feature         | Description                                                                                                                                                       |
| :-------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Signatures      | In CCF, only entries signed by the primary can be committed (in contrast to all entries in normal Raft)                                                           |
| Reconfiguration | CCF implements a one-transaction version of reconfiguration for Raft (read the description [here](https://microsoft.github.io/CCF/main/overview/consensus.html)). |

## Checked invariants

These invariants are a modification of the invariants found [here](https://github.com/dricketts/raft.tla). The original Raft specification does not contain any invariants and reconfiguration introduces important differences to Raft. One example of this is that Raft with reconfigurations can result in two leaders in the same term. We accept this in CCF since we also get the guarantee that one of these leaders will never make progress. Thus, the invariants below are reformualed for CCF.

| Name                     | Short description                                                                                                                                                           |
| :----------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LogInv                   | Committing an entry never changes the previous log indices, neither does it decrease the size of the committed log.                                                         |
| CandidateTermNotInLogInv | Candidates that have a chance to win an election will not be elected to a term that already had a leader that appended entries.                                             |
| ElectionSafetyInv        | A leader always has the greatest index for its current term.                                                                                                                |
| LogMatchingInv           | Two logs with the same (index,term) entry have a log prefix up to that same point (this means that all logs are identical up to that point if they match at a given point). |
| QuorumLogInv             | All committed entries are contained in the log of at least one server in every quorum.                                                                                      |
| MoreUpToDateCorrectInv   | The "up-to-date" check performed by servers before issuing a vote implies that i receives a vote from j only if i has all of j's committed entries.                         |
| SignatureInv             | In CCF, only signature messages should ever be committed.                                                                                                                   |

## Note on liveness

This specification was created to verify certain _persistence_ (i.e. safety) properties of the Raft protocol as it is
implemented in CCF. In doing so, this specification does not check any liveness guarantees. To allow model checking
in a reasonable amount of time, the implementation focuses on the persistence guarantees and places certain limitations
on the state space to be explored. Since these limitations can lead certain traces of the execution into a deadlock,
**liveness is not checkable with this model**.
