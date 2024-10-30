---- MODULE MCabs ----

EXTENDS abs, TLC, SequencesExt, FiniteSetsExt, Integers

\* All (temporal) formulas below are expected to hold but cause a
\* spurious violation of liveness properties due to our MonothonicReduction
\* view.

SpuriousPropA ==
    \* Stenghtened variant of EmptyLeadsToNonEmpty.
    \A i \in Servers:
        cLogs[i] = <<>> ~> [](cLogs[i] # <<>>)

----

\* All (temporal) formulas below are expected to result in liveness violations,
\* as there is nothing in the behavior spec that forces all Terms to be present
\* in any/all logs.

NotAPropA ==
    <>(\A i \in Servers: Terms = Range(cLogs[i]) )

NotAPropB ==
    <>[](\A i \in Servers: Terms = Range(cLogs[i]) )

NotAPropC ==
    <>(\E i \in Servers: Terms = Range(cLogs[i]) )

NotAPropD ==
    <>[](\E i \in Servers: Terms = Range(cLogs[i]) )

NotAPropE ==
    \E i \in Servers:
        cLogs[i] = <<>> ~> Terms = Range(cLogs[i])

NotAPropF ==
    \A i \in Servers:
        \A n \in 1..10: \* 10 is arbitrary but TLC doesn't handle Nat.  LeadsTo is vacausously true if n > Len(cLogs[i]).
            Len(cLogs[i]) = n ~> cLogs[i] = <<>>

NotAPropG ==
    \A i \in Servers:
        \A n \in 1..10:
            Len(cLogs[i]) = n ~> Len(cLogs[i]) = n - 1

NotAPropH ==
    \* We would expect NotAPropH to hold if we conjoin  Len(cLogs'[i]) = Len(cLogs[i]) + 1  to abs!Next.
    \* Instead, we get a spurious violation of liveness properties, similar to SpuriousPropA.
    \A i \in Servers:
        \A n \in 0..1:
            Len(cLogs[i]) = n ~> Len(cLogs[i]) = n + 1

----

Symmetry ==
      Permutations(Servers)

CONSTANTS NodeOne, NodeTwo, NodeThree

MCServers == {NodeOne, NodeTwo, NodeThree}
MCTerms == 2..4
MCStartTerm == Min(MCTerms)
MaxExtend == 3
MCMaxTerm == Max(MCTerms)

ASSUME
    \* LongestCommonPrefix in View for a single server would always shorten the
    \* log to <<>>, reducing the state-space to a single state.
    Cardinality(MCServers) > 1

MCTypeOK ==
    \* 4 because of the initial log.
    cLogs \in [Servers -> BoundedSeq(Terms, 4 + MaxExtend)]

MCSeq(S) ==
    BoundedSeq(S, MaxExtend)

-----

\* Combining the following conditions makes the state space finite:
\* - Terms is a *finite* set (MCTerms)
\* - The divergence of any two logs is bounded (MaxDivergence)
\* - The longest common prefix of all logs is discarded (MonotonicReduction)

Abs(n) ==
    IF n >= 0 THEN n ELSE -n

MaxDivergence ==
    \A i, j \in Servers :
        Abs(Len(cLogs[i]) - Len(cLogs[j])) <= 2

-----

TailFrom(seq, idx) ==
    SubSeq(seq, idx + 1, Len(seq))

MonotonicReductionLongestCommonPrefix ==
    \* Find the longest common prefix of all logs and drop it from all logs.
    LET commonPrefixBound == Len(LongestCommonPrefix(Range(cLogs)))
    IN [ s \in Servers |-> TailFrom(cLogs[s], commonPrefixBound) ]

MonotonicReductionLongestCommonPrefixAndTerms ==
    \* Find the longest common prefix of all logs and drop it from all logs.
    \* We also realign the terms in the remaining suffixes.
    LET commonPrefixBound == Len(LongestCommonPrefix(Range(cLogs)))
        minTerm ==
            \* 3) The minimum term out of all minima.
            Min({
                \* 2) The minimum term in the suffix of a log.
                Min(
                    \* 1) All terms in the suffix of a log.
                    Range(TailFrom(cLogs[s], commonPrefixBound))
                        \* \cup {MCMaxTerm+1} to handle the case where a log is empty.
                        \* MCMaxTerm+1 to always be greater than any term in the log.
                        \* If all logs are empty, the minTerm does not matter.
                        \cup {MCMaxTerm+1}) : s \in Servers})
        delta == minTerm - StartTerm
    IN  [ s \in Servers |-> 
            [ i \in 1..Len(cLogs[s]) - commonPrefixBound |->
                    cLogs[s][i + commonPrefixBound] - delta ] ]

MonotonicReduction ==
    MonotonicReductionLongestCommonPrefixAndTerms

====