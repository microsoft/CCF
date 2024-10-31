---- MODULE MCabs ----

EXTENDS abs, TLC, SequencesExt, FiniteSetsExt, Integers

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