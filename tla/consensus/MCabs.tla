---- MODULE MCabs ----

EXTENDS abs, TLC, SequencesExt, FiniteSetsExt, Integers

Symmetry ==
      Permutations(Servers)

CONSTANTS NodeOne, NodeTwo, NodeThree

MCServers == {NodeOne, NodeTwo, NodeThree}
MCTerms == 2..4
MCStartTerm == Min(MCTerms)
MaxExtend == 3

MCTypeOK ==
    \* 4 because of the initial log.
    cLogs \in [Servers -> BoundedSeq(Terms, 4 + MaxExtend)]

MCSeq(S) ==
    BoundedSeq(S, MaxExtend)

\* Limit length of logs to terminate model checking.
MaxLogLengthConstraint ==
    \A i \in Servers :
        Len(cLogs[i]) <= 7

Abs(n) ==
    IF n >= 0 THEN n ELSE -n

MaxDivergence ==
    \A i, j \in Servers :
        Abs(Len(cLogs[i]) - Len(cLogs[j])) <= 2

TailFrom(seq, idx) ==
    SubSeq(seq, idx + 1, Len(seq))

MonotonicReduction ==
    \* Find the longest common prefix of all logs and drop it from all logs. We realign the terms in the remaining suffixes to start at StartTerm.
    LET lcp == LongestCommonPrefix(Range(cLogs))
        commonPrefixBound == Len(lcp)
        minTerm == Min({Min(Range(TailFrom(cLogs[s], commonPrefixBound)) \cup {0}) : s \in Servers}) \* \cup {0} to handle the case where the log is empty.
    IN 
        [ s \in Servers |-> [i \in 1..Len(cLogs[s])-commonPrefixBound |-> cLogs[s][i + commonPrefixBound] - minTerm ] ]

====