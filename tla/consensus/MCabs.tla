---- MODULE MCabs ----

EXTENDS abs, TLC

Symmetry ==
      Permutations(Servers)

CONSTANTS NodeOne, NodeTwo, NodeThree

MCServers == {NodeOne, NodeTwo, NodeThree}
MCTerms == 2..4

\* Limit length of logs to terminate model checking.
MaxLogLengthConstraint ==
    \A i \in Servers :
        Len(cLogs[i]) <= 7
====