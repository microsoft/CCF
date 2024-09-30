---- MODULE MCabs ----

EXTENDS abs, TLC

Symmetry ==
      Permutations(Servers)

CONSTANTS NodeOne, NodeTwo, NodeThree

MCServers == {NodeOne, NodeTwo, NodeThree}
MCTerms == 2..4
MCMaxLogLength == 7

====