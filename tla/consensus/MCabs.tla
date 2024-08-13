---- MODULE MCabs ----

EXTENDS abs

CONSTANTS NodeOne, NodeTwo, NodeThree

MCServers == {NodeOne, NodeTwo, NodeThree}
MCTerms == 2..5
MCRequestLimit == 3
MCStartTerm == 2

====