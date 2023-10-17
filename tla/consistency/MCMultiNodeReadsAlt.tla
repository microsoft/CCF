---- MODULE MCMultiNodeReadsAlt ----
\* MCMultiNodeReads with a different initial state

EXTENDS MCMultiNodeReads

\* Alternative initial state with two transactions already committed
InitAlt ==
    /\ ledgerBranches = << 
        <<[view |-> 1, tx |-> 0]>>,
        <<[view |-> 1, tx |-> 0], [view |-> 2, tx |-> 1]>> 
        >>
    /\ history = <<
        [type |-> RwTxRequest, tx |-> 0], 
        [type |-> RwTxRequest, tx |-> 1], 
        [type |-> RwTxResponse, tx_id |-> <<1, 1>>, tx |-> 0, observed |-> <<0>>], 
        [type |-> RwTxResponse, tx_id |-> <<2, 2>>, tx |-> 1, observed |-> <<0, 1>>], 
        [type |-> TxStatusReceived, status |-> CommittedStatus, tx_id |-> <<1, 1>>], 
        [type |-> TxStatusReceived, status |-> CommittedStatus, tx_id |-> <<2, 2>>]
        >>

MCSpecMultiNodeReadsAlt == InitAlt /\ [][MCNextMultiNodeReadsAction]_vars


====