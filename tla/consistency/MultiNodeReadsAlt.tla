---- MODULE MultiNodeReadsAlt ----

EXTENDS MultiNodeReads

\* Alternative initial state with transactions already committed
InitAlt ==
    /\ ledgers = << 
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

SpecMultiNodeReadsAlt == InitAlt /\ [][NextMultiNodeReadsAction]_vars


====