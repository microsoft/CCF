-------------------------------- MODULE Network -------------------------------
EXTENDS ccfraft, Sequences

----------------------------------------------------------------------------------
\* Reordering and duplication of messages:

ReorderDupInitMessageVar ==
    messages = <<>>
    
ReorderDupWithMessage(m, msgs) == 
    IF m \notin (DOMAIN msgs) THEN
        msgs @@ (m :> 1)
    ELSE
        [ msgs EXCEPT ![m] = @ + 1 ]

ReorderDupWithoutMessage(m, msgs) == 
    IF msgs[m] = 1 THEN
        [ msg \in ((DOMAIN msgs) \ {m}) |-> msgs[msg] ]
    ELSE
        [ msgs EXCEPT ![m] = @ - 1 ]

ReorderDupMessages ==
    DOMAIN messages

ReorderDupMessagesTo(dest) ==
    { m \in Messages : m.dest = dest }

----------------------------------------------------------------------------------
\* Reordering and deduplication of messages (iff the spec removes message m from
\* msgs after receiving m, i.e., ReorderNoDupWithoutMessage.)

ReorderNoDupInitMessageVar ==
    messages = {}

ReorderNoDupWithMessage(m, msgs) == 
    msgs \union {m}

ReorderNoDupWithoutMessage(m, msgs) == 
    msgs \ {m}

ReorderNoDupMessages ==
    messages

ReorderNoDupMessagesTo(dest) ==
    { m \in Messages : m.dest = dest }

----------------------------------------------------------------------------------
\* Ordering and duplication of messages:

OrderInitMessageVar ==
    messages = [ s \in Servers |-> <<>>]

OrderWithMessage(m, msgs) ==
    [ messages EXCEPT ![m.dest] = Append(@, m) ]

OrderWithoutMessage(m, msgs) ==
    [ messages EXCEPT ![m.dest] = SelectSeq(@, LAMBDA e: m # e) ]

OrderMessages ==
    UNION { Range(messages[s]) : s \in Servers }

OrderMessagesTo(dest) ==
    IF messages[dest] # <<>> THEN {messages[dest][1]} ELSE {}

----------------------------------------------------------------------------------
\* Ordering and deduplication of messages:

OrderNoDupInitMessageVar ==
    OrderInitMessageVar

OrderNoDupWithMessage(m, msgs) ==
    IF \E i \in 1..Len(msgs[m.dest]) : msgs[m.dest][i] = m THEN
        msgs
    ELSE
        OrderWithMessage(m, msgs)

OrderNoDupWithoutMessage(m, msgs) ==
    OrderWithoutMessage(m, msgs)

OrderNoDupMessages ==
    OrderMessages

OrderNoDupMessagesTo(dest) ==
    OrderMessagesTo(dest)

==================================================================================
