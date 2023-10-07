-------------------------------- MODULE Network -------------------------------
EXTENDS Naturals, Sequences, SequencesExt, Functions, TLC


CONSTANT 
    Servers

VARIABLE 
    messages

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
    { m \in ReorderDupMessages : m.dest = dest }

ReorderDupOneMoreMessage(msg) ==
    \/ msg \notin ReorderDupMessages /\ msg \in ReorderDupMessages'
    \/ msg \in ReorderDupMessages /\ messages'[msg] > messages[msg]

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
    { m \in messages : m.dest = dest }

ReorderNoDupOneMoreMessage(msg) ==
    \/ msg \notin ReorderNoDupMessages /\ msg \in ReorderNoDupMessages'
    \/ msg \in ReorderNoDupMessages /\ messages'[msg] > messages[msg]

----------------------------------------------------------------------------------
\* Point-to-Point Ordering and duplication of messages:

OrderInitMessageVar ==
    messages = [ s \in Servers |-> <<>>]

OrderWithMessage(m, msgs) ==
    [ msgs EXCEPT ![m.dest] = Append(@, m) ]

OrderWithoutMessage(m, msgs) ==
    [ msgs EXCEPT ![m.dest] = SelectSeq(@, LAMBDA e: m # e) ]

OrderMessages ==
    UNION { Range(messages[s]) : s \in Servers }

OrderMessagesTo(dest) ==
    IF messages[dest] # <<>> THEN {messages[dest][1]} ELSE {}

OrderOneMoreMessage(m) ==
    \/ /\ m \notin OrderMessages
       /\ m \in OrderMessages'
    \/ Len(SelectSeq(messages[m.dest], LAMBDA e: m = e)) < Len(SelectSeq(messages'[m.dest], LAMBDA e: m = e))

----------------------------------------------------------------------------------
\* Point-to-Point Ordering and no duplication of messages:

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

----------------------------------------------------------------------------------

InitMessageVar ==
    ReorderNoDupInitMessageVar

Messages ==
    ReorderNoDupMessages    

MessagesTo(dest) ==
    ReorderNoDupMessagesTo(dest)

\* Helper for Send and Reply. Given a message m and set of messages, return a
\* new set of messages with one more m in it.
WithMessage(m, msgs) ==
    ReorderNoDupWithMessage(m, msgs)

\* Helper for Discard and Reply. Given a message m and bag of messages, return
\* a new bag of messages with one less m in it.
WithoutMessage(m, msgs) ==
    ReorderNoDupWithoutMessage(m, msgs)
   
OneMoreMessage(msg) ==
    ReorderNoDupOneMoreMessage(msg)

==================================================================================
