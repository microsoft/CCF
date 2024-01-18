-------------------------------- MODULE Network -------------------------------
EXTENDS Naturals, Sequences, SequencesExt, Bags, Functions, TLC

CONSTANT
    OrderedNoDup,
    Ordered,
    ReorderedNoDup,
    Reordered

CONSTANT
    Guarantee
ASSUME Guarantee \in {OrderedNoDup, Ordered, ReorderedNoDup, Reordered}

CONSTANT 
    Servers

VARIABLE 
    messages

----------------------------------------------------------------------------------
\* Reordering and duplication of messages:

LOCAL ReorderDupInitMessageVar ==
    messages = <<>>
    
LOCAL ReorderDupWithMessage(m, msgs) == 
    IF m \notin (DOMAIN msgs) THEN
        msgs @@ (m :> 1)
    ELSE
        [ msgs EXCEPT ![m] = @ + 1 ]

LOCAL ReorderDupWithoutMessage(m, msgs) == 
    IF msgs[m] = 1 THEN
        [ msg \in ((DOMAIN msgs) \ {m}) |-> msgs[msg] ]
    ELSE
        [ msgs EXCEPT ![m] = @ - 1 ]

LOCAL ReorderDupMessages ==
    DOMAIN messages

LOCAL ReorderDupMessagesTo(dest, source) ==
    { m \in ReorderDupMessages : m.dest = dest /\ m.source = source}

LOCAL ReorderDupOneMoreMessage(msg) ==
    \/ msg \notin ReorderDupMessages /\ msg \in ReorderDupMessages'
    \/ msg \in ReorderDupMessages /\ messages'[msg] > messages[msg]

LOCAL ReorderDupDropMessages ==
    messages' \in SubBag(messages)

----------------------------------------------------------------------------------
\* Reordering and deduplication of messages (iff the spec removes message m from
\* msgs after receiving m, i.e., ReorderNoDupWithoutMessage.)

LOCAL ReorderNoDupInitMessageVar ==
    messages = {}

LOCAL ReorderNoDupWithMessage(m, msgs) == 
    msgs \union {m}

LOCAL ReorderNoDupWithoutMessage(m, msgs) == 
    msgs \ {m}

LOCAL ReorderNoDupMessages ==
    messages

LOCAL ReorderNoDupMessagesTo(dest, source) ==
    { m \in messages : m.dest = dest /\ m.source = source }

LOCAL ReorderNoDupOneMoreMessage(msg) ==
    \/ msg \notin ReorderNoDupMessages /\ msg \in ReorderNoDupMessages'
    \/ msg \in ReorderNoDupMessages /\ messages'[msg] > messages[msg]

LOCAL ReorderNoDupDropMessages ==
    messages' \in SUBSET messages

----------------------------------------------------------------------------------
\* Point-to-Point Ordering and duplication of messages:

LOCAL OrderInitMessageVar ==
    messages = [ src \in Servers |-> [ dst \in Servers |-> <<>> ] ]

LOCAL OrderWithMessage(m, msgs) ==
    [ msgs EXCEPT ![m.source][m.dest] = Append(@, m) ]

LOCAL OrderWithoutMessage(m, msgs) ==
    [ msgs EXCEPT ![m.source][m.dest] = RemoveFirst(@, m) ]

LOCAL OrderMessages ==
    UNION { UNION { Range(messages[src][dst]) : dst \in Servers } : src \in Servers }

LOCAL OrderMessagesTo(dest, source) ==
    Range(messages[source][dest])

LOCAL OrderOneMoreMessage(m) ==
    \/ /\ m \notin OrderMessages
       /\ m \in OrderMessages'
    \/ Len(SelectSeq(messages[m.source][m.dest], LAMBDA e: m = e)) < Len(SelectSeq(messages'[m.source][m.dest], LAMBDA e: m = e))

LOCAL OrderDropMessagesTo(dest, source) ==
    \E s \in Suffixes(messages[source][dest]):  \* TODO - Change to SubSeqs if more sophisticated message loss is needed.
        messages' = [ messages EXCEPT ![source][dest] = s ]

----------------------------------------------------------------------------------
\* Point-to-Point Ordering and no duplication of messages:

LOCAL OrderNoDupInitMessageVar ==
    OrderInitMessageVar

LOCAL OrderNoDupWithMessage(m, msgs) ==
    IF \E i \in 1..Len(msgs[m.source][m.dest]) : msgs[m.source][m.dest][i] = m THEN
        msgs
    ELSE
        OrderWithMessage(m, msgs)

LOCAL OrderNoDupWithoutMessage(m, msgs) ==
    OrderWithoutMessage(m, msgs)

LOCAL OrderNoDupMessages ==
    OrderMessages

LOCAL OrderNoDupMessagesTo(dest, source) ==
    OrderMessagesTo(dest, source)

LOCAL OrderNoDupOneMoreMessage(m) ==
    \/ /\ m \notin OrderMessages
       /\ m \in OrderMessages'
    \/ /\ m \in OrderMessages
       /\ m \in OrderMessages'

LOCAL OrderNoDupDropMessagesTo(dest, source) ==
    \E subSeq \in SubSeqs(messages[source][dest]):
        messages' = [ messages EXCEPT ![source][dest] = subSeq ]

----------------------------------------------------------------------------------

InitMessageVar ==
    CASE Guarantee = OrderedNoDup   -> OrderNoDupInitMessageVar
      [] Guarantee = Ordered        -> OrderInitMessageVar
      [] Guarantee = ReorderedNoDup -> ReorderNoDupInitMessageVar
      [] Guarantee = Reordered      -> ReorderDupInitMessageVar

Messages ==
    CASE Guarantee = OrderedNoDup   -> OrderNoDupMessages
      [] Guarantee = Ordered        -> OrderMessages
      [] Guarantee = ReorderedNoDup -> ReorderNoDupMessages
      [] Guarantee = Reordered      -> ReorderDupMessages

MessagesTo(dest, source) ==
    CASE Guarantee = OrderedNoDup   -> OrderNoDupMessagesTo(dest, source)
      [] Guarantee = Ordered        -> OrderMessagesTo(dest, source)
      [] Guarantee = ReorderedNoDup -> ReorderNoDupMessagesTo(dest, source)
      [] Guarantee = Reordered      -> ReorderDupMessagesTo(dest, source)

\* Helper for Send and Reply. Given a message m and set of messages, return a
\* new set of messages with one more m in it.
WithMessage(m, msgs) ==
    CASE Guarantee = OrderedNoDup   -> OrderNoDupWithMessage(m, msgs)
      [] Guarantee = Ordered        -> OrderWithMessage(m, msgs)
      [] Guarantee = ReorderedNoDup -> ReorderNoDupWithMessage(m, msgs)
      [] Guarantee = Reordered      -> ReorderDupWithMessage(m, msgs)

\* Helper for Discard and Reply. Given a message m and bag of messages, return
\* a new bag of messages with one less m in it.
WithoutMessage(m, msgs) ==
    CASE Guarantee = OrderedNoDup   -> OrderNoDupWithoutMessage(m, msgs)
      [] Guarantee = Ordered        -> OrderWithoutMessage(m, msgs)
      [] Guarantee = ReorderedNoDup -> ReorderNoDupWithoutMessage(m, msgs)
      [] Guarantee = Reordered      -> ReorderDupWithoutMessage(m, msgs)
   
OneMoreMessage(msg) ==
    CASE Guarantee = OrderedNoDup   -> OrderNoDupOneMoreMessage(msg)
      [] Guarantee = Ordered        -> OrderOneMoreMessage(msg)
      [] Guarantee = ReorderedNoDup -> ReorderNoDupOneMoreMessage(msg) 
      [] Guarantee = Reordered      -> ReorderDupOneMoreMessage(msg)

DropMessagesTo(dest, source) ==
    CASE Guarantee = OrderedNoDup   -> OrderNoDupDropMessagesTo(dest, source)
      [] Guarantee = Ordered        -> OrderDropMessagesTo(dest, source)
      [] Guarantee = ReorderedNoDup -> ReorderNoDupDropMessages
      [] Guarantee = Reordered      -> ReorderDupDropMessages

==================================================================================
