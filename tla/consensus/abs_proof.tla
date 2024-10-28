---- MODULE abs_proof ----
EXTENDS abs, TLAPS

LEMMA Spec => TypeOK
<1> USE DEF TypeOK
<1>1. Init => TypeOK BY StartTermIsTerm DEF Init, InitialLogs
<1>2. TypeOK /\ [Next]_cLogs => TypeOK' BY DEF Next, Extend, Copy, CopyMaxAndExtend
<1>. QED BY <1>1, <1>2, PTL DEF Spec

======