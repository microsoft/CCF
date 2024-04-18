// learn more at https://aka.ms/genaiscript
script({
  title: "TLAi-linter",
  description:
    "Check if the prose comments and their TLA+ declarations and definitions are syntactically and semantically consistent",
});

// use def to emit LLM variables
def(
  "TLA+",
  env.files.filter((f) => f.filename.endsWith(".tla")),
  { lineNumbers: true },
);

// use $ to output formatted text to the prompt
$`You are an expert at TLA+/TLAPLUS. Your task is to check if the prose comments and their TLA+ declarations and definitions are syntactically and semantically consistent!!!
However, you may assume that that a parser has already checked the syntax of the TLA+ code.
Explain any consistencies and inconsistencies you may find.  Report inconsistent and consistent pairs in a single ANNOTATION section.

## TLA+ Syntax Hints
- A formula [A]_v is called a temporal formula, and is shorthand for the formula A \/ v' = v.  In other words, the formula is true if A is true or if the value of v remains unchanged.  Usually, v is a tuple of the spec's variables.
- The symbol \`#\` is alternative syntax used for inequality in TLA+; the other symbol is \`/=\".
- There a no assignments in TLA: \`x = 23\` and \`x' = 42\` are formula that assert that x equals 23 in the current state and 42 in a successor state.  Moreover, one may write \`x = 42 /\ x = 23\` which equals false but does not assign to x twice.

## TLA+ Semantics Hints
- Do NOT add any invariants or properties to the behavior specification Spec or any of its subformulas.  This would change THEOREM Spec => Inv into THEOREM Spec /\ Inv => Inv, which is vacuously true.
- TLA+ specs are always stuttering insensitive, i.e., the next-state relation is always [A]_v.  In other words, one cannot write a stuttering sensitive specification.

## TLA+ Convention Hints
- Trivial or obvious formulas and sub-formulas are typically not commented.
- The type correctness invariant is typically called TypeOK.
- Users can employ TLA labels as a means to conceptually associate a comment with a sub-formula like a specific disjunct or conjunct of a TLA formula. Even though these labels have no other function, they facilitate referencing particular parts of the formula from a comment.

## Formal and informal math Hints
- Take into account that humans may write informal math that is syntactically different from the formal math, yet semantically equivalent.  For example, humans may write \`N > 3T\` instead of \`N > 3 * T\`.

## Natural language Hints
- Unless a built-in TLA+ declaration or definition like an operator in the TLA+ standard library dictates otherwise, the prose comments should follow British English spelling conventions.

## Experiment with copy-paste catching
- Files that do not have the word "raft" in their name should not contain any mention of raft.
`;