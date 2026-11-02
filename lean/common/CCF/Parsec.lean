module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Std.Internal.Parsec.Basic

public section

namespace CCF.Parsec

/-- An immutable event stream with a cursor into the next unconsumed event. -/
structure EventInput (Event : Type) where
  /-- Events in their original order. -/
  events : Array Event
  /-- Index of the next event. -/
  position : Nat := 0
  /-- Farthest consumed-pattern failure retained across speculative alternatives. -/
  diagnostic : Option (Nat × String) := none

-- Parsec compares cursor positions, so events need no equality instance.
instance {Event : Type} : Std.Internal.Parsec.Input (EventInput Event) Nat Nat where
  pos := (·.position)
  next input := { input with position := input.position + 1 }
  curr := (·.position)
  hasNext input := input.position < input.events.size
  next' input _ := { input with position := input.position + 1 }
  curr' input _ := input.position

/-- Parsec over an array of arbitrary events. -/
abbrev Parser (Event : Type) := Std.Internal.Parsec (EventInput Event)

/-- An event parser carrying application state, discarded on a failed alternative. -/
abbrev ParserT (Event State : Type) := StateT State (Parser Event)

variable {Event State α : Type}

/-- Try a parser transactionally, restoring the cursor and application state on failure.
Retain the farthest consumed-pattern diagnostic for a subsequent parse failure. -/
def attempt (parser : ParserT Event State α) : ParserT Event State α :=
  fun state input =>
    match parser.run state input with
    | .success remaining value => .success remaining value
    | .error remaining error =>
        let diagnostic :=
          if input.position < remaining.position then
            match remaining.diagnostic with
            | some (position, message) =>
                if remaining.position < position then
                  some (position, message)
                else
                  some (remaining.position, toString error)
            | none => some (remaining.position, toString error)
          else
            remaining.diagnostic
        .error { input with diagnostic } error

/-- Fail at the current cursor, committing the branch if input was consumed. -/
def failure (message : String) : ParserT Event State α :=
  liftM (Std.Internal.Parsec.fail message : Parser Event α)

/-- Lift an application validation result into the parser. -/
def validated : Except String α → ParserT Event State α
  | .ok value => pure value
  | .error error => failure error

/-- Inspect the next event without consuming input or changing application state. -/
def peek : ParserT Event State (Option Event) :=
  liftM (m := Parser Event)
    ((fun input =>
        match Std.Internal.Parsec.peek? input with
        | .success remaining index => .success remaining (index.bind (input.events[·]?))
        | .error remaining error => .error remaining error)
      : Parser Event (Option Event))

/-- Consume one event, or fail with the supplied diagnostic at end of input. -/
def take (message : String := "unexpected end of input") : ParserT Event State Event := do
  let some event ← peek | failure message
  let _ ← liftM (Std.Internal.Parsec.any : Parser Event Nat)
  return event

/-- Consume a matching event; a predicate mismatch leaves input and state untouched. -/
def satisfy (predicate : Event → Bool) (message : String)
    : ParserT Event State Event := do
  let some event ← peek | failure message
  unless predicate event do
    failure message
  take message

/-- Repeat a consuming rule, threading application state and retaining committed failures.
The rule must consume input whenever it succeeds. -/
partial def many (parser : ParserT Event State α) : ParserT Event State (List α) :=
  (do
    let first ← parser
    return first :: (← many parser))
  <|> pure []

/-- Repeat a consuming rule without collecting results.
The rule must consume input whenever it succeeds. -/
partial def many_ (parser : ParserT Event State Unit) : ParserT Event State Unit :=
  (parser *> many_ parser) <|> pure ()

/-- Optionally parse a rule; failure after consumption remains fatal. -/
def optionalRule (parser : ParserT Event State α) : ParserT Event State (Option α) :=
  (some <$> parser) <|> pure none

/-- Optionally parse a rule, discarding its result. -/
def optional_ (parser : ParserT Event State Unit) : ParserT Event State Unit :=
  discard (optionalRule parser)

/-- Require the entire event stream to have been consumed. -/
def eof : ParserT Event State Unit :=
  liftM (Std.Internal.Parsec.eof : Parser Event Unit)

/-- Run a parser from the first event, preserving Parsec's position-aware diagnostics.
Use `eof` in the parser when trailing events must be rejected. -/
def run (events : Array Event) (parser : Parser Event α) : Except String α :=
  match parser { events } with
  | .success _ value => .ok value
  | .error remaining error =>
      match remaining.diagnostic with
      | some (position, message) =>
          if remaining.position < position then
            .error message
          else
            .error (toString error)
      | none => .error (toString error)

end CCF.Parsec
