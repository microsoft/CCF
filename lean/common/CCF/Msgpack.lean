module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public section

/-!
Readers of MessagePack values, as `src/msgpack/encode.h` writes them, and `msgpack_struct`,
which declares a structure with the reader of its map.
-/

namespace CCF.Msgpack

/-- Reads a value from the bytes at a cursor, which it advances past the value. -/
abbrev Reader (α : Type) := ReaderT ByteArray (EStateM String USize) α

@[inline]
private def getByte (data : ByteArray) (pos : USize) (h : pos < data.usize) : UInt8 :=
  data.uget pos (Nat.lt_of_lt_of_le h USize.toNat_ofNat_le)

/-- Run a reader on `data` starting at byte offset `pos`. -/
@[inline]
def run {α : Type} (r : Reader α) (data : ByteArray) (pos : USize := 0)
    : Except String (α × USize) :=
  match r data pos with
  | .ok v p => .ok (v, p)
  | .error e _ => .error e

@[inline]
private def readByte : Reader UInt8 :=
  fun data pos =>
    if h : pos < data.usize then
      .ok (getByte data pos h) (pos + 1)
    else
      .error "unexpected end of MessagePack input" pos

private partial def readBEAux (data : ByteArray) (pos rem : USize) (acc : UInt64)
    : UInt64 :=
  if rem == 0 then
    acc
  else if h : pos < data.usize then
    readBEAux data (pos + 1) (rem - 1) ((acc <<< 8) ||| (getByte data pos h).toUInt64)
  else
    acc

@[inline]
private def readBE (n : USize) : Reader UInt64 :=
  fun data pos =>
    if n <= data.usize - pos then
      .ok (readBEAux data pos n 0) (pos + n)
    else
      .error "unexpected end of MessagePack input" pos

/-- Read a MessagePack boolean (`0xC2` or `0xC3`). -/
@[inline]
def readBool : Reader Bool := do
  match ← readByte with
  | 0xC2 => pure false
  | 0xC3 => pure true
  | _ => throw "expected bool"

/-- Read an unsigned MessagePack integer (`fixint` or `uint8/16/32/64`). -/
@[inline]
def readNat : Reader Nat := do
  let b ← readByte
  if b < 0x80 then
    pure b.toNat
  else
    match b with
    | 0xCC => UInt64.toNat <$> readBE 1
    | 0xCD => UInt64.toNat <$> readBE 2
    | 0xCE => UInt64.toNat <$> readBE 4
    | 0xCF => UInt64.toNat <$> readBE 8
    | _ => throw "expected unsigned integer"

/-- Read a string header: the start and length of its bytes, which are not validated. -/
@[inline]
private def readStrSpan : Reader (USize × USize) :=
  fun data pos =>
    match readByte data pos with
    | .error e p => .error e p
    | .ok b pos =>
        let lenRes :=
          if b >= 0xA0 && b <= 0xBF then
            .ok (b &&& 0x1F).toUInt64 pos
          else
            match b with
            | 0xD9 => readBE 1 data pos
            | 0xDA => readBE 2 data pos
            | 0xDB => readBE 4 data pos
            | _ => .error "expected string" pos
        match lenRes with
        | .error e p => .error e p
        | .ok n s =>
            let len := n.toUSize
            if n == len.toUInt64 && len <= data.usize - s then
              .ok (s, len) (s + len)
            else
              .error "string exceeds MessagePack buffer" s

/-- Read and UTF-8 validate a MessagePack string. -/
def readStr : Reader String := do
  let (start, len) ← readStrSpan
  let some str := String.fromUTF8? ((← read).extract start.toNat (start + len).toNat)
  | throw "invalid UTF-8 in MessagePack string"
  return str

/-- Read a MessagePack array header and return its element count. -/
@[inline]
def readArrayHeader : Reader Nat := do
  let b ← readByte
  if b >= 0x90 && b <= 0x9F then
    pure (b &&& 0x0F).toNat
  else
    match b with
    | 0xDC => UInt64.toNat <$> readBE 2
    | 0xDD => UInt64.toNat <$> readBE 4
    | _ => throw "expected array"

/-- Read a MessagePack map header and return its entry count. -/
@[inline]
def readMapHeader : Reader Nat := do
  let b ← readByte
  if b >= 0x80 && b <= 0x8F then
    pure (b &&& 0x0F).toNat
  else
    match b with
    | 0xDE => UInt64.toNat <$> readBE 2
    | 0xDF => UInt64.toNat <$> readBE 4
    | _ => throw "expected map"

/-- Read a Fluentd EventTime (`fixext8` ext type `0`) in nanoseconds, or `nil` as `none`. -/
@[inline]
def readEventTime : Reader (Option Nat) := do
  match ← readByte with
  | 0xC0 => pure none
  | 0xD7 =>
      if (← readByte) != 0x00 then throw "expected Fluentd EventTime ext type 0"
      let sec ← readBE 4;
      let nsec ← readBE 4
      if nsec >= 1000000000 then throw "invalid EventTime nanoseconds"
      pure (some (sec.toNat * 1000000000 + nsec.toNat))
  | _ => throw "expected Fluentd EventTime or nil"

private partial def skipLoop (data : ByteArray) (pos rem : USize)
    : EStateM.Result String USize Unit :=
  if rem == 0 then
    .ok () pos
  else if h : pos < data.usize then
    let b := getByte data pos h;
    let pos := pos + 1;
    let rem := rem - 1
    let step (p extra : USize) :=
      if extra <= data.usize - p && rem <= data.usize - p - extra then
        skipLoop data p (rem + extra)
      else
        .error "truncated MessagePack container" p
    let skipN (n : USize) :=
      if n <= data.usize - pos then
        skipLoop data (pos + n) rem
      else
        .error "unexpected end of MessagePack input" pos
    let skipLen (w ext : USize) :=
      if w <= data.usize - pos then
        let n := readBEAux data pos w 0;
        let len := n.toUSize;
        let p := pos + w
        if n == len.toUInt64 && ext <= data.usize - p && len <= data.usize - p - ext then
          skipLoop data (p + ext + len) rem
        else
          .error "unexpected end of MessagePack input" p
      else
        .error "unexpected end of MessagePack input" pos
    let container (w mult : USize) :=
      if w <= data.usize - pos then
        let n := readBEAux data pos w 0;
        let cnt := n.toUSize;
        let p := pos + w
        if n == cnt.toUInt64 && cnt <= (data.usize - p) / mult then
          step p (cnt * mult)
        else
          .error "truncated MessagePack container" p
      else
        .error "unexpected end of MessagePack input" pos
    if b < 0x80 || b >= 0xE0 || b == 0xC0 || b == 0xC2 || b == 0xC3 then
      skipLoop data pos rem
    else if b <= 0x8F then
      step pos ((b &&& 0x0F).toUSize * 2)
    else if b <= 0x9F then
      step pos (b &&& 0x0F).toUSize
    else if b <= 0xBF then
      skipN (b &&& 0x1F).toUSize
    else
      match b with
      | 0xCC | 0xD0 => skipN 1
      | 0xCD | 0xD1 | 0xD4 => skipN 2
      | 0xD5 => skipN 3
      | 0xCA | 0xCE | 0xD2 => skipN 4
      | 0xD6 => skipN 5
      | 0xCB | 0xCF | 0xD3 => skipN 8
      | 0xD7 => skipN 9
      | 0xD8 => skipN 17
      | 0xC4 | 0xD9 => skipLen 1 0
      | 0xC5 | 0xDA => skipLen 2 0
      | 0xC6 | 0xDB => skipLen 4 0
      | 0xC7 => skipLen 1 1
      | 0xC8 => skipLen 2 1
      | 0xC9 => skipLen 4 1
      | 0xDC => container 2 1
      | 0xDD => container 4 1
      | 0xDE => container 2 2
      | 0xDF => container 4 2
      | _ => .error "invalid MessagePack format byte 0xC1" pos
  else
    .error "unexpected end of MessagePack input" pos

/-- Skip one complete MessagePack value without allocating or validating UTF-8. -/
@[inline]
def skip : Reader Unit := fun data pos => skipLoop data pos 1

private def litEq (data : ByteArray) (start : USize) (lit : String) (i : Nat) : Bool :=
  if h : i < lit.utf8ByteSize then
    data.get! (start.toNat + i) == lit.getUTF8Byte ⟨i⟩ h && litEq data start lit (i + 1)
  else
    true
termination_by lit.utf8ByteSize - i

/-- Consume the next value if it is the string `lit`; otherwise leave it unread. -/
def strIs (lit : String) : Reader Bool :=
  fun data pos =>
    match readStrSpan data pos with
    | .ok (start, len) next =>
        if len.toNat == lit.utf8ByteSize && litEq data start lit 0 then
          .ok true next
        else
          .ok false pos
    | .error error pos => .error error pos

/-- Read an array with the reader of its elements. -/
def readList {α : Type} (element : Reader α) : Reader (List α) := do
  let rec loop : Nat → List α → Reader (List α)
    | 0, read => return read.reverse
    | n + 1, read => do loop n ((← element) :: read)
  loop (← readArrayHeader) []

/-- Read the keys of a map, skipping their values. -/
def readMapKeys : Reader (List String) := do
  let rec loop : Nat → List String → Reader (List String)
    | 0, keys => return keys.reverse
    | n + 1, keys => do
        let key ← readStr
        skip
        loop n (key :: keys)
  loop (← readMapHeader) []

/-- The value of a key which a map must have. -/
def required {α : Type} (key : String) : Option α → Reader α
  | some value => pure value
  | none => throw s!"missing key '{key}'"

/-- Reject the key at the cursor: the unknown-key reader of a map with no other keys. -/
def unknownKey : Reader Unit := do
  throw s!"unknown key '{← readStr}'"

/--
`msgpack_struct structure T where f : τ := reader ...` declares the structure `T` and
readers of it from a map with a key per field, in any order: `T.read` reads the map, and
`T.readFields n` its `n` entries, once its header is read.
A field is named as its key, and is followed by the reader of its value, not by a default.
A field of type `Option τ` may be absent; its `reader` reads a `τ`.
An unknown key is skipped with its value; `msgpack_struct!` rejects it instead.
-/
syntax (name := msgpackStruct) "msgpack_struct " command : command

@[inherit_doc msgpackStruct]
syntax (name := msgpackStructStrict) "msgpack_struct! " command : command

/-- The declarations of a `msgpack_struct`, whose unknown keys `unknown` reads. -/
private meta def structWithReaders
    (doc : Option (Lean.TSyntax `Lean.Parser.Command.docComment)) (name : Lean.Ident)
    (names : Array Lean.Ident) (types readers : Array Lean.Term) (unknown : Lean.Term)
    : Lean.MacroM Lean.Command := do
  let keys : Array Lean.Term := names.map fun field => Lean.quote (toString field.getId)
  let vars : Array Lean.Term := names.map fun field => ⟨field⟩
  -- Each field is read into an `Option`, which is checked once the map is read.
  let mut loopType : Lean.Term ← `(Reader $name)
  let mut values : Array Lean.Term := #[]
  for index in (List.range names.size).reverse do
    let type := types[index]!
    let var := vars[index]!
    if type matches `(Option $_) then
      loopType ← `($type → $loopType)
      values := #[var] ++ values
    else
      loopType ← `(Option $type → $loopType)
      values := #[← `((← required $(keys[index]!) $var))] ++ values
  let mut step : Lean.Term ← `($unknown *> loop n $vars*)
  for index in (List.range names.size).reverse do
    let args := vars.set! index (← `(some value))
    step ←
      `(strIs $(keys[index]!) >>= fun found =>
          if found then $(readers[index]!) >>= fun value => loop n $args* else $step)
  let nones : Array Lean.Term ← names.mapM fun _ => `(none)
  let readFields := Lean.mkIdentFrom name (name.getId ++ `readFields)
  let read := Lean.mkIdentFrom name (name.getId ++ `read)
  `($[$doc]? structure $name where
      $[$names:ident : $types]*
    /-- Read the `n` entries of a map into the structure. -/
    def $readFields (n : Nat) : Reader $name :=
      let rec loop : Nat → $loopType
        | 0, $vars,* => do return ⟨$values,*⟩
        | n + 1, $vars,* => $step
      loop n $nones*
    /-- Read a map into the structure. -/
    def $read : Reader $name := readMapHeader >>= $readFields)

macro_rules
  | `(msgpack_struct $[$doc:docComment]? structure $name:ident where
        $[$names:ident : $types := $readers]*) => do
      structWithReaders doc name names types readers (← `(skip *> skip))
  | `(msgpack_struct! $[$doc:docComment]? structure $name:ident where
        $[$names:ident : $types := $readers]*) => do
      structWithReaders doc name names types readers (← `(unknownKey))

end CCF.Msgpack
