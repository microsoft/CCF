module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import CCF.Msgpack
import CCF.Msgpack

namespace CCF.Tests.Msgpack

open CCF.Msgpack

msgpack_struct
  /-- A structure with a required and an optional field, which skips unknown keys. -/
  structure Sample where
    a : Nat := readNat
    b : Option Bool := readBool
    names : List String := readMapKeys

msgpack_struct!
  /-- A structure which rejects unknown keys. -/
  structure Strict where
    x : Nat := readNat

deriving instance BEq, Repr for Sample, Strict

def expectOk {α : Type} [BEq α] [Repr α] (label : String) (reader : Reader α)
    (bytes : Array UInt8) (expected : α)
    : IO Unit := do
  match CCF.Msgpack.run reader (ByteArray.mk bytes) with
  | .ok (value, position) =>
      unless value == expected && position.toNat == bytes.size do
        throw
          (IO.userError
            s!"{label}: read {repr value} to {position}, expected {repr expected} to {bytes.size}")
  | .error error => throw (IO.userError s!"{label}: unexpected error {error}")

def expectError {α : Type} (label : String) (reader : Reader α) (bytes : Array UInt8)
    : IO Unit := do
  if (CCF.Msgpack.run reader (ByteArray.mk bytes)).isOk then
    throw (IO.userError s!"{label}: expected an error")

/-- Checks the readers on each encoding they read, on truncated input, and on strings which are not UTF-8. -/
def run : IO Unit := do
  -- Unsigned integers: fixint, uint 8, 16, 32 and 64.
  expectOk "fixint" readNat #[0x7F] 127
  expectOk "uint8" readNat #[0xCC, 0xFF] 255
  expectOk "uint16" readNat #[0xCD, 0x01, 0x02] 0x0102
  expectOk "uint32" readNat #[0xCE, 0x00, 0x01, 0x00, 0x00] 0x10000
  expectOk "uint64" readNat #[0xCF, 0, 0, 0, 1, 0, 0, 0, 2] 0x100000002
  expectError "truncated uint32" readNat #[0xCE, 0x00, 0x01]
  expectOk "false" readBool #[0xC2] false
  expectOk "true" readBool #[0xC3] true
  -- Fluentd EventTime, or nil.
  expectOk "no time" readEventTime #[0xC0] none
  expectOk "time" readEventTime #[0xD7, 0x00, 0, 0, 0, 2, 0, 0, 0, 5] (some 2000000005)
  expectError "time of another ext type" readEventTime
    #[0xD7, 0x01, 0, 0, 0, 1, 0, 0, 0, 0]
  expectError "time with too many nanoseconds" readEventTime
    #[0xD7, 0x00, 0, 0, 0, 1, 0x3B, 0x9A, 0xCA, 0x00]
  -- Strings: `strIs` leaves a string it does not match unread.
  let hello := #[0xA5, 0x68, 0x65, 0x6C, 0x6C, 0x6F]
  expectOk "str" readStr hello "hello"
  expectError "str which is not UTF-8" readStr #[0xA2, 0xFF, 0xFE]
  expectOk "strIs"
    (do
      return (← strIs "hell", ← strIs "world", ← strIs "hello"))
    hello (false, false, true)
  expectOk "list" (readList readNat) #[0x93, 0x01, 0x02, 0xCC, 0x80] [1, 2, 128]
  expectOk "map keys" readMapKeys #[0x82, 0xA1, 0x61, 0x80, 0xA1, 0x62, 0x01] ["a", "b"]
  -- `skip` reads no value: a string need not be UTF-8.
  expectOk "skip of a string which is not UTF-8" skip
    #[0x81, 0xA1, 0x61, 0xA3, 0xFF, 0xFE, 0x80] ()
  -- bin 8, float 64, a negative fixint, fixext 4 and an empty array.
  expectOk "skip" skip
    #[
      0x95,
      0xC4,
      0x02,
      0xAA,
      0xBB,
      0xCB,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0xFF,
      0xD6,
      0x02,
      1,
      2,
      3,
      4,
      0x90
    ]
    ()
  -- A header for more than the input holds is rejected without reading as much.
  expectError "skip of a truncated map 32" skip #[0xDF, 0xFF, 0xFF, 0xFF, 0xFF]
  expectError "truncated str 32" readStr #[0xDB, 0xFF, 0xFF, 0xFF, 0xFF, 0x41]
  expectError "skip of the unused format" skip #[0xC1]
  -- {"b": false, "zz": 1, "a": 3, "names": {"n": {}}}: any order, an unknown key skipped.
  expectOk "struct" Sample.read
    #[
      0x84,
      0xA1,
      0x62,
      0xC2,
      0xA2,
      0x7A,
      0x7A,
      0x01,
      0xA1,
      0x61,
      0x03,
      0xA5,
      0x6E,
      0x61,
      0x6D,
      0x65,
      0x73,
      0x81,
      0xA1,
      0x6E,
      0x80
    ]
    { a := 3, b := some false, names := ["n"] }
  -- {"a": 3, "names": {}}: an optional field may be absent.
  expectOk "struct without its optional field" Sample.read
    #[0x82, 0xA1, 0x61, 0x03, 0xA5, 0x6E, 0x61, 0x6D, 0x65, 0x73, 0x80]
    { a := 3, b := none, names := [] }
  -- {"names": {}}
  expectError "struct without a required field" Sample.read
    #[0x81, 0xA5, 0x6E, 0x61, 0x6D, 0x65, 0x73, 0x80]
  expectOk "strict struct" Strict.read #[0x81, 0xA1, 0x78, 0x09] { x := 9 }
  -- {"x": 9, "y": 1}
  expectError "strict struct with an unknown key" Strict.read
    #[0x82, 0xA1, 0x78, 0x09, 0xA1, 0x79, 0x01]
  IO.println "Msgpack reader checks passed."

#eval run

end CCF.Tests.Msgpack
