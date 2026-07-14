// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Consumer-facing API-compatibility tests for the COSE/CBOR surface of the
// generated wasm bundle: CborValue decoding, the CoseSign1 wrapper, and
// standalone COSE_Sign1 signature verification (verify_embedded / verify_detached).

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  pkg,
  textBytes,
  assertStringError,
  assertRejectsStringError,
} = require('./support.cjs');

// CBOR accessors: CborValue decoding plus the CoseSign1 wrapper.
test('cbor accessors decode scalars, containers, tags, and COSE_Sign1', () => {
  const intValue = pkg.CborValue.from_bytes(Uint8Array.of(0x01));
  assert.equal(intValue.kind(), 'int');
  assert.equal(intValue.int(), 1n);
  assert.deepEqual(Array.from(intValue.to_bytes()), [0x01]);

  const simpleValue = pkg.CborValue.from_bytes(Uint8Array.of(0xf6));
  assert.equal(simpleValue.kind(), 'simple');
  assert.equal(simpleValue.simple(), 22);

  const bytesValue = pkg.CborValue.from_bytes(Uint8Array.of(0x43, 1, 2, 3));
  assert.equal(bytesValue.kind(), 'bytes');
  assert.deepEqual(Array.from(bytesValue.bytes()), [1, 2, 3]);

  const textValue = pkg.CborValue.from_bytes(Uint8Array.of(0x62, 0x68, 0x69));
  assert.equal(textValue.kind(), 'text');
  assert.equal(textValue.text(), 'hi');

  const arrayValue = pkg.CborValue.from_bytes(Uint8Array.of(0x82, 0x01, 0x61, 0x61));
  assert.equal(arrayValue.kind(), 'array');
  assert.equal(arrayValue.len(), 2);
  assert.equal(arrayValue.array_at(0).int(), 1n);
  assert.equal(arrayValue.array_at(1).text(), 'a');

  const mapValue = pkg.CborValue.from_bytes(Uint8Array.of(
    0xa2,
    0x01, 0x63, 0x6f, 0x6e, 0x65,
    0x61, 0x6b, 0x81, 0xf6,
  ));
  assert.equal(mapValue.kind(), 'map');
  assert.equal(mapValue.len(), 2);
  assert.equal(mapValue.map_at_int(1n).text(), 'one');
  assert.equal(mapValue.map_at_text('k').array_at(0).simple(), 22);
  assert.equal(mapValue.map_at(pkg.CborValue.from_bytes(Uint8Array.of(0x01))).text(), 'one');
  const entry = mapValue.map_entry_at(0);
  assert.equal(entry.length, 2);
  assert.equal(entry[0].int(), 1n);
  assert.equal(entry[1].text(), 'one');
  assert.equal(mapValue.map_key_at(1).text(), 'k');
  assert.equal(mapValue.map_value_at(1).array_at(0).simple(), 22);
  assert.equal(mapValue.map_has_int(1n), true);
  assert.equal(mapValue.map_has_int(2n), false);
  assert.equal(mapValue.map_has_text('k'), true);
  assert.equal(mapValue.map_has_text('x'), false);
  assert.equal(mapValue.map_has(pkg.CborValue.from_bytes(Uint8Array.of(0x01))), true);

  const taggedValue = pkg.CborValue.from_bytes(Uint8Array.of(0xc1, 0x18, 0x2a));
  assert.equal(taggedValue.kind(), 'tagged');
  assert.equal(taggedValue.tag(), 1n);
  assert.equal(taggedValue.tagged_payload().int(), 42n);

  const sign1Bytes = Uint8Array.of(
    0xd2, 0x84,
    0x43, 0xa1, 0x01, 0x26,
    0xa0,
    0x45, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
    0x43, 0x01, 0x02, 0x03,
  );
  const sign1 = pkg.CborValue.from_bytes(sign1Bytes).as_cose_sign1();
  assert.ok(sign1 instanceof pkg.CoseSign1);
  assert.deepEqual(Array.from(sign1.protected()), [0xa1, 0x01, 0x26]);
  assert.equal(sign1.protected_header().map_at_int(1n).int(), -7n);
  assert.equal(sign1.unprotected().kind(), 'map');
  assert.equal(sign1.payload().toString(), Uint8Array.of(0x68, 0x65, 0x6c, 0x6c, 0x6f).toString());
  assert.deepEqual(Array.from(sign1.signature()), [1, 2, 3]);

  // Failure mode: CborValue accessor type mismatches raise string errors.
  assertStringError(() => intValue.text(), /Expected TextString/);
  // Failure mode: a CoseSign1 accessor over a malformed structure (null payload
  // where a byte string is required) raises the shipped string error.
  const malformedSign1 = pkg.CborValue.from_bytes(Uint8Array.of(
    0xd2, 0x84,
    0x43, 0xa1, 0x01, 0x26,
    0xa0,
    0xf6,
    0x43, 0x01, 0x02, 0x03,
  )).as_cose_sign1();
  assertStringError(() => malformedSign1.payload(), /payload must be a byte string/);
});

// Standalone COSE_Sign1 signature verification: the wasm equivalent of the C
// ABI tav_verify_cose_sign1_embedded / tav_verify_cose_sign1_detached. Uses the
// same P-256 verification-only vector as the C consumer and in-crate tests.
const COSE_ALG_ES256 = -7;
const COSE_PHDR = [0xa1, 0x01, 0x26];
const COSE_PAYLOAD = textBytes('verification-only COSE vector');
const COSE_SPKI = new Uint8Array([
  48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61,
  3, 1, 7, 3, 66, 0, 4, 201, 171, 117, 35, 159, 13, 22, 69, 184, 252, 18, 119,
  177, 246, 18, 133, 248, 151, 60, 164, 201, 112, 233, 4, 224, 54, 241, 53, 11,
  85, 3, 249, 180, 113, 248, 87, 244, 106, 253, 83, 32, 139, 158, 31, 51, 72,
  167, 32, 114, 51, 92, 109, 60, 158, 23, 216, 2, 11, 126, 11, 242, 186, 211,
  205,
]);
const COSE_SIG = [
  90, 37, 149, 163, 211, 129, 174, 167, 177, 116, 232, 19, 137, 13, 86, 18, 47,
  248, 221, 245, 81, 132, 222, 25, 6, 230, 131, 70, 41, 27, 154, 74, 57, 92,
  210, 184, 112, 104, 224, 64, 234, 0, 184, 153, 253, 249, 148, 125, 58, 93,
  103, 128, 147, 144, 252, 13, 252, 91, 233, 88, 189, 169, 103, 151,
];

// Append a CBOR byte string (major type 2) for buffers up to 255 bytes.
function putBstr(out, bytes) {
  if (bytes.length < 24) out.push(0x40 | bytes.length);
  else out.push(0x58, bytes.length);
  for (const b of bytes) out.push(b);
}

// Build a tagged (18) COSE_Sign1 envelope [protected, {}, payload, signature].
// With embeddedPayload false the payload slot is CBOR null (detached).
function buildSign1(embeddedPayload) {
  const env = [0xd2, 0x84];
  putBstr(env, COSE_PHDR);
  env.push(0xa0); // empty unprotected header map
  if (embeddedPayload) putBstr(env, COSE_PAYLOAD);
  else env.push(0xf6); // CBOR null
  putBstr(env, COSE_SIG);
  return new Uint8Array(env);
}

function coseSign1(bytes) {
  return pkg.CborValue.from_bytes(bytes).as_cose_sign1();
}

test('CoseSign1.verify_embedded accepts a valid signature and rejects tampering', async () => {
  // Valid embedded signature resolves.
  await coseSign1(buildSign1(true)).verify_embedded(COSE_SPKI, COSE_ALG_ES256);

  // Corrupting the trailing signature byte makes verification fail; a verifier
  // that skipped the signature check would wrongly resolve.
  const tampered = buildSign1(true);
  tampered[tampered.length - 1] ^= 0xff;
  await assertRejectsStringError(
    coseSign1(tampered).verify_embedded(COSE_SPKI, COSE_ALG_ES256),
  );
});

test('CoseSign1.verify_detached accepts a nil payload and rejects an embedded one', async () => {
  // A detached envelope (nil payload) verifies against the caller-supplied payload.
  await coseSign1(buildSign1(false)).verify_detached(COSE_PAYLOAD, COSE_SPKI, COSE_ALG_ES256);

  // The wrong detached payload fails the signature check.
  await assertRejectsStringError(
    coseSign1(buildSign1(false)).verify_detached(
      textBytes('a different payload'),
      COSE_SPKI,
      COSE_ALG_ES256,
    ),
  );

  // An embedded (byte-string) payload is rejected by detached verification.
  await assertRejectsStringError(
    coseSign1(buildSign1(true)).verify_detached(COSE_PAYLOAD, COSE_SPKI, COSE_ALG_ES256),
    /nil COSE payload/,
  );
});
