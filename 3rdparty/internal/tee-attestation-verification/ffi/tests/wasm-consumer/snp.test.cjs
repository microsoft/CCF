// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Consumer-facing API-compatibility tests for the SNP surface of the generated
// wasm bundle: the SnpAttestationReport accessors and verify_attestation_async.
// Each test drives the exported functions exactly as an external JS consumer
// would, covering both the success path and the failure modes.

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  pkg,
  loadMilanInputs,
  verifiedMilanReport,
  assertRejectsVerifyError,
} = require('./support.cjs');

test('attestation accessors expose every SnpAttestationReport getter', async () => {
  const attestation = await verifiedMilanReport();
  assert.ok(attestation instanceof pkg.SnpAttestationReport);

  assert.equal(attestation.version, 3);
  assert.equal(typeof attestation.guest_svn, 'number');
  assert.equal(typeof attestation.policy, 'bigint');
  assert.equal(typeof attestation.policy_abi_minor, 'number');
  assert.equal(typeof attestation.policy_abi_major, 'number');
  assert.equal(typeof attestation.policy_smt, 'boolean');
  assert.equal(typeof attestation.policy_migrate_ma, 'boolean');
  assert.equal(typeof attestation.policy_debug, 'boolean');
  assert.equal(typeof attestation.policy_single_socket, 'boolean');
  assert.equal(typeof attestation.policy_cxl_allow, 'boolean');
  assert.equal(typeof attestation.policy_mem_aes_256_xts, 'boolean');
  assert.equal(typeof attestation.policy_rapl_dis, 'boolean');
  assert.equal(typeof attestation.policy_ciphertext_hiding_dram, 'boolean');
  assert.equal(typeof attestation.policy_page_swap_disable, 'boolean');
  assert.equal(typeof attestation.vmpl, 'number');
  assert.equal(typeof attestation.signature_algo, 'number');
  assert.equal(typeof attestation.platform_info, 'bigint');
  assert.equal(typeof attestation.flags, 'number');
  assert.equal(typeof attestation.flags_author_key_en, 'boolean');
  assert.equal(typeof attestation.flags_mask_chip_key, 'boolean');
  assert.equal(typeof attestation.flags_signing_key, 'number');
  assert.equal(typeof attestation.cpuid_fam_id, 'number');
  assert.equal(typeof attestation.cpuid_mod_id, 'number');
  assert.equal(typeof attestation.cpuid_step, 'number');
  assert.equal(typeof attestation.current_build, 'number');
  assert.equal(typeof attestation.current_minor, 'number');
  assert.equal(typeof attestation.current_major, 'number');
  assert.equal(typeof attestation.committed_build, 'number');
  assert.equal(typeof attestation.committed_minor, 'number');
  assert.equal(typeof attestation.committed_major, 'number');

  const byteFields = {
    family_id: 16,
    image_id: 16,
    platform_version: 8,
    report_data: 64,
    measurement: 48,
    host_data: 32,
    id_key_digest: 48,
    author_key_digest: 48,
    report_id: 32,
    report_id_ma: 32,
    reported_tcb: 8,
    chip_id: 64,
    committed_tcb: 8,
    launch_tcb: 8,
    signature_r: 72,
    signature_s: 72,
  };
  for (const [name, length] of Object.entries(byteFields)) {
    assert.ok(attestation[name] instanceof Uint8Array, `${name} should be Uint8Array`);
    assert.equal(attestation[name].length, length, `${name} length`);
  }

  // Assert concrete decoded values from the known-good Milan fixture so the
  // accessors are checked for correctness, not just shape.
  const toHex = (bytes) => Buffer.from(bytes).toString('hex');
  assert.equal(attestation.guest_svn, 2);
  assert.equal(attestation.vmpl, 0);
  assert.equal(attestation.policy, 196639n);
  assert.equal(attestation.signature_algo, 1);
  assert.equal(toHex(attestation.report_data), '00'.repeat(64));
  assert.equal(toHex(attestation.host_data), '4f4448c67f3c8dfc8de8a5e37125d807dadcc41f06cf23f615dbd52eec777d10');
  assert.equal(toHex(attestation.family_id), '01000000000000000000000000000000');
  assert.equal(toHex(attestation.image_id), '02000000000000000000000000000000');
  assert.equal(
    toHex(attestation.measurement),
    '5feee30d6d7e1a29f403d70a4198237ddfb13051a2d6976439487c609388ed7f98189887920ab2fa0096903a0c23fca1',
  );
  assert.equal(
    toHex(attestation.chip_id),
    '4ffb5cb4fd594f3fee6528fc3fb10370bb38abe89dcd5ba2cf0ab6a11df2ca282add516bef45a890a8c9f9732bdca68f9f3f16c42e846030a800295dbeb19ba5',
  );
  assert.equal(
    toHex(attestation.report_id),
    '5e01036273418d910bdca3f5cb9c7d849e88e2141483eb6cc9afd794ffbbbcbc',
  );
});

// SNP verify attestation: verify_attestation_async (typed VerifyError).
test('snp verify attestation returns a report and rejects an invalid root', async () => {
  const { report, ark, ask, vcek } = loadMilanInputs();

  const attestation = await pkg.verify_attestation_async(report, ark, ask, vcek);
  assert.ok(attestation instanceof pkg.SnpAttestationReport);
  assert.equal(attestation.version, 3);

  // Failure mode: swapping ASK in as the ARK breaks the root of trust.
  await assertRejectsVerifyError(
    pkg.verify_attestation_async(report, ask, ask, vcek),
    pkg.ErrorCode.InvalidRootCertificate,
    /Invalid root certificate/,
  );

  // Malformed inputs are rejected as InvalidArgument before verification runs.
  await assertRejectsVerifyError(
    pkg.verify_attestation_async(new Uint8Array(), ark, ask, vcek),
    pkg.ErrorCode.InvalidArgument,
    /expected 1184 bytes, got 0/,
  );
  await assertRejectsVerifyError(
    pkg.verify_attestation_async(report.slice(0, 100), ark, ask, vcek),
    pkg.ErrorCode.InvalidArgument,
    /Invalid attestation report/,
  );
  await assertRejectsVerifyError(
    pkg.verify_attestation_async(report, 'not a pem', ask, vcek),
    pkg.ErrorCode.InvalidArgument,
    /ARK PEM/,
  );
  await assertRejectsVerifyError(
    pkg.verify_attestation_async(report, ark, 'not a pem', vcek),
    pkg.ErrorCode.InvalidArgument,
    /ASK PEM/,
  );
  await assertRejectsVerifyError(
    pkg.verify_attestation_async(report, ark, ask, 'not a pem'),
    pkg.ErrorCode.InvalidArgument,
    /VCEK PEM/,
  );

  // A tampered report body fails AMD signature verification.
  const corrupted = Uint8Array.from(report);
  corrupted[100] ^= 0xff;
  await assertRejectsVerifyError(
    pkg.verify_attestation_async(corrupted, ark, ask, vcek),
    pkg.ErrorCode.SignatureVerificationError,
  );
});
