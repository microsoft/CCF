// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Consumer-facing API-compatibility tests for the CACI surface of the generated
// wasm bundle: verify_snp_attestation_with_cert_chain_async (plus the
// split_certificate_bundle / split_pem_bundle chain helpers),
// verify_uvm_endorsement_async, and the full verify_caci_attestation policy check.

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  pkg,
  TRUSTED_DIDX509,
  loadMilanInputs,
  loadCaciInputs,
  assertStringError,
  assertRejectsStringError,
} = require('./support.cjs');

// SNP verify with cert chain: verify_snp_attestation_with_cert_chain_async,
// including the split_certificate_bundle / split_pem_bundle helpers used to
// assemble the endorsement chain.
test('snp verify with cert chain accepts endorsements and rejects a bad chain', async () => {
  const { ask, ark } = loadMilanInputs();

  const splitSnp = Array.from(pkg.split_certificate_bundle(`${ask}\n${ark}`));
  assert.equal(splitSnp.length, 2);
  assert.match(splitSnp[0], /BEGIN CERTIFICATE/);
  assert.match(splitSnp[1], /BEGIN CERTIFICATE/);
  // Failure mode: splitting an empty bundle raises the shipped string error.
  assertStringError(() => pkg.split_certificate_bundle(''), /empty/);
  // A non-PEM bundle raises the parse string error rather than a VerifyError.
  assertStringError(() => pkg.split_certificate_bundle('not a pem'), /certificate bundle PEM/);
  // split_pem_bundle is a separate exported symbol with its own string error.
  assertStringError(() => pkg.split_pem_bundle(''), /empty/);

  const { report, endorsements } = loadCaciInputs();
  const attestation = await pkg.verify_snp_attestation_with_cert_chain_async(report, endorsements);
  assert.ok(attestation instanceof pkg.SnpAttestationReport);

  // Failure mode: the endorsement array must be exactly [vcek, ask, ark].
  await assertRejectsStringError(
    pkg.verify_snp_attestation_with_cert_chain_async(report, endorsements.slice(0, 2)),
    /expected AMD endorsements/,
  );
});

// verify_uvm_endorsement: verify_uvm_endorsement_async.
test('verify_uvm_endorsement returns a CBOR payload and rejects an untrusted root', async () => {
  const { uvmEndorsement } = loadCaciInputs();

  const uvm = await pkg.verify_uvm_endorsement_async(uvmEndorsement, TRUSTED_DIDX509);
  assert.ok(uvm instanceof pkg.CborValue);
  const sign1 = uvm.as_cose_sign1();
  assert.ok(sign1 instanceof pkg.CoseSign1);
  assert.ok(sign1.payload().length > 0);

  // Failure mode: a did:x509 root that doesn't match the chain is rejected.
  await assertRejectsStringError(
    pkg.verify_uvm_endorsement_async(
      uvmEndorsement,
      'did:x509:0:sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA::eku:1.3.6.1.4.1.311.76.59.1.2',
    ),
    /DID x509 policy error: issuer DID prefix .* does not match trusted DID prefix/,
  );
});

// verify_caci_attestation: the full relying-party policy check.
test('verify_caci_attestation returns report data and rejects an empty policy set', async () => {
  const { manifest, report, endorsements, uvmEndorsement, policies } = loadCaciInputs();

  const attestation = await pkg.verify_snp_attestation_with_cert_chain_async(report, endorsements);
  const uvm = await pkg.verify_uvm_endorsement_async(uvmEndorsement, TRUSTED_DIDX509);

  const reportData = await pkg.verify_caci_attestation(
    attestation,
    JSON.stringify(manifest.minimum_tcb),
    policies,
    uvm,
    manifest.uvm_feed,
    BigInt(manifest.minimum_svn),
  );
  assert.ok(reportData instanceof Uint8Array);
  assert.equal(reportData.length, 64);

  // Failure mode: at least one trusted execution policy digest is required.
  await assertRejectsStringError(
    pkg.verify_caci_attestation(
      attestation,
      JSON.stringify(manifest.minimum_tcb),
      [],
      uvm,
      manifest.uvm_feed,
      BigInt(manifest.minimum_svn),
    ),
    /at least one trusted CACI execution policy/,
  );
});
