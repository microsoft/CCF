// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Shared harness for the wasm consumer tests. Loads the generated
// `tee_attestation_verification_ffi.js` package exactly as an external JS
// consumer would, plus the fixture readers and error-assertion helpers reused
// across the per-area test files (snp / cose / caci).

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const repoRoot = path.resolve(__dirname, '../../..');
const pkg = require(path.join(repoRoot, 'target/wasm-consumer-tests/pkg/tee_attestation_verification_ffi.js'));

const TRUSTED_DIDX509 = 'did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.2';

function read(rel, encoding = undefined) {
  return fs.readFileSync(path.join(repoRoot, rel), encoding);
}

function readText(rel) {
  return read(rel, 'utf8');
}

function hexToBytes(hex) {
  const clean = hex.replace(/\s+/g, '');
  assert.equal(clean.length % 2, 0);
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function base64ToBytes(value) {
  return new Uint8Array(Buffer.from(value.replace(/\s+/g, ''), 'base64'));
}

function textBytes(value) {
  return new TextEncoder().encode(value);
}

function loadMilanInputs() {
  return {
    report: new Uint8Array(read('demos/web-verify-kernel/test-data/milan_attestation_report.bin')),
    ark: readText('demos/web-verify-kernel/test-data/milan_ark.pem'),
    ask: readText('demos/web-verify-kernel/test-data/milan_ask.pem'),
    vcek: readText('demos/web-verify-kernel/test-data/milan_vcek.pem'),
  };
}

function loadCaciInputs() {
  const manifest = JSON.parse(readText('demos/caci-attestation-verify/test-data/manifest.json'));
  const hostAmdCert = JSON.parse(new TextDecoder().decode(base64ToBytes(readText('demos/caci-attestation-verify/test-data/host-amd-cert.base64'))));
  // split_pem_bundle turns the ASK+ARK chain PEM into individual certificates.
  const chain = Array.from(pkg.split_pem_bundle(hostAmdCert.certificateChain));
  assert.equal(chain.length, 2);
  return {
    manifest,
    hostAmdCert,
    chain,
    report: hexToBytes(readText('demos/caci-attestation-verify/test-data/aci-report.hex')),
    endorsements: [hostAmdCert.vcekCert, chain[0], chain[1]].map(textBytes),
    uvmEndorsement: base64ToBytes(readText('demos/caci-attestation-verify/test-data/reference-info.base64')),
    policies: manifest.trusted_caci_execution_policies.map(hexToBytes),
  };
}

// A verified SNP report is the only way to obtain a SnpAttestationReport, so
// the accessor test reuses the real verification path to produce one.
async function verifiedMilanReport() {
  const { report, ark, ask, vcek } = loadMilanInputs();
  return pkg.verify_attestation_async(report, ark, ask, vcek);
}

function assertStringError(fn, messageSubstring) {
  assert.throws(fn, (err) => {
    assert.equal(typeof err, 'string', `expected string error, got ${err}`);
    if (messageSubstring) assert.match(err, messageSubstring);
    return true;
  });
}

async function assertRejectsStringError(promise, messageSubstring) {
  await assert.rejects(promise, (err) => {
    assert.equal(typeof err, 'string', `expected string error, got ${err}`);
    if (messageSubstring) assert.match(err, messageSubstring);
    return true;
  });
}

async function assertRejectsVerifyError(promise, code, messageSubstring) {
  await assert.rejects(promise, (err) => {
    assert.ok(err instanceof pkg.VerifyError, `expected VerifyError, got ${err}`);
    assert.equal(err.code, code);
    if (messageSubstring) assert.match(err.message, messageSubstring);
    return true;
  });
}

module.exports = {
  pkg,
  TRUSTED_DIDX509,
  textBytes,
  loadMilanInputs,
  loadCaciInputs,
  verifiedMilanReport,
  assertStringError,
  assertRejectsStringError,
  assertRejectsVerifyError,
};
