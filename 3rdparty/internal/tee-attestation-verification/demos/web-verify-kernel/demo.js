// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import init, {
  split_certificate_bundle,
  verify_attestation_async,
} from "./pkg/tee_attestation_verification_ffi.js";

const statusEl = document.getElementById("status");
const outputEl = document.getElementById("output");
let wasmInitPromise;

function setStatus(msg, kind = "") {
  statusEl.textContent = msg;
  statusEl.className = kind;
}

function ensureWasmLoaded() {
  if (!wasmInitPromise) {
    wasmInitPromise = init();
  }
  return wasmInitPromise;
}

// ----- input helpers --------------------------------------------------------

function hexToBytes(hex) {
  const clean = hex.replace(/\s+/g, "");
  if (clean.length === 0) return null;
  if (clean.length % 2 !== 0) throw new Error("hex string has odd length");
  if (!/^[0-9a-fA-F]+$/.test(clean)) throw new Error("hex string contains non-hex characters");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// Wire up file inputs so picking a file populates the matching textarea.
// The textareas remain the single source of truth on submit, so users can
// see (and edit) exactly what will be verified.
function wireFileToText(fileId, textId, transform) {
  const fileEl = document.getElementById(fileId);
  const textEl = document.getElementById(textId);
  fileEl.addEventListener("change", async () => {
    const f = fileEl.files[0];
    if (!f) return;
    textEl.value = await transform(f);
  });
}

wireFileToText("report-file", "report-hex",
  async f => bytesToHex(new Uint8Array(await f.arrayBuffer())));
wireFileToText("vcek-file", "vcek-text", f => f.text());
wireFileToText("bundle-file", "bundle-text", f => f.text());
wireFileToText("ask-file",  "ask-text",  f => f.text());
wireFileToText("ark-file",  "ark-text",  f => f.text());

function getReportBytes() {
  const bytes = hexToBytes(document.getElementById("report-hex").value);
  if (!bytes) throw new Error("No attestation report provided (upload a file or paste hex)");
  return bytes;
}

function getPem(name, textId) {
  const text = document.getElementById(textId).value;
  if (!text.trim()) throw new Error(`No ${name} PEM provided (upload a file or paste text)`);
  return text;
}

function errorDetails(err) {
  const code = err && err.code !== undefined ? ` (code ${err.code})` : "";
  const msg = err && err.message ? err.message : String(err);
  return { code, msg };
}

// ----- formatting -----------------------------------------------------------

// Column at which values start in the rendered table. Chosen to match the
// sample output the demo is modelled on; the longest rendered field name
// (`author_key_digest`) fits with room for at least one trailing space.
const LABEL_WIDTH = 24;

const u8hex = n => n.toString(16).padStart(2, "0");
const u32hex = n => (n >>> 0).toString(16).padStart(8, "0");
const u64hex = n => BigInt(n).toString(16).padStart(16, "0");

const bytesToHex = bytes => Array.from(bytes, u8hex).join("");

// Format a byte array as the sample does:
//   - split into 16-byte groups (32 hex chars each)
//   - two groups per line, separated by a single space
//   - continuation lines indented under the value column
function fmtBytes(bytes) {
  const groups = [];
  for (let i = 0; i < bytes.length; i += 16) {
    groups.push(bytesToHex(bytes.slice(i, i + 16)));
  }
  const indent = " ".repeat(LABEL_WIDTH);
  const lines = [];
  for (let i = 0; i < groups.length; i += 2) {
    lines.push(groups.slice(i, i + 2).join(" "));
  }
  return lines.map((l, i) => (i === 0 ? l : indent + l)).join("\n");
}

const row = (name, value) => `  ${name}:`.padEnd(LABEL_WIDTH) + value;

// ----- rendering ------------------------------------------------------------

// Reserved regions in the AttestationReport struct (see src/snp/report.rs).
// The WASM bindings do not expose them because they are required by the SNP
// spec to be zero in any signed report; we render them as zeros of the
// correct width so the output matches the expected table layout.
const RESERVED_ZEROS = {
  r1: new Uint8Array(4),   // reserved0: [u8; 4]  @ 0x04C
  r2: new Uint8Array(21),  // reserved1: [u8; 21] @ 0x18B
  r5: new Uint8Array(168), // reserved4: [u8; 168] @ 0x1F8
};

function render(report) {
  const lines = [
    row("version",           u32hex(report.version)),
    row("guest_svn",         u32hex(report.guest_svn)),
    row("policy",            u64hex(report.policy)),
    row("family_id",         fmtBytes(report.family_id)),
    row("image_id",          fmtBytes(report.image_id)),
    row("vmpl",              u32hex(report.vmpl)),
    row("signature_algo",    u32hex(report.signature_algo)),
    row("current_tcb",       fmtBytes(report.platform_version)),
    row("platform_info",     u64hex(report.platform_info)),
    // The full u32 flags word at offset 0x48. `author_key_en` is bit 0, but
    // the sample labels the whole word `author_key_en` (the other bits are
    // mask_chip_key and signing_key, exposed separately via `flags_*`).
    row("author_key_en",     u32hex(report.flags)),
    row("reserved1",         bytesToHex(RESERVED_ZEROS.r1)),
    row("report_data",       fmtBytes(report.report_data)),
    row("measurement",       fmtBytes(report.measurement)),
    row("host_data",         fmtBytes(report.host_data)),
    row("id_key_digest",     fmtBytes(report.id_key_digest)),
    row("author_key_digest", fmtBytes(report.author_key_digest)),
    row("report_id",         fmtBytes(report.report_id)),
    row("report_id_ma",      fmtBytes(report.report_id_ma)),
    row("reported_tcb",      fmtBytes(report.reported_tcb)),
    row("cpuid_fam_id",      u8hex(report.cpuid_fam_id)),
    row("cpuid_mod_id",      u8hex(report.cpuid_mod_id)),
    row("cpuid_step",        u8hex(report.cpuid_step)),
    row("reserved2",         fmtBytes(RESERVED_ZEROS.r2)),
    row("chip_id",           fmtBytes(report.chip_id)),
    row("committed_tcb",     fmtBytes(report.committed_tcb)),
    row("current_build",     u8hex(report.current_build)),
    row("current_minor",     u8hex(report.current_minor)),
    row("current_major",     u8hex(report.current_major)),
    row("reserved3",         u8hex(0)),
    row("committed_build",   u8hex(report.committed_build)),
    row("committed_minor",   u8hex(report.committed_minor)),
    row("committed_major",   u8hex(report.committed_major)),
    row("reserved4",         u8hex(0)),
    row("launch_tcb",        fmtBytes(report.launch_tcb)),
    row("reserved5",         fmtBytes(RESERVED_ZEROS.r5)),
  ];

  // Signature on the wire is r(72) || s(72) || reserved(368), total 512 B.
  // r and s are returned from WASM as their raw 72-byte fields; zero-pad
  // the remainder.
  const sig = new Uint8Array(512);
  sig.set(report.signature_r, 0);
  sig.set(report.signature_s, 72);
  lines.push(row("signature", fmtBytes(sig)));

  return lines.join("\n");
}

// ----- main -----------------------------------------------------------------

async function onSplitBundle() {
  outputEl.textContent = "";
  setStatus("Loading WASM module...");
  try {
    await ensureWasmLoaded();
    setStatus("Splitting certificate bundle...");
    const bundlePem = getPem("certificate bundle", "bundle-text");
    const certificates = split_certificate_bundle(bundlePem);
    if (certificates.length !== 2) {
      throw new Error(`Expected 2 certificates (ASK then ARK), got ${certificates.length}`);
    }

    document.getElementById("ask-text").value = certificates[0];
    document.getElementById("ark-text").value = certificates[1];
    setStatus("Split 2 certificates from bundle into ASK and ARK fields.", "ok");
  } catch (err) {
    console.error(err);
    const { msg } = errorDetails(err);
    setStatus(`Bundle split failed: ${msg}`, "err");
  }
}

async function onSubmit(ev) {
  ev.preventDefault();
  outputEl.textContent = "";
  setStatus("Loading WASM module...");
  try {
    await ensureWasmLoaded();
    setStatus("Reading inputs...");
    const reportBytes = getReportBytes();
    const arkPem  = getPem("ARK",  "ark-text");
    const askPem  = getPem("ASK",  "ask-text");
    const vcekPem = getPem("VCEK", "vcek-text");
    setStatus(`Verifying ${reportBytes.length}-byte report...`);
    const report = await verify_attestation_async(reportBytes, arkPem, askPem, vcekPem);
    // Narrow success wording: the WASM call verifies only the certificate
    // chain (against the supplied ARK) and the report signature. It does not
    // enforce TCB/policy/measurement expectations — see the demo README.
    setStatus("Signature chain verified against supplied ARK.", "ok");
    outputEl.textContent = render(report);
  } catch (err) {
    // VerifyError from WASM has .code and .message getters; native JS errors
    // just have .message. Surface whichever we have, and log the raw object
    // to devtools for easier debugging.
    console.error(err);
    const { code, msg } = errorDetails(err);
    setStatus(`Verification failed${code}: ${msg}`, "err");
  }
}

document.getElementById("split-bundle").addEventListener("click", onSplitBundle);
document.getElementById("form").addEventListener("submit", onSubmit);
