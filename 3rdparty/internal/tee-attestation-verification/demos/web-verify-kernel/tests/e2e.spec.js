// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// End-to-end test for the web-verify-kernel demo.
//
// Drives a real browser, loads the demo page from a static server rooted at
// the demo directory (see playwright.config.js), populates the four inputs
// with the Milan test fixtures, clicks Verify, and diffs the rendered output
// against a committed golden file.
//
// Regenerate the golden with:  UPDATE_GOLDEN=1 npx playwright test

import { test, expect } from "@playwright/test";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const goldenPath = resolve(here, "milan_report.expected.txt");

// Fixture paths (HTTP-relative); served from the demo dir's `test-data/`.
const FIXTURES = {
  milanReport: "/test-data/milan_attestation_report.bin",
  milanVcek:   "/test-data/milan_vcek.pem",
  milanAsk:    "/test-data/milan_ask.pem",
  milanArk:    "/test-data/milan_ark.pem",
  turinArk:    "/test-data/turin_ark.pem",
};

test("Milan fixture renders the expected report", async ({ page, baseURL }) => {
  // Fetch fixtures via the same static server the browser uses. Doing the
  // fetches from Node keeps the test deterministic even if fetch APIs in
  // the page context misbehave.
  const get = async path => {
    const r = await fetch(baseURL + path);
    if (!r.ok) throw new Error(`fetch ${path} -> ${r.status}`);
    return r;
  };
  const reportBytes = new Uint8Array(await (await get(FIXTURES.milanReport)).arrayBuffer());
  const vcekPem = await (await get(FIXTURES.milanVcek)).text();
  const askPem  = await (await get(FIXTURES.milanAsk)).text();
  const arkPem  = await (await get(FIXTURES.milanArk)).text();

  // Surface page errors to the test log.
  page.on("pageerror", err => console.log("[pageerror]", err.message));
  page.on("console", msg => {
    if (msg.type() === "error") console.log("[console.error]", msg.text());
  });

  await page.goto("/");

  // Populate the textareas directly (bypass the file pickers — upload input
  // automation varies between browsers, and the textareas are the single
  // source of truth on submit).
  const reportHex = Array.from(reportBytes, b => b.toString(16).padStart(2, "0")).join("");
  await page.locator("#report-hex").fill(reportHex);
  await page.locator("#vcek-text").fill(vcekPem);
  await page.locator("#ask-text").fill(askPem);
  await page.locator("#ark-text").fill(arkPem);

  await page.locator('button[type="submit"]').click();

  // Wait for verification to finish (status turns green on success, red on
  // failure). Generous timeout: WASM init + WebCrypto ECDSA chain validation.
  await expect(page.locator("#status")).toHaveClass(/ok|err/, { timeout: 30_000 });
  const statusClass = await page.locator("#status").getAttribute("class");
  const statusText = await page.locator("#status").textContent();
  if (statusClass !== "ok") {
    throw new Error(`Verification did not succeed: status="${statusText}"`);
  }

  const rendered = await page.locator("#output").textContent();

  if (process.env.UPDATE_GOLDEN) {
    await writeFile(goldenPath, rendered);
    console.log(`Wrote golden: ${goldenPath} (${rendered.length} bytes)`);
    return;
  }

  const expected = await readFile(goldenPath, "utf8");
  expect(rendered).toBe(expected);
});

test("ASK/ARK bundle can be split into certificate inputs before verification", async ({ page, baseURL }) => {
  const get = async path => {
    const r = await fetch(baseURL + path);
    if (!r.ok) throw new Error(`fetch ${path} -> ${r.status}`);
    return r;
  };
  const reportBytes = new Uint8Array(await (await get(FIXTURES.milanReport)).arrayBuffer());
  const vcekPem = await (await get(FIXTURES.milanVcek)).text();
  const askPem  = await (await get(FIXTURES.milanAsk)).text();
  const arkPem  = await (await get(FIXTURES.milanArk)).text();

  await page.goto("/");

  const reportHex = Array.from(reportBytes, b => b.toString(16).padStart(2, "0")).join("");
  await page.locator("#report-hex").fill(reportHex);
  await page.locator("#vcek-text").fill(vcekPem);
  await page.locator("#bundle-text").fill(`${askPem}\n${arkPem}`);

  await page.locator("#split-bundle").click();

  await expect(page.locator("#status")).toHaveClass("ok", { timeout: 30_000 });
  await expect(page.locator("#status")).toHaveText("Split 2 certificates from bundle into ASK and ARK fields.");
  const splitAsk = await page.locator("#ask-text").inputValue();
  const splitArk = await page.locator("#ark-text").inputValue();
  expect(splitAsk).toContain("-----BEGIN CERTIFICATE-----");
  expect(splitArk).toContain("-----BEGIN CERTIFICATE-----");
  expect(splitAsk).not.toBe(splitArk);

  await page.locator('button[type="submit"]').click();
  await expect(page.locator("#status")).toHaveClass("ok", { timeout: 30_000 });
  await expect(page.locator("#status")).toHaveText("Signature chain verified against supplied ARK.");
  await expect(page.locator("#output")).not.toHaveText("");
});

test("mismatched ARK (Turin against Milan chain) surfaces a verification error and suppresses output", async ({ page, baseURL }) => {
  // Use the real Milan fixtures for everything except the ARK, which is
  // replaced with the Turin ARK. This is a valid certificate but does not
  // root the Milan VCEK→ASK chain, exercising the chain-validation error
  // path of demo.js and confirming that no partial/stale output is shown
  // on failure.
  const get = async path => {
    const r = await fetch(baseURL + path);
    if (!r.ok) throw new Error(`fetch ${path} -> ${r.status}`);
    return r;
  };
  const reportBytes = new Uint8Array(await (await get(FIXTURES.milanReport)).arrayBuffer());
  const vcekPem = await (await get(FIXTURES.milanVcek)).text();
  const askPem  = await (await get(FIXTURES.milanAsk)).text();
  const turinArkPem = await (await get(FIXTURES.turinArk)).text();

  await page.goto("/");

  const reportHex = Array.from(reportBytes, b => b.toString(16).padStart(2, "0")).join("");
  await page.locator("#report-hex").fill(reportHex);
  await page.locator("#vcek-text").fill(vcekPem);
  await page.locator("#ask-text").fill(askPem);
  await page.locator("#ark-text").fill(turinArkPem);

  await page.locator('button[type="submit"]').click();

  // Status must end up in the error state.
  await expect(page.locator("#status")).toHaveClass("err", { timeout: 30_000 });

  // A Turin ARK against a Milan VCEK→ASK chain surfaces as
  // ErrorCode::InvalidRootCertificate (102). `ErrorCode` is the JS-facing
  // name (see `#[wasm_bindgen(js_name = "ErrorCode")]`) for `TavErrorCode`
  // in ffi/src/lib.rs — the same enum used by the C ABI.
  const statusText = await page.locator("#status").textContent();
  expect(statusText).toMatch(/^Verification failed \(code 102\): /);

  // The output pane must remain empty so callers can't mistake an error run
  // for a successful verification.
  await expect(page.locator("#output")).toHaveText("");
});
