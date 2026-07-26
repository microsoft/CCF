// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { test, expect } from "@playwright/test";

const FIXTURES = {
  caciReport: "/test-data/aci-report.hex",
  hostAmdCert: "/test-data/host-amd-cert.base64",
  referenceInfo: "/test-data/reference-info.base64",
};

const bytesToHex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");

test("Confidential CACI execution policy fixture verifies and returns report data", async ({ page, baseURL }) => {
  await verifyFixture(page, baseURL, ({ reportedTcbHex }) => JSON.stringify({ "00a00f11": reportedTcbHex }));
});

test("Confidential CACI execution policy fixture verifies without minimum TCB policy", async ({ page, baseURL }) => {
  await verifyFixture(page, baseURL, () => "");
});

async function verifyFixture(page, baseURL, minimumTcbJson) {
  const get = async path => {
    const r = await fetch(baseURL + path);
    if (!r.ok) throw new Error(`fetch ${path} -> ${r.status}`);
    return r;
  };
  const reportHex = (await (await get(FIXTURES.caciReport)).text()).trim();
  const reportBytes = new Uint8Array(reportHex.match(/../g).map(byte => Number.parseInt(byte, 16)));
  const hostAmdCert = await (await get(FIXTURES.hostAmdCert)).text();
  const referenceInfo = await (await get(FIXTURES.referenceInfo)).text();
  const hostDataHex = bytesToHex(reportBytes.slice(0x0c0, 0x0c0 + 32));
  const reportedTcbHex = bytesToHex(reportBytes.slice(0x180, 0x180 + 8));
  const reportDataHex = bytesToHex(reportBytes.slice(0x050, 0x050 + 64));

  await page.goto("/");

  await page.locator("#report-hex").fill(reportHex);
  await page.locator("#amd-bundle-text").fill(hostAmdCert);
  await page.locator("#uvm-text").fill(referenceInfo);
  await page.locator("#policy-hex").fill(`${"00".repeat(32)}\n${hostDataHex}`);
  await page.locator("#minimum-tcb-json").fill(minimumTcbJson({ reportedTcbHex }));
  await page.locator("#feed").fill("ContainerPlat-AMD-UVM");
  await page.locator("#minimum-svn").fill("104");

  await page.locator('#caci-form button[type="submit"]').click();

  await expect(page.locator("#status")).toHaveClass("ok", { timeout: 30_000 });
  await expect(page.locator("#status")).toHaveText("Confidential CACI execution policy verified.");
  await expect(page.locator("#output")).toContainText("verified_report_data");
  await expect(page.locator("#output")).toContainText("verified_snp_attestation");
  await expect(page.locator("#output")).toContainText("verified_uvm_cose");
  await expect(page.locator("#output")).toContainText("protected_headers");
  await expect(page.locator("#output")).toContainText("unprotected_headers");
  await expect(page.locator("#output")).toContainText("reference_info_payload");
  await expect(page.locator("#output")).toContainText(reportDataHex.slice(0, 32));
  await expect(page.locator("#output")).toContainText(hostDataHex.slice(0, 32));
  await expect(page.locator("#output")).toContainText("feed: ContainerPlat-AMD-UVM");
  await expect(page.locator("#output")).toContainText("content_type: application/json");
  await expect(page.locator("#output")).toContainText('"iss": "did:x509:0:sha256');
  await expect(page.locator("#output")).toContainText('"timestamp": h');
  await expect(page.locator("#output")).toContainText("x-ms-sevsnpvm-guestsvn: 104");
}

test("manifest populates a good example", async ({ page }) => {
  await page.goto("/");

  await page.locator("#load-example").click();

  await expect(page.locator("#status")).toHaveClass("ok", { timeout: 30_000 });
  await expect(page.locator("#status")).toHaveText("Loaded good example from manifest.");
  await expect(page.locator("#report-hex")).not.toHaveValue("");
  await expect(page.locator("#amd-bundle-text")).not.toHaveValue("");
  await expect(page.locator("#uvm-text")).not.toHaveValue("");
  await expect(page.locator("#policy-hex")).not.toHaveValue("");
  await expect(page.locator("#minimum-tcb-json")).toHaveValue(/00a00f11/);
});
