// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { beforeEach, describe, it } from "node:test";
import { runInNewContext } from "node:vm";
import forge from "node-forge";
import "../src/polyfill.js";
import { ccf } from "../src/global.js";
import { generateSelfSignedCert } from "./crypto.js";

const constitution = readFileSync(
  "../../samples/constitutions/default/actions.js",
  "utf8",
);
const proposalScripts = ["validate", "apply"]
  .map((name) =>
    readFileSync(
      `../../samples/constitutions/default/${name}.js`,
      "utf8",
    ).replace("export function", "function"),
  )
  .join("\n");
const { cert, privateKey } = generateSelfSignedCert();
const renewed = forge.pki.certificateFromPem(cert);
renewed.serialNumber = "01";
renewed.sign(forge.pki.privateKeyFromPem(privateKey), forge.md.sha256.create());
const replacement = forge.pki.certificateToPem(renewed);
const did = ccf.pemToId(cert, "did:key");

beforeEach(() => {
  for (const name of Object.getOwnPropertyNames(ccf.kv)) {
    delete ccf.kv[name];
  }
  ccf.kv["public:ccf.gov.service.info"].set(
    new ArrayBuffer(8),
    ccf.jsonCompatibleToBuf({ status: "Open" }),
  );
});

function validate(input: string): { valid: boolean; description: string } {
  return runInNewContext(
    `${constitution}\n${proposalScripts}\nvalidate(input);`,
    { ccf, input },
  );
}

function apply(input: string): void {
  runInNewContext(`${constitution}\n${proposalScripts}\napply(input);`, {
    ccf,
    input,
  });
}

for (const role of ["member", "user"]) {
  const certsTable = `public:ccf.gov.${role}s.certs`;
  const keysTable = `public:ccf.gov.${role}s.public_keys`;
  const infoTable = `public:ccf.gov.${role}s.info`;
  const legacyId = ccf.pemToId(cert);

  function setAction(args: object) {
    return {
      name: `set_${role}`,
      args: { ...args, [`${role}_data`]: { v: 1 } },
    };
  }

  function removeAction(id: string) {
    return { name: `remove_${role}`, args: { [`${role}_id`]: id } };
  }

  describe(`${role} identity enrollment`, () => {
    function enroll(args: {
      cert?: string;
      id_format?: string;
      did_key?: string;
    }): void {
      runInNewContext(`${constitution}\ncheckIdentityEnrollment(args);`, {
        ccf,
        args,
      });
    }

    it("accepts a DID alone and rejects certificate-shaped DID enrollment", () => {
      enroll({ did_key: did });
      enroll({ cert });
      for (const args of [
        {},
        { did_key: did, cert },
        { did_key: did, id_format: "did:key" },
        { cert, id_format: "did:key" },
        { cert, id_format: "sha256" },
        { did_key: "did:key:zinvalid" },
        { did_key: did + "#fragment" },
      ]) {
        assert.throws(() => enroll(args));
      }
    });

    it("enrolls the same key under both ID formats independently", () => {
      const both = JSON.stringify({
        actions: [setAction({ cert }), setAction({ did_key: did })],
      });
      const result = validate(both);
      assert.equal(result.valid, true, result.description);
      apply(both);
      assert.deepEqual(
        ccf.kv[certsTable].get(ccf.strToBuf(legacyId)),
        ccf.strToBuf(cert),
      );
      assert.deepEqual(
        ccf.kv[keysTable].get(ccf.strToBuf(did)),
        ccf.publicKeyFromDidKey(did),
      );
      assert.equal(ccf.kv[infoTable].has(ccf.strToBuf(legacyId)), true);
      assert.equal(ccf.kv[infoTable].has(ccf.strToBuf(did)), true);

      const replacementId = ccf.pemToId(replacement);
      const renewal = JSON.stringify({
        actions: [setAction({ cert: replacement })],
      });
      assert.equal(validate(renewal).valid, true);
      apply(renewal);
      assert.equal(ccf.kv[certsTable].has(ccf.strToBuf(replacementId)), true);

      const removal = JSON.stringify({ actions: [removeAction(legacyId)] });
      assert.equal(validate(removal).valid, true);
      apply(removal);
      assert.equal(ccf.kv[certsTable].has(ccf.strToBuf(legacyId)), false);
      assert.equal(ccf.kv[certsTable].has(ccf.strToBuf(replacementId)), true);
      assert.equal(ccf.kv[keysTable].has(ccf.strToBuf(did)), true);
      assert.equal(ccf.kv[infoTable].has(ccf.strToBuf(did)), true);
    });

    it("removes a DID enrollment without affecting a legacy one", () => {
      apply(
        JSON.stringify({
          actions: [setAction({ cert }), setAction({ did_key: did })],
        }),
      );
      const removal = JSON.stringify({ actions: [removeAction(did)] });
      assert.equal(validate(removal).valid, true);
      apply(removal);
      assert.equal(ccf.kv[keysTable].has(ccf.strToBuf(did)), false);
      assert.equal(ccf.kv[infoTable].has(ccf.strToBuf(did)), false);
      assert.equal(ccf.kv[certsTable].has(ccf.strToBuf(legacyId)), true);
      assert.equal(ccf.kv[infoTable].has(ccf.strToBuf(legacyId)), true);
    });
  });
}

describe("set_member re-enrollment", () => {
  it("resets activation without storing a certificate", () => {
    const input = JSON.stringify({
      actions: [
        { name: "set_member", args: { did_key: did, member_data: { v: 1 } } },
      ],
    });
    assert.equal(validate(input).valid, true);
    apply(input);
    ccf.kv["public:ccf.gov.members.info"].set(
      ccf.strToBuf(did),
      ccf.jsonCompatibleToBuf({ status: "Active", member_data: { v: 1 } }),
    );
    ccf.kv["public:ccf.gov.members.acks"].set(
      ccf.strToBuf(did),
      ccf.strToBuf("ack"),
    );
    apply(input);
    assert.deepEqual(
      ccf.bufToJsonCompatible(
        ccf.kv["public:ccf.gov.members.info"].get(ccf.strToBuf(did))!,
      ),
      { status: "Accepted", member_data: { v: 1 } },
    );
    assert.equal(
      ccf.kv["public:ccf.gov.members.acks"].has(ccf.strToBuf(did)),
      false,
    );
    assert.equal(ccf.kv["public:ccf.gov.members.certs"].size, 0);
  });
});
