// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { beforeEach, describe, it } from "node:test";
import { runInNewContext } from "node:vm";
import forge from "node-forge";
import "../src/polyfill.js";
import { ccf, type CCF } from "../src/global.js";
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

  describe(`${role} identity enrollment`, () => {
    function enroll(
      args: { cert?: string; id_format?: string; did_key?: string },
      runtime: Partial<CCF> = ccf,
    ): unknown {
      return runInNewContext(
        `${constitution}\ncheckIdentityEnrollment(args, tableName);`,
        { ccf: runtime, args, tableName: certsTable },
      );
    }

    it("uses keyed legacy lookups without traversing certificates", (t) => {
      const table = ccf.kv[certsTable];
      const id = ccf.pemToId(cert);
      table.set(ccf.strToBuf(id), ccf.strToBuf(cert));
      t.mock.method(table, "forEach", () => {
        assert.fail("Legacy enrollment must not traverse certificates");
      });
      assert.equal(enroll({ cert }), id);
      assert.equal(enroll({ cert, id_format: "sha256" }), id);
    });

    it("rejects legacy enrollment of an existing DID key", () => {
      ccf.kv[keysTable].set(ccf.strToBuf(did), ccf.publicKeyFromDidKey(did));
      assert.throws(() => enroll({ cert: replacement }), /different ID format/);
    });

    it("rejects DID enrollment of an existing legacy key", () => {
      ccf.kv[certsTable].set(
        ccf.strToBuf(ccf.pemToId(cert)),
        ccf.strToBuf(cert),
      );
      assert.throws(
        () => enroll({ did_key: ccf.pemToId(replacement, "did:key") }),
        /different ID format/,
      );
    });

    it("accepts a DID alone and rejects certificate-shaped DID enrollment", () => {
      assert.equal(enroll({ did_key: did }), did);
      for (const args of [
        { did_key: did, cert },
        { did_key: did, id_format: "did:key" },
        { cert, id_format: "did:key" },
        { did_key: "did:key:zinvalid" },
        { did_key: did + "#fragment" },
      ]) {
        assert.throws(() => enroll(args));
      }
    });

    it("propagates unexpected conversion failures", () => {
      const failure = new Error("Failed to parse PEM: invalid public key");
      assert.throws(
        () =>
          enroll(
            { cert },
            {
              certificatesHaveSamePublicKey: ccf.certificatesHaveSamePublicKey,
              pemToId: (_pem, format) => {
                if (format === "did:key") {
                  throw failure;
                }
                return ccf.pemToId(cert);
              },
            },
          ),
        (error) => error === failure,
      );
    });

    it("preserves legacy keys outside the DID profile", () => {
      const id = ccf.pemToId(cert);
      for (const reason of [
        "Unsupported did:key EC curve",
        "Unsupported did:key public key type",
        "did:key RSA keys must be between 2048 and 16384 bits",
      ]) {
        assert.equal(
          enroll(
            { cert },
            {
              certificatesHaveSamePublicKey: ccf.certificatesHaveSamePublicKey,
              pemToId: (_pem, format) => {
                if (format === "did:key") {
                  throw new Error("Failed to parse PEM: " + reason);
                }
                return id;
              },
            },
          ),
          id,
        );
      }
    });

    it("preserves the one-argument legacy API on older runtimes", () => {
      assert.equal(
        enroll(
          { cert },
          {
            pemToId: (...args) => {
              assert.equal(args.length, 1);
              return ccf.pemToId(args[0]);
            },
          },
        ),
        ccf.pemToId(cert),
      );
    });
  });

  for (const oldFormat of ["sha256", "did:key"] as const) {
    describe(`${role} atomic migration from ${oldFormat}`, () => {
      const newFormat = oldFormat === "sha256" ? "did:key" : "sha256";
      const oldId = ccf.pemToId(cert, oldFormat);
      const newId = ccf.pemToId(cert, newFormat);
      const oldTable = oldFormat === "sha256" ? certsTable : keysTable;
      const newTable = oldFormat === "sha256" ? keysTable : certsTable;
      const removal = {
        name: `remove_${role}`,
        args: { [`${role}_id`]: oldId },
      };
      const enrollment = {
        name: `set_${role}`,
        args: {
          ...(newFormat === "sha256" ? { cert } : { did_key: newId }),
          [`${role}_data`]: { v: 1 },
        },
      };
      const proposal = JSON.stringify({ actions: [removal, enrollment] });

      beforeEach(() => {
        ccf.kv[oldTable].set(
          ccf.strToBuf(oldId),
          oldFormat === "sha256"
            ? ccf.strToBuf(cert)
            : ccf.publicKeyFromDidKey(oldId),
        );
        ccf.kv[infoTable].set(
          ccf.strToBuf(oldId),
          ccf.jsonCompatibleToBuf({
            [`${role}_data`]: { v: 1 },
            ...(role === "member" ? { status: "Active" } : {}),
          }),
        );
      });

      it("validates without mutation and applies removal before enrollment", () => {
        const result = validate(proposal);
        assert.equal(result.valid, true, result.description);
        assert.equal(ccf.kv[oldTable].has(ccf.strToBuf(oldId)), true);
        assert.equal(ccf.kv[newTable].has(ccf.strToBuf(newId)), false);
        apply(proposal);
        assert.equal(ccf.kv[oldTable].has(ccf.strToBuf(oldId)), false);
        assert.equal(ccf.kv[infoTable].has(ccf.strToBuf(oldId)), false);
        assert.deepEqual(
          ccf.kv[newTable].get(ccf.strToBuf(newId)),
          newFormat === "sha256"
            ? ccf.strToBuf(cert)
            : ccf.publicKeyFromDidKey(newId),
        );
        assert.deepEqual(
          ccf.bufToJsonCompatible(ccf.kv[infoTable].get(ccf.strToBuf(newId))!),
          {
            [`${role}_data`]: { v: 1 },
            ...(role === "member" ? { status: "Accepted" } : {}),
          },
        );
      });

      it("rejects missing, later, unrelated, and wrong-role removals", () => {
        const otherRole = role === "member" ? "user" : "member";
        for (const proposedActions of [
          [enrollment],
          [enrollment, removal],
          [
            {
              name: removal.name,
              args: { [`${role}_id`]: ccf.pemToId(replacement) },
            },
            enrollment,
          ],
          [
            {
              name: `remove_${otherRole}`,
              args: { [`${otherRole}_id`]: oldId },
            },
            enrollment,
          ],
        ]) {
          const result = validate(JSON.stringify({ actions: proposedActions }));
          assert.equal(result.valid, false);
          assert.match(result.description, /different ID format/);
        }
        assert.equal(ccf.kv[oldTable].has(ccf.strToBuf(oldId)), true);
      });

      it("rechecks application-time state", () => {
        assert.equal(validate(proposal).valid, true);
        assert.throws(
          () =>
            runInNewContext(
              `${constitution}\nactions.get("set_${role}").apply(args);`,
              { ccf, args: enrollment.args },
            ),
          /different ID format/,
        );
        assert.equal(ccf.kv[oldTable].has(ccf.strToBuf(oldId)), true);
        assert.equal(ccf.kv[newTable].has(ccf.strToBuf(newId)), false);
      });

      if (oldFormat === "sha256") {
        it("requires removal of every legacy enrollment carrying the key", () => {
          const otherId = ccf.pemToId(replacement);
          ccf.kv[certsTable].set(
            ccf.strToBuf(otherId),
            ccf.strToBuf(replacement),
          );
          ccf.kv[infoTable].set(
            ccf.strToBuf(otherId),
            ccf.jsonCompatibleToBuf(
              role === "member" ? { status: "Active" } : { user_data: null },
            ),
          );
          assert.equal(validate(proposal).valid, false);
          const complete = JSON.stringify({
            actions: [
              removal,
              { name: removal.name, args: { [`${role}_id`]: otherId } },
              enrollment,
            ],
          });
          assert.equal(validate(complete).valid, true);
          apply(complete);
          assert.equal(ccf.kv[certsTable].size, 0);
          assert.equal(ccf.kv[keysTable].size, 1);
        });
      }
    });
  }
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
