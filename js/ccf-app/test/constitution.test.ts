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
const { cert, privateKey } = generateSelfSignedCert();
const renewed = forge.pki.certificateFromPem(cert);
renewed.serialNumber = "01";
renewed.sign(forge.pki.privateKeyFromPem(privateKey), forge.md.sha256.create());
const replacement = forge.pki.certificateToPem(renewed);

beforeEach(() => {
  for (const name of Object.getOwnPropertyNames(ccf.kv)) {
    delete ccf.kv[name];
  }
});

for (const tableName of [
  "public:ccf.gov.members.certs",
  "public:ccf.gov.users.certs",
]) {
  describe(`identity enrollment in ${tableName}`, () => {
    function enroll(
      args: { cert: string; id_format?: "sha256" | "did:key" },
      runtime: Partial<CCF> = ccf,
    ): unknown {
      return runInNewContext(
        `${constitution}\ncheckIdentityEnrollment(args, tableName);`,
        { ccf: runtime, args, tableName },
      );
    }

    it("uses keyed lookups without traversing existing certificates", (t) => {
      const table = ccf.kv[tableName];
      const id = ccf.pemToId(cert);
      table.set(ccf.strToBuf(id), ccf.strToBuf(cert));
      t.mock.method(table, "forEach", () => {
        assert.fail("Legacy enrollment must not traverse certificates");
      });
      assert.equal(enroll({ cert }), id);
      assert.equal(enroll({ cert, id_format: "sha256" }), id);
    });

    it("rejects legacy enrollment of an existing DID key with a new certificate", (t) => {
      const table = ccf.kv[tableName];
      const did = ccf.pemToId(cert, "did:key");
      table.set(ccf.strToBuf(did), ccf.strToBuf(cert));
      t.mock.method(table, "forEach", () => {
        assert.fail("Cross-format lookup must not traverse certificates");
      });
      assert.notEqual(ccf.pemToId(replacement), ccf.pemToId(cert));
      assert.throws(() => enroll({ cert: replacement }), /different ID format/);
    });

    it("rejects DID enrollment of an existing legacy key with a new certificate", () => {
      ccf.kv[tableName].set(
        ccf.strToBuf(ccf.pemToId(cert)),
        ccf.strToBuf(cert),
      );
      assert.throws(
        () => enroll({ cert: replacement, id_format: "did:key" }),
        /different ID format/,
      );
    });

    it("allows DID enrollment when only other DID keys are present", () => {
      const other = generateSelfSignedCert().cert;
      ccf.kv[tableName].set(
        ccf.strToBuf(ccf.pemToId(other, "did:key")),
        ccf.strToBuf(other),
      );
      assert.equal(
        enroll({ cert, id_format: "did:key" }),
        ccf.pemToId(cert, "did:key"),
      );
    });

    it("preserves legacy enrollment for keys outside the DID profile", () => {
      const id = ccf.pemToId(cert);
      for (const prefix of ["", "Failed to parse PEM: "]) {
        for (const reason of [
          "Unsupported did:key EC curve",
          "Unsupported did:key public key type",
          "did:key RSA keys must be between 2048 and 16384 bits",
        ]) {
          assert.equal(
            enroll(
              { cert },
              {
                certificatesHaveSamePublicKey:
                  ccf.certificatesHaveSamePublicKey,
                pemToId: (_pem, format) => {
                  if (format === "did:key") {
                    throw new Error(prefix + reason);
                  }
                  return id;
                },
              },
            ),
            id,
          );
        }
      }
    });

    it("propagates unexpected DID conversion failures", () => {
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

    it("preserves the one-argument legacy API on older runtimes", () => {
      const id = ccf.pemToId(cert);
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
        id,
      );
    });
  });
}

describe("set_member re-enrollment", () => {
  function applySetMember(args: Record<string, unknown>): void {
    runInNewContext(
      `${constitution}\nconst action = actions.get("set_member");\naction.validate(args);\naction.apply(args);`,
      { ccf, args },
    );
  }

  it("updates an existing DID member like a legacy member", () => {
    ccf.kv["public:ccf.gov.service.info"].set(
      new ArrayBuffer(8),
      ccf.jsonCompatibleToBuf({ status: "Open" }),
    );
    const did = ccf.pemToId(cert, "did:key");
    const rawDid = ccf.strToBuf(did);
    applySetMember({ cert, id_format: "did:key", member_data: { v: 1 } });
    ccf.kv["public:ccf.gov.members.info"].set(
      rawDid,
      ccf.jsonCompatibleToBuf({ member_data: { v: 1 }, status: "Active" }),
    );
    ccf.kv["public:ccf.gov.members.acks"].set(rawDid, ccf.strToBuf("ack"));

    applySetMember({
      cert: replacement,
      id_format: "did:key",
      member_data: { v: 2 },
    });

    assert.equal(
      ccf.bufToStr(ccf.kv["public:ccf.gov.members.certs"].get(rawDid)!),
      replacement,
    );
    assert.deepEqual(
      ccf.bufToJsonCompatible(
        ccf.kv["public:ccf.gov.members.info"].get(rawDid)!,
      ),
      { member_data: { v: 2 }, status: "Accepted" },
    );
    assert.equal(ccf.kv["public:ccf.gov.members.acks"].has(rawDid), false);
    assert.equal(ccf.kv["public:ccf.gov.members.certs"].size, 1);
  });
});
