// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

import * as fs from "fs";
import * as tmp from "tmp";
import * as crypto from "crypto";
import * as forge from "node-forge";
import * as selfsigned from "selfsigned";
import { assert } from "chai";
import bent from "bent";
import jwt from "jsonwebtoken";
import { NODE_ADDR, setupMochaCCFSandbox } from "./util";
import {
  CreatePollRequest,
  SubmitOpinionRequest,
  CreatePollsRequest,
  SubmitOpinionsRequest,
  NumericPollResponse,
  StringPollResponse,
  MINIMUM_OPINION_THRESHOLD,
  GetPollResponse,
} from "../src/controllers/poll";

tmp.setGracefulCleanup();

const APP_BUNDLE_DIR = "dist";
const ENDPOINT_URL = `${NODE_ADDR}/app/polls`;

class FakeAuth {
  privateKeyPem: string;
  jwtIssuerFile: tmp.FileResult;
  keyId = "12345";
  issuer = "https://demo";

  constructor() {
    const keys = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: "spki",
        format: "pem",
      },
      privateKeyEncoding: {
        type: "pkcs8",
        format: "pem",
      },
    });
    const certPem = selfsigned.generate(null, {
      algorithm: "sha256",
      keyPair: {
        privateKey: keys.privateKey,
        publicKey: keys.publicKey,
      },
    }).cert;
    const cert = forge.pki.certificateFromPem(certPem);
    const certDer = forge.asn1
      .toDer(forge.pki.certificateToAsn1(cert))
      .getBytes();
    const certDerB64 = forge.util.encode64(certDer);

    this.privateKeyPem = keys.privateKey;
    this.jwtIssuerFile = tmp.fileSync();

    const jwtIssuer = {
      issuer: this.issuer,
      jwks: { keys: [{ kty: "RSA", kid: this.keyId, x5c: [certDerB64] }] },
    };
    fs.writeFileSync(this.jwtIssuerFile.name, JSON.stringify(jwtIssuer));
  }

  user(userId: number) {
    const payload = {
      sub: "user" + userId,
    };
    const token = jwt.sign(payload, this.privateKeyPem, {
      algorithm: "RS256",
      keyid: this.keyId,
      issuer: this.issuer,
    });
    return {
      authorization: `Bearer ${token}'`,
    };
  }
}

// Note: In order to use a single CCF instance (and hence keep tests fast),
// each test uses a different poll topic.

describe("/polls", function () {
  this.timeout(35000);

  const fakeAuth = new FakeAuth();

  setupMochaCCFSandbox({
    app_bundle_dir: APP_BUNDLE_DIR,
    jwt_issuer_paths: [fakeAuth.jwtIssuerFile.name],
  });

  describe("POST /{topic}", function () {
    it("creates numeric polls", async function () {
      const topic = "post-a";
      const body: CreatePollRequest = {
        type: "number",
      };
      await bent("POST", 201)(
        `${ENDPOINT_URL}/${topic}`,
        body,
        fakeAuth.user(1)
      );
    });
    it("creates string polls", async function () {
      const topic = "post-b";
      const body: CreatePollRequest = {
        type: "string",
      };
      await bent("POST", 201)(
        `${ENDPOINT_URL}/${topic}`,
        body,
        fakeAuth.user(1)
      );
    });
    it("rejects creating polls with an existing topic", async function () {
      const topic = "post-c";
      const body: CreatePollRequest = {
        type: "string",
      };
      await bent("POST", 201)(
        `${ENDPOINT_URL}/${topic}`,
        body,
        fakeAuth.user(1)
      );
      await bent("POST", 403)(
        `${ENDPOINT_URL}/${topic}`,
        body,
        fakeAuth.user(1)
      );
    });
    it("rejects creating polls without authorization", async function () {
      const topic = "post-d";
      const body: CreatePollRequest = {
        type: "string",
      };
      await bent("POST", 401)(`${ENDPOINT_URL}/${topic}`, body);
    });
  });
  describe("POST /", function () {
    it("creates multiple polls", async function () {
      const body: CreatePollsRequest = {
        polls: {
          "post-multiple-a": { type: "number" },
          "post-multiple-b": { type: "string" },
        },
      };
      await bent("POST", 201)(`${ENDPOINT_URL}`, body, fakeAuth.user(1));
    });
    it("rejects creating polls with an existing topic", async function () {
      const body: CreatePollsRequest = {
        polls: {
          "post-multiple-c": { type: "number" },
        },
      };
      await bent("POST", 201)(`${ENDPOINT_URL}`, body, fakeAuth.user(1));
      await bent("POST", 403)(`${ENDPOINT_URL}`, body, fakeAuth.user(1));
    });
    it("rejects creating polls without authorization", async function () {
      const body: CreatePollsRequest = {
        polls: {
          "post-multiple-d": { type: "number" },
        },
      };
      await bent("POST", 401)(`${ENDPOINT_URL}`, body);
    });
  });
  describe("PUT /{topic}", function () {
    it("stores opinions to a topic", async function () {
      const topic = "put-a";
      const pollBody: CreatePollRequest = {
        type: "number",
      };
      await bent("POST", 201)(
        `${ENDPOINT_URL}/${topic}`,
        pollBody,
        fakeAuth.user(1)
      );

      const opinionBody: SubmitOpinionRequest = {
        opinion: 1.2,
      };
      await bent("PUT", 204)(
        `${ENDPOINT_URL}/${topic}`,
        opinionBody,
        fakeAuth.user(1)
      );
    });
    it("rejects opinions with mismatching data type", async function () {
      const topic = "put-b";
      const pollBody: CreatePollRequest = {
        type: "number",
      };
      await bent("POST", 201)(
        `${ENDPOINT_URL}/${topic}`,
        pollBody,
        fakeAuth.user(1)
      );

      const opinionBody: SubmitOpinionRequest = {
        opinion: "foo",
      };
      await bent("PUT", 400)(
        `${ENDPOINT_URL}/${topic}`,
        opinionBody,
        fakeAuth.user(1)
      );
    });
    it("rejects opinions for unknown topics", async function () {
      const body: SubmitOpinionRequest = {
        opinion: 1.2,
      };
      await bent("PUT", 404)(
        `${ENDPOINT_URL}/non-existing`,
        body,
        fakeAuth.user(1)
      );
    });
    it("rejects opinions without authorization", async function () {
      const topic = "put-c";
      const pollBody: CreatePollRequest = {
        type: "number",
      };
      await bent("POST", 201)(
        `${ENDPOINT_URL}/${topic}`,
        pollBody,
        fakeAuth.user(1)
      );

      const opinionBody: SubmitOpinionRequest = {
        opinion: 1.2,
      };
      await bent("PUT", 401)(`${ENDPOINT_URL}/${topic}`, opinionBody);
    });
  });
  describe("PUT /", function () {
    it("stores opinions to multiple topics", async function () {
      const topicA = "put-multiple-a";
      const topicB = "put-multiple-b";
      const body: CreatePollsRequest = {
        polls: {
          [topicA]: { type: "number" },
          [topicB]: { type: "string" },
        },
      };
      await bent("POST", 201)(`${ENDPOINT_URL}`, body, fakeAuth.user(1));

      const opinionBody: SubmitOpinionsRequest = {
        opinions: {
          [topicA]: { opinion: 1.5 },
          [topicB]: { opinion: "foo" },
        },
      };
      await bent("PUT", 204)(`${ENDPOINT_URL}`, opinionBody, fakeAuth.user(1));
    });
    it("rejects opinions with mismatching data type", async function () {
      const topicA = "put-multiple-c";
      const topicB = "put-multiple-d";
      const body: CreatePollsRequest = {
        polls: {
          [topicA]: { type: "number" },
          [topicB]: { type: "string" },
        },
      };
      await bent("POST", 201)(`${ENDPOINT_URL}`, body, fakeAuth.user(1));

      const opinionBody: SubmitOpinionsRequest = {
        opinions: {
          [topicA]: { opinion: 1.5 },
          [topicB]: { opinion: 1.6 },
        },
      };
      await bent("PUT", 400)(`${ENDPOINT_URL}`, opinionBody, fakeAuth.user(1));
    });
    it("rejects opinions for unknown topics", async function () {
      const body: SubmitOpinionsRequest = {
        opinions: {
          "non-existing": { opinion: 1.5 },
        },
      };
      await bent("PUT", 400)(`${ENDPOINT_URL}`, body, fakeAuth.user(1));
    });
    it("rejects opinions without authorization", async function () {
      const topic = "put-multiple-e";
      const pollBody: CreatePollsRequest = {
        polls: {
          [topic]: { type: "number" },
        },
      };
      await bent("POST", 201)(`${ENDPOINT_URL}`, pollBody, fakeAuth.user(1));

      const opinionBody: SubmitOpinionsRequest = {
        opinions: {
          [topic]: { opinion: 1.5 },
        },
      };
      await bent("PUT", 401)(`${ENDPOINT_URL}`, opinionBody);
    });
  });
  describe("GET /{topic}", function () {
    it("returns aggregated numeric poll opinions", async function () {
      const topic = "get-a";
      const pollBody: CreatePollRequest = {
        type: "number",
      };
      await bent("POST", 201)(
        `${ENDPOINT_URL}/${topic}`,
        pollBody,
        fakeAuth.user(1)
      );

      let opinions = [1.5, 0.9, 1.2, 1.5, 0.9, 1.2, 1.5, 0.9, 1.2, 1.5];
      for (let i = 0; i < opinions.length; i++) {
        const opinionBody: SubmitOpinionRequest = {
          opinion: opinions[i],
        };
        await bent("PUT", 204)(
          `${ENDPOINT_URL}/${topic}`,
          opinionBody,
          fakeAuth.user(i)
        );
      }

      let aggregated: NumericPollResponse = await bent("GET", "json", 200)(
        `${ENDPOINT_URL}/${topic}`,
        null,
        fakeAuth.user(1)
      );
      assert.equal(
        aggregated.statistics.mean,
        opinions.reduce((a, b) => a + b, 0) / opinions.length
      );
    });
    it("returns aggregated string poll opinions", async function () {
      const topic = "get-b";
      const pollBody: CreatePollRequest = {
        type: "string",
      };
      await bent("POST", 201)(
        `${ENDPOINT_URL}/${topic}`,
        pollBody,
        fakeAuth.user(1)
      );

      let opinions = [
        "foo",
        "foo",
        "bar",
        "foo",
        "foo",
        "bar",
        "foo",
        "foo",
        "bar",
        "foo",
      ];
      for (let i = 0; i < opinions.length; i++) {
        const opinionBody: SubmitOpinionRequest = {
          opinion: opinions[i],
        };
        await bent("PUT", 204)(
          `${ENDPOINT_URL}/${topic}`,
          opinionBody,
          fakeAuth.user(i)
        );
      }

      let aggregated: StringPollResponse = await bent("GET", "json", 200)(
        `${ENDPOINT_URL}/${topic}`,
        null,
        fakeAuth.user(1)
      );
      assert.equal(aggregated.statistics.counts["foo"], 7);
      assert.equal(aggregated.statistics.counts["bar"], 3);
    });
    it("rejects returning aggregated opinions below the required opinion count threshold", async function () {
      const topic = "get-c";
      const pollBody: CreatePollRequest = {
        type: "number",
      };
      await bent("POST", 201)(
        `${ENDPOINT_URL}/${topic}`,
        pollBody,
        fakeAuth.user(1)
      );

      for (let i = 0; i < MINIMUM_OPINION_THRESHOLD - 1; i++) {
        const opinionBody: SubmitOpinionRequest = {
          opinion: 1.0,
        };
        await bent("PUT", 204)(
          `${ENDPOINT_URL}/${topic}`,
          opinionBody,
          fakeAuth.user(i)
        );
      }

      const poll: GetPollResponse = await bent("GET", "json", 200)(
        `${ENDPOINT_URL}/${topic}`,
        null,
        fakeAuth.user(1)
      );
      assert.notExists(poll.statistics);
    });
    it("rejects returning aggregated opinions for unknown topics", async function () {
      await bent("GET", 404)(
        `${ENDPOINT_URL}/non-existing`,
        null,
        fakeAuth.user(1)
      );
    });
  });
});
