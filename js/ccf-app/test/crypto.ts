import * as crypto from "crypto";
import forge from "node-forge";

export function generateSelfSignedCert() {
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
  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.publicKeyFromPem(keys.publicKey);
  cert.sign(
    forge.pki.privateKeyFromPem(keys.privateKey),
    forge.md.sha256.create(),
  );
  const certPem = forge.pki.certificateToPem(cert);
  return {
    privateKey: keys.privateKey,
    publicKey: keys.publicKey,
    cert: certPem,
  };
}

export function generateCertChain(len: number): string[] {
  const keyPairs = [];
  for (let i = 0; i < len; i++) {
    keyPairs.push(
      crypto.generateKeyPairSync("rsa", {
        modulusLength: 2048,
        publicKeyEncoding: {
          type: "spki",
          format: "pem",
        },
        privateKeyEncoding: {
          type: "pkcs8",
          format: "pem",
        },
      }),
    );
  }
  const certs = [];
  for (let i = 0; i < len; i++) {
    const cert = forge.pki.createCertificate();
    cert.publicKey = forge.pki.publicKeyFromPem(keyPairs[i].publicKey);
    const signer = i < len - 1 ? keyPairs[i + 1] : keyPairs[i];
    cert.sign(
      forge.pki.privateKeyFromPem(signer.privateKey),
      forge.md.sha256.create(),
    );
    const certPem = forge.pki.certificateToPem(cert);
    certs.push(certPem);
  }
  return certs;
}
