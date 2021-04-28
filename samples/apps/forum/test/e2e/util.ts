// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

import { ChildProcess, spawn } from "child_process";
import * as path from "path";

// accept self-signed certs
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const NODE_HOST = "127.0.0.1:8000";
export const NODE_ADDR = "https://" + NODE_HOST;

interface CCFSandboxOpts {
  app_bundle_dir: string;
  jwt_issuer_paths?: string[];
}

export function getCCFSandboxCmdAndArgs(opts: CCFSandboxOpts) {
  const CCF_SANDBOX_ARGS = [
    "--node",
    "local://" + NODE_HOST,
    "--js-app-bundle",
    opts.app_bundle_dir,
    "--workspace",
    ".workspace_ccf",
  ];
  for (const jwt_issuer_path of opts.jwt_issuer_paths || []) {
    CCF_SANDBOX_ARGS.push("--jwt-issuer", jwt_issuer_path);
  }
  if (process.env.VERBOSE == "1") {
    CCF_SANDBOX_ARGS.push("--verbose");
  }
  if (process.env.ENCLAVE_TYPE) {
    CCF_SANDBOX_ARGS.push("--enclave-type=" + process.env.ENCLAVE_TYPE);
  }
  if (process.env.CONSENSUS) {
    CCF_SANDBOX_ARGS.push("--consensus=" + process.env.CONSENSUS);
  }

  // This logic allows to run tests easily from a CCF install or the CCF repository.
  // Most of this will disappear once CCF's build folder uses the same layout as an install.
  let CCF_SANDBOX_SCRIPT: string;
  const CCF_REPO_ROOT = path.join("..", "..", "..");
  const CCF_BINARY_DIR =
    process.env.CCF_BINARY_DIR || path.join(CCF_REPO_ROOT, "build");
  if (path.basename(CCF_BINARY_DIR) === "bin") {
    // ccf install tree
    CCF_SANDBOX_SCRIPT = path.join(CCF_BINARY_DIR, "sandbox.sh");
  } else {
    // ccf repo tree
    CCF_SANDBOX_SCRIPT = path.join(
      CCF_REPO_ROOT,
      "tests",
      "sandbox",
      "sandbox.sh"
    );
    CCF_SANDBOX_ARGS.push("--binary-dir", CCF_BINARY_DIR);
  }
  console.log(CCF_SANDBOX_ARGS);
  return {
    command: CCF_SANDBOX_SCRIPT,
    args: CCF_SANDBOX_ARGS,
  };
}

export function setupMochaCCFSandbox(opts: CCFSandboxOpts) {
  const { command, args } = getCCFSandboxCmdAndArgs(opts);

  let sandboxProcess: ChildProcess;
  before(function () {
    this.timeout(60000); // first time takes longer due to venv install
    return new Promise<void>((resolve, reject) => {
      sandboxProcess = spawn(command, args, {
        stdio: ["pipe", "pipe", "inherit"],
        timeout: 40000, // sandbox startup + max test duration
      });
      sandboxProcess.on("exit", reject);
      sandboxProcess.stdout.on("data", (data) => {
        const msg = data.toString();
        console.log(msg);
        if (msg.includes("Started CCF network")) {
          sandboxProcess.off("exit", reject);
          resolve();
        }
      });
    });
  });

  after(function () {
    this.timeout(5000);
    return new Promise<void>((resolve, reject) => {
      sandboxProcess.on("exit", () => {
        resolve();
      });
      sandboxProcess.kill("SIGINT");
    });
  });
}
