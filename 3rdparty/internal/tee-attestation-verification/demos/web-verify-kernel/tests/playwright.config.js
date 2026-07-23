// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { defineConfig } from "@playwright/test";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
// The demo directory is one level up from demos/web-verify-kernel/tests/.
const demoRoot = resolve(here, "..");
const chromiumExecutablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE;

export default defineConfig({
  testDir: ".",
  fullyParallel: false,
  reporter: [["list"]],
  // Start a static file server rooted at the demo directory so the demo's
  // `./pkg/...` import resolves, and so the bundled fixtures under
  // `test-data/` are reachable via HTTP.
  webServer: {
    command: `python3 -m http.server 8123 --directory "${demoRoot}"`,
    url: "http://127.0.0.1:8123/",
    reuseExistingServer: !process.env.CI,
    stdout: "ignore",
    stderr: "pipe",
  },
  use: {
    baseURL: "http://127.0.0.1:8123",
  },
  projects: [{
    name: "chromium",
    use: {
      browserName: "chromium",
      launchOptions: chromiumExecutablePath
        ? { executablePath: chromiumExecutablePath }
        : undefined,
    },
  }],
});
