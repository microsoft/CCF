// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { defineConfig } from "@playwright/test";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const demoRoot = resolve(here, "..");
const chromiumExecutablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE;

export default defineConfig({
  testDir: ".",
  fullyParallel: false,
  reporter: [["list"]],
  webServer: {
    command: `python3 -m http.server 8124 --directory "${demoRoot}"`,
    url: "http://127.0.0.1:8124/",
    reuseExistingServer: !process.env.CI,
    stdout: "ignore",
    stderr: "pipe",
  },
  use: {
    baseURL: "http://127.0.0.1:8124",
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
