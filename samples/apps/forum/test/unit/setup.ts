import "@microsoft/ccf-app/polyfill";
import * as ccfapp from "@microsoft/ccf-app";

beforeEach(function () {
  // clear KV before each test
  for (const name of Object.getOwnPropertyNames(ccfapp.rawKv)) {
    ccfapp.rawKv[name].forEach((_, k, m) => {
      m.delete(k);
    });
  }
});
