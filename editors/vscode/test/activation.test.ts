import assert from "node:assert/strict";
import { test } from "node:test";

import { resolveProviderLaunch } from "../src/activation.js";

test("launch paths use the bundled native bridge and XDG runtime", () => {
  assert.deepEqual(resolveProviderLaunch(
    "/opt/gus-extension",
    { XDG_RUNTIME_DIR: "/run/user/1000" },
    "linux",
    1000,
  ), {
    bridgePath: "/opt/gus-extension/bin/gus-provider-bridge",
    runtimeDirectory: "/run/user/1000/gus",
  });
});

test("explicit runtime is exact and Unix fallback matches the native shim", () => {
  assert.equal(resolveProviderLaunch(
    "/opt/gus-extension",
    { GUS_RUNTIME_DIR: "/private/gus-runtime" },
    "darwin",
    501,
  ).runtimeDirectory, "/private/gus-runtime");
  assert.equal(resolveProviderLaunch(
    "/opt/gus-extension",
    {},
    "darwin",
    501,
  ).runtimeDirectory, "/tmp/gus-501");
});

test("relative and unavailable runtime paths fail closed", () => {
  assert.throws(() => resolveProviderLaunch(
    "/opt/gus-extension",
    { XDG_RUNTIME_DIR: "relative" },
    "linux",
    1000,
  ), /must be absolute/u);
  assert.throws(() => resolveProviderLaunch(
    "/opt/gus-extension",
    {},
    "win32",
    undefined,
  ), /unavailable/u);
});
