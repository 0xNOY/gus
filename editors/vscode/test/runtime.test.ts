import assert from "node:assert/strict";
import { test } from "node:test";

import type { ProviderBridgeOptions } from "../src/bridge.js";
import type {
  ProviderRegistrationRequest,
  ProviderStatusSnapshot,
} from "../src/ipc.js";
import type { ProviderClient } from "../src/provider.js";
import { startProviderRuntime } from "../src/runtime.js";
import type { StatusPresentation } from "../src/ui.js";

const REGISTRATION: ProviderRegistrationRequest = {
  kind: "vscode",
  editor_session_id: "window-1",
  capabilities: ["profile_quick_pick", "status"],
};

class FakeStatusBar {
  readonly presentations: StatusPresentation[] = [];
  disposals = 0;

  show(presentation: StatusPresentation): void {
    this.presentations.push(presentation);
  }

  dispose(): void {
    this.disposals += 1;
  }
}

test("runtime wires status, fatal state, and disposal exactly once", () => {
  const statusBar = new FakeStatusBar();
  const fatals: Error[] = [];
  let bridgeOptions: ProviderBridgeOptions | undefined;
  let closes = 0;
  const runtime = startProviderRuntime({
    bridgePath: "/opt/gus/bin/gus-provider-bridge",
    runtimeDirectory: "/run/user/1000/gus",
    registration: REGISTRATION,
    quickPickWindow: { showQuickPick: async () => undefined },
    statusBar,
    onFatal: (error) => fatals.push(error),
  }, (options) => {
    bridgeOptions = options;
    return { close: () => { closes += 1; } } as ProviderClient;
  });

  const snapshot: ProviderStatusSnapshot = {
    registration_id: "10000000-0000-4000-8000-000000000001",
    provider_generation: "1",
    entries: [],
  };
  bridgeOptions?.onStatus(snapshot);
  assert.equal(statusBar.presentations.at(-1)?.text, "$(person) GUS: Select on protected operation");

  bridgeOptions?.onFatal(new Error("connection failed"));
  assert.equal(statusBar.presentations.at(-1)?.text, "$(error) GUS: Provider unavailable");
  assert.equal(fatals.length, 1);

  runtime.dispose();
  runtime.dispose();
  assert.equal(closes, 1);
  assert.equal(statusBar.disposals, 1);
});

test("runtime disposes UI when bridge startup fails", () => {
  const statusBar = new FakeStatusBar();
  assert.throws(() => startProviderRuntime({
    bridgePath: "/opt/gus/bin/gus-provider-bridge",
    runtimeDirectory: "/run/user/1000/gus",
    registration: REGISTRATION,
    quickPickWindow: { showQuickPick: async () => undefined },
    statusBar,
    onFatal: () => {},
  }, () => {
    throw new Error("spawn failed");
  }), /spawn failed/u);
  assert.equal(statusBar.disposals, 1);
});
