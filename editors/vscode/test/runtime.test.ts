import assert from "node:assert/strict";
import { test } from "node:test";

import type { ProviderBridgeOptions } from "../src/bridge.js";
import type {
  ProviderRegistrationRequest,
  ProviderStatusSnapshot,
} from "../src/ipc.js";
import type { ProviderClient } from "../src/provider.js";
import type { ProviderScheduler } from "../src/provider.js";
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

class FakeScheduler implements ProviderScheduler {
  timeoutCallback: (() => void) | undefined;
  timeoutCleared = false;

  setInterval(): unknown {
    return 1;
  }

  clearInterval(): void {}

  setTimeout(callback: () => void): unknown {
    this.timeoutCallback = callback;
    return 2;
  }

  clearTimeout(): void {
    this.timeoutCleared = true;
    this.timeoutCallback = undefined;
  }
}

test("runtime reconnects after a provider failure and disposes exactly once", async () => {
  const statusBar = new FakeStatusBar();
  const fatals: Error[] = [];
  const scheduler = new FakeScheduler();
  const bridges: ProviderBridgeOptions[] = [];
  let closes = 0;
  const runtime = startProviderRuntime({
    bridgePath: "/opt/gus/bin/gus-provider-bridge",
    runtimeDirectory: "/run/user/1000/gus",
    registration: REGISTRATION,
    quickPickWindow: { showQuickPick: async () => undefined },
    statusBar,
    scheduler,
    onFatal: (error) => fatals.push(error),
  }, (options) => {
    bridges.push(options);
    return { close: () => { closes += 1; } } as ProviderClient;
  });

  bridges[0]?.onReady?.();
  await runtime.ready;
  const snapshot: ProviderStatusSnapshot = {
    registration_id: "10000000-0000-4000-8000-000000000001",
    provider_generation: "1",
    entries: [],
  };
  bridges[0]?.onStatus(snapshot);
  assert.equal(statusBar.presentations.at(-1)?.text, "$(person) GUS: Select on protected operation");

  bridges[0]?.onFatal(new Error("connection failed"));
  assert.equal(statusBar.presentations.at(-1)?.text, "$(sync~spin) GUS: Reconnecting");
  assert.equal(fatals.length, 0);
  scheduler.timeoutCallback?.();
  assert.equal(bridges.length, 2);
  bridges[1]?.onReady?.();
  bridges[1]?.onStatus(snapshot);
  assert.equal(statusBar.presentations.at(-1)?.text, "$(person) GUS: Select on protected operation");

  runtime.dispose();
  runtime.dispose();
  assert.equal(closes, 2);
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
