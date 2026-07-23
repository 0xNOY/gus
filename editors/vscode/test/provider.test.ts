import assert from "node:assert/strict";
import { test } from "node:test";

import { decodeProviderRequest, type ProviderRegistrationRequest } from "../src/ipc.js";
import {
  ProviderClient,
  ProviderRecordDecoder,
  type ProviderScheduler,
  type ProviderTransport,
} from "../src/provider.js";

const REGISTRATION_ID = "10000000-0000-4000-8000-000000000001";
const PROMPT_ID = "20000000-0000-4000-8000-000000000002";
const REPOSITORY = "22".repeat(32);

class MemoryTransport implements ProviderTransport {
  readonly records: Uint8Array[] = [];
  closed = false;

  async write(record: Uint8Array): Promise<void> {
    this.records.push(record);
  }

  close(): void {
    this.closed = true;
  }
}

class MemoryScheduler implements ProviderScheduler {
  callback: (() => void) | undefined;
  cleared = false;
  timeoutCallback: (() => void) | undefined;
  timeoutCleared = false;

  setInterval(callback: () => void): unknown {
    this.callback = callback;
    return 1;
  }

  clearInterval(): void {
    this.cleared = true;
  }

  setTimeout(callback: () => void): unknown {
    this.timeoutCallback = callback;
    return 2;
  }

  clearTimeout(): void {
    this.timeoutCleared = true;
  }
}

function registration(): ProviderRegistrationRequest {
  return {
    kind: "vscode",
    editor_session_id: "window-1",
    capabilities: ["profile_quick_pick", "status"],
  };
}

function brokerRecord(requestId: string, message: unknown): Uint8Array {
  const payload = new TextEncoder().encode(JSON.stringify({
    protocol_version: 1,
    message_family: "provider_response",
    request_id: requestId,
    message,
  }));
  const result = new Uint8Array(4 + payload.length);
  new DataView(result.buffer).setUint32(0, payload.length, false);
  result.set(payload, 4);
  return result;
}

async function settle(): Promise<void> {
  await new Promise((resolve) => setImmediate(resolve));
}

test("record decoder accepts fragmented and coalesced broker records", () => {
  const first = brokerRecord(REGISTRATION_ID, { type: "acknowledged" });
  const second = brokerRecord(PROMPT_ID, { type: "acknowledged" });
  const joined = new Uint8Array(first.length + second.length);
  joined.set(first);
  joined.set(second, first.length);
  const decoder = new ProviderRecordDecoder();
  assert.deepEqual(decoder.push(joined.subarray(0, 5)), []);
  const records = decoder.push(joined.subarray(5));
  assert.equal(records.length, 2);
  assert.deepEqual(records[0], first);
  assert.deepEqual(records[1], second);
});

test("provider registers, subscribes, heartbeats, and answers one prompt", async () => {
  const transport = new MemoryTransport();
  const scheduler = new MemoryScheduler();
  const failures: Error[] = [];
  const statuses: unknown[] = [];
  const client = new ProviderClient({
    registration: registration(),
    transport,
    scheduler,
    picker: { pick: async (prompt) => prompt.profiles[0] },
    onStatus: (status) => statuses.push(status),
    onFatal: (error) => failures.push(error),
  });
  client.start();
  await settle();
  const register = decodeProviderRequest(transport.records[0]!);
  assert.equal(register.message.type, "register");

  client.receive(brokerRecord(register.request_id, {
    type: "registered",
    body: {
      registration_id: register.request_id,
      provider_generation: "1",
      heartbeat_interval_millis: 1000,
    },
  }));
  await settle();
  assert.equal(decodeProviderRequest(transport.records[1]!).message.type, "subscribe_status");
  scheduler.callback?.();
  await settle();
  assert.equal(decodeProviderRequest(transport.records[2]!).message.type, "heartbeat");

  client.receive(brokerRecord(PROMPT_ID, {
    type: "selection_prompt",
    body: {
      registration_id: register.request_id,
      provider_generation: "1",
      selection_generation: "2",
      scope: { kind: "ide_window", opaque_id: "33".repeat(32), label: "VS Code" },
      repository: { identity: REPOSITORY, label: "gus" },
      operation: "commit",
      profiles: [{ profile_id: "alice", display_name: "Alice", email: "alice@example.test" }],
      timeout_millis: 30000,
    },
  }));
  await settle();
  const decision = decodeProviderRequest(transport.records[3]!);
  assert.equal(decision.request_id, PROMPT_ID);
  assert.equal(JSON.stringify(decision.message), JSON.stringify({
    type: "selection_decision",
    body: {
      registration_id: register.request_id,
      provider_generation: "1",
      selection_generation: "2",
      decision: { result: "selected", profile_id: "alice" },
    },
  }));
  assert.deepEqual(failures, []);
  assert.deepEqual(statuses, []);

  client.close();
  assert(transport.closed);
  assert(scheduler.cleared);
});

test("foreign registration response closes the provider", async () => {
  const transport = new MemoryTransport();
  const scheduler = new MemoryScheduler();
  const failures: Error[] = [];
  const client = new ProviderClient({
    registration: registration(),
    transport,
    scheduler,
    picker: { pick: async () => undefined },
    onStatus: () => {},
    onFatal: (error) => failures.push(error),
  });
  client.start();
  await settle();
  client.receive(brokerRecord(REGISTRATION_ID, {
    type: "registered",
    body: {
      registration_id: REGISTRATION_ID,
      provider_generation: "1",
      heartbeat_interval_millis: 1000,
    },
  }));
  assert(transport.closed);
  assert.match(failures[0]?.message ?? "", /registration response/u);
});

test("provider aborts an expired prompt without sending a stale decision", async () => {
  const transport = new MemoryTransport();
  const scheduler = new MemoryScheduler();
  let pickerSignal: AbortSignal | undefined;
  let resolvePicker: ((value: undefined) => void) | undefined;
  const client = new ProviderClient({
    registration: registration(),
    transport,
    scheduler,
    picker: {
      pick: async (_prompt, signal) => {
        pickerSignal = signal;
        return new Promise<undefined>((resolve) => { resolvePicker = resolve; });
      },
    },
    onStatus: () => {},
    onFatal: (error) => assert.fail(error.message),
  });
  client.start();
  await settle();
  const register = decodeProviderRequest(transport.records[0]!);
  client.receive(brokerRecord(register.request_id, {
    type: "registered",
    body: {
      registration_id: register.request_id,
      provider_generation: "1",
      heartbeat_interval_millis: 1000,
    },
  }));
  await settle();
  client.receive(brokerRecord(PROMPT_ID, {
    type: "selection_prompt",
    body: {
      registration_id: register.request_id,
      provider_generation: "1",
      selection_generation: "2",
      scope: { kind: "ide_window", opaque_id: "33".repeat(32), label: "VS Code" },
      repository: { identity: REPOSITORY, label: "gus" },
      operation: "commit",
      profiles: [{ profile_id: "alice", display_name: "Alice", email: null }],
      timeout_millis: 1000,
    },
  }));
  await settle();
  scheduler.timeoutCallback?.();
  assert(pickerSignal?.aborted);
  resolvePicker?.(undefined);
  await settle();
  assert.equal(transport.records.length, 2, "only register and status subscription are sent");
});

test("provider presents repositories authorized by the authenticated broker", async () => {
  const transport = new MemoryTransport();
  const scheduler = new MemoryScheduler();
  const failures: Error[] = [];
  const client = new ProviderClient({
    registration: registration(),
    transport,
    scheduler,
    picker: { pick: async () => undefined },
    onStatus: () => {},
    onFatal: (error) => failures.push(error),
  });
  client.start();
  await settle();
  const register = decodeProviderRequest(transport.records[0]!);
  client.receive(brokerRecord(register.request_id, {
    type: "registered",
    body: {
      registration_id: register.request_id,
      provider_generation: "1",
      heartbeat_interval_millis: 1000,
    },
  }));
  await settle();
  client.receive(brokerRecord(PROMPT_ID, {
    type: "selection_prompt",
    body: {
      registration_id: register.request_id,
      provider_generation: "1",
      selection_generation: "2",
      scope: { kind: "ide_window", opaque_id: "33".repeat(32), label: "VS Code" },
      repository: { identity: "44".repeat(32), label: "other" },
      operation: "commit",
      profiles: [{ profile_id: "alice", display_name: "Alice", email: null }],
      timeout_millis: 1000,
    },
  }));
  await settle();
  assert.equal(transport.records.length, 3);
  assert.equal(
    decodeProviderRequest(transport.records[2]!).message.type,
    "selection_decision",
  );
  assert.deepEqual(failures, []);
});
