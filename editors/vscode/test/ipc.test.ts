import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  FRAME_HEADER_BYTES,
  type MessageFamily,
  type ProviderControlMessage,
  type ProviderRegistrationRequest,
  type ProviderResponseFrame,
  createProviderControlFrame,
  createProviderRegistrationFrame,
  createProviderSelectionResponseFrame,
  decodeBrokerError,
  decodeProviderRequest,
  decodeProviderResponse,
  decodeShimRequest,
  decodeShimResponse,
  encodeFrame,
  newRequestId,
} from "../src/ipc.js";

interface CorpusCase {
  direction: MessageFamily;
  payload: unknown;
}

interface Corpus {
  valid: CorpusCase[];
  invalid: CorpusCase[];
}

interface WireNegativeCase {
  name: string;
  direction: MessageFamily;
  payload: string;
}

function isCorpusCase(value: unknown): value is CorpusCase {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return (
    (record.direction === "shim_request" ||
      record.direction === "shim_response" ||
      record.direction === "provider_request" ||
      record.direction === "provider_response") &&
    Object.hasOwn(record, "payload")
  );
}

async function loadCorpus(): Promise<Corpus> {
  const path = new URL(
    "../../../../crates/gus-ipc/tests/fixtures/conformance-v1.json",
    import.meta.url,
  );
  const parsed: unknown = JSON.parse(await readFile(path, "utf8"));
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("invalid conformance corpus root");
  }
  const record = parsed as Record<string, unknown>;
  if (
    !Array.isArray(record.valid) ||
    !record.valid.every(isCorpusCase) ||
    !Array.isArray(record.invalid) ||
    !record.invalid.every(isCorpusCase)
  ) {
    throw new Error("invalid conformance corpus cases");
  }
  return { valid: record.valid, invalid: record.invalid };
}

async function loadWireNegativeCorpus(): Promise<WireNegativeCase[]> {
  const path = new URL(
    "../../../../crates/gus-ipc/tests/fixtures/wire-negative-v1.json",
    import.meta.url,
  );
  const parsed: unknown = JSON.parse(await readFile(path, "utf8"));
  if (
    !Array.isArray(parsed) ||
    !parsed.every(
      (value): value is WireNegativeCase =>
        typeof value === "object" &&
        value !== null &&
        !Array.isArray(value) &&
        typeof (value as Record<string, unknown>).name === "string" &&
        typeof (value as Record<string, unknown>).payload === "string" &&
        ["shim_request", "shim_response", "provider_request", "provider_response"].includes(
          String((value as Record<string, unknown>).direction),
        ),
    )
  ) {
    throw new Error("invalid wire-negative corpus");
  }
  return parsed;
}

function record(payload: unknown): Uint8Array {
  return recordText(JSON.stringify(payload));
}

function recordText(payload: string): Uint8Array {
  const encoded = new TextEncoder().encode(payload);
  const result = new Uint8Array(FRAME_HEADER_BYTES + encoded.byteLength);
  new DataView(result.buffer).setUint32(0, encoded.byteLength, false);
  result.set(encoded, FRAME_HEADER_BYTES);
  return result;
}

function decode(direction: MessageFamily, bytes: Uint8Array) {
  switch (direction) {
    case "shim_request":
      return decodeShimRequest(bytes);
    case "shim_response":
      return decodeShimResponse(bytes);
    case "provider_request":
      return decodeProviderRequest(bytes);
    case "provider_response":
      return decodeProviderResponse(bytes);
  }
}

test("Rust and TypeScript accept every v1 message variant in the shared corpus", async () => {
  const corpus = await loadCorpus();
  assert.equal(corpus.valid.length, 20);
  for (const entry of corpus.valid) {
    const decoded = decode(entry.direction, record(entry.payload));
    assert.equal(decoded.message_family, entry.direction);
    assert.deepEqual(decode(entry.direction, encodeFrame(decoded)), decoded);

    const messageUnknown = structuredClone(entry.payload) as {
      message: Record<string, unknown>;
    };
    messageUnknown.message.unexpected = true;
    assert.throws(() => decode(entry.direction, record(messageUnknown)));

    const bodyUnknown = structuredClone(entry.payload) as {
      message: { body?: unknown };
    };
    if (
      typeof bodyUnknown.message.body === "object" &&
      bodyUnknown.message.body !== null &&
      !Array.isArray(bodyUnknown.message.body)
    ) {
      (bodyUnknown.message.body as Record<string, unknown>).unexpected = true;
      assert.throws(() => decode(entry.direction, record(bodyUnknown)));
    }
  }

  const tags = new Set(
    corpus.valid.map((entry) => {
      const payload = entry.payload as { message: { type: string } };
      return `${entry.direction}:${payload.message.type}`;
    }),
  );
  for (const tag of [
    "shim_request:resolve_selection",
    "shim_request:clear_selection",
    "shim_request:status",
    "shim_response:resolved",
    "shim_response:cleared",
    "shim_response:status",
    "shim_response:error",
    "provider_request:register",
    "provider_request:heartbeat",
    "provider_request:subscribe_status",
    "provider_request:update_repositories",
    "provider_request:selection_decision",
    "provider_request:unregister",
    "provider_response:registered",
    "provider_response:selection_prompt",
    "provider_response:status_snapshot",
    "provider_response:acknowledged",
    "provider_response:error",
  ]) {
    assert(tags.has(tag), `shared corpus is missing ${tag}`);
  }
});

test("Rust and TypeScript reject the shared negative corpus", async () => {
  const corpus = await loadCorpus();
  assert(corpus.invalid.length >= 7);
  for (const entry of corpus.invalid) {
    assert.throws(() => decode(entry.direction, record(entry.payload)));
  }
});

test("all stable error codes have an exact cross-language contract", async () => {
  const path = new URL(
    "../../../../crates/gus-ipc/tests/fixtures/error-contract-v1.json",
    import.meta.url,
  );
  const parsed: unknown = JSON.parse(await readFile(path, "utf8"));
  assert(Array.isArray(parsed));
  assert.equal(parsed.length, 31);
  const codes = new Set<string>();
  for (const value of parsed) {
    const error = decodeBrokerError(value);
    codes.add(error.code);
  }
  assert.equal(codes.size, 31);

  const internal = structuredClone(
    parsed.find(
      (value: unknown) =>
        typeof value === "object" &&
        value !== null &&
        (value as { code?: unknown }).code === "GUS_E_INTERNAL",
    ),
  ) as Record<string, unknown>;
  internal.phase = "deferred_helper";
  internal.real_git_started = true;
  assert.throws(() => decodeBrokerError(internal));
});

test("byte-stream framing rejects partial and coalesced records", async () => {
  const corpus = await loadCorpus();
  const complete = record(corpus.valid[0]?.payload);
  assert.throws(() => decodeShimRequest(complete.subarray(0, complete.length - 1)));
  const coalesced = new Uint8Array(complete.length * 2);
  coalesced.set(complete);
  coalesced.set(complete, complete.length);
  assert.throws(() => decodeShimRequest(coalesced));
});

test("strict JSON parsing rejects duplicate keys", async () => {
  const corpus = await loadCorpus();
  const payload = JSON.stringify(corpus.valid[0]?.payload).replace(
    '"protocol_version":1',
    '"protocol_version":1,"protocol_version":1',
  );
  assert.throws(() => decodeShimRequest(recordText(payload)));
});

test("request IDs generated by the provider are canonical UUIDv4", () => {
  assert.match(
    newRequestId(),
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
});

test("Rust and TypeScript reject the same lexical and Unicode wire boundaries", async () => {
  const cases = await loadWireNegativeCorpus();
  assert.equal(cases.length, 8);
  for (const entry of cases) {
    assert.throws(
      () => decode(entry.direction, recordText(entry.payload)),
      `TypeScript accepted wire-negative case: ${entry.name}`,
    );
  }
});

test("encoder canonicalizes data properties and rejects smuggling surfaces", async () => {
  const corpus = await loadCorpus();
  const decoded = decodeShimRequest(record(corpus.valid[0]?.payload));

  const extra = { ...decoded, unexpected: "TOKEN=secret" };
  assert.throws(() => encodeFrame(extra));

  const inheritedToJson = Object.assign(
    Object.create({
      toJSON: () => ({ TOKEN: "secret" }),
    }) as object,
    decoded,
  ) as typeof decoded;
  assert.deepEqual(decodeShimRequest(encodeFrame(inheritedToJson)), decoded);

  const accessor = { ...decoded };
  Object.defineProperty(accessor, "request_id", {
    enumerable: true,
    get: () => decoded.request_id,
  });
  assert.throws(() => encodeFrame(accessor));

  const registrationCase = corpus.valid.find(
    (entry) =>
      entry.direction === "provider_request" &&
      (entry.payload as { message?: { type?: string } }).message?.type === "register",
  );
  assert(registrationCase !== undefined);
  const sparse = decodeProviderRequest(record(registrationCase.payload));
  if (sparse.message.type === "register") {
    sparse.message.body.capabilities = new Array(1) as typeof sparse.message.body.capabilities;
  }
  assert.throws(() => encodeFrame(sparse));
});

test("duplicate-key diagnostics never reflect attacker-controlled keys", () => {
  const malicious = '{"x\\nTOKEN=secret":1,"x\\nTOKEN=secret":2}';
  assert.throws(
    () => decodeShimRequest(recordText(malicious)),
    (error: unknown) => error instanceof Error && error.message === "duplicate JSON key",
  );
});

test("provider factories enforce request ID roles and prompt correlation", async () => {
  const registration: ProviderRegistrationRequest = {
    kind: "vscode",
    editor_session_id: "window-1",
    host_instance: "1111111111111111111111111111111111111111111111111111111111111111",
    repositories: [
      "2222222222222222222222222222222222222222222222222222222222222222",
    ],
    capabilities: ["profile_quick_pick", "status"],
  };
  const registrationFrame = createProviderRegistrationFrame(registration);
  assert.equal(registrationFrame.message.type, "register");
  assert.match(
    registrationFrame.request_id,
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );

  const control: ProviderControlMessage = {
    type: "heartbeat",
    body: {
      registration_id: "30000000-0000-4000-8000-000000000001",
      provider_generation: "3",
    },
  };
  const controlFrame = createProviderControlFrame(control);
  assert.notEqual(controlFrame.request_id, registrationFrame.request_id);

  const corpus = await loadCorpus();
  const promptCase = corpus.valid.find(
    (entry) =>
      entry.direction === "provider_response" &&
      (entry.payload as { message?: { type?: string } }).message?.type === "selection_prompt",
  );
  assert(promptCase !== undefined);
  const promptFrame = decodeProviderResponse(record(promptCase.payload));
  const response = createProviderSelectionResponseFrame(promptFrame, { result: "cancelled" });
  assert.equal(response.request_id, promptFrame.request_id);
  assert.equal(response.message.type, "selection_decision");
  if (response.message.type === "selection_decision" && promptFrame.message.type === "selection_prompt") {
    assert.equal(
      response.message.body.registration_id,
      promptFrame.message.body.registration_id,
    );
    assert.equal(
      response.message.body.provider_generation,
      promptFrame.message.body.provider_generation,
    );
    assert.equal(
      response.message.body.selection_generation,
      promptFrame.message.body.selection_generation,
    );
  }

  const acknowledged = corpus.valid.find(
    (entry) =>
      entry.direction === "provider_response" &&
      (entry.payload as { message?: { type?: string } }).message?.type === "acknowledged",
  );
  assert(acknowledged !== undefined);
  assert.throws(() =>
    createProviderSelectionResponseFrame(
      decodeProviderResponse(record(acknowledged.payload)) as ProviderResponseFrame,
      { result: "unavailable" },
    ),
  );
});
