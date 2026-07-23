import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  FRAME_HEADER_BYTES,
  type DecodedProviderResponseFrame,
  type MessageFamily,
  type ProviderControlMessage,
  type ProviderRegistrationRequest,
  createProviderControlFrame,
  createProviderRegistrationFrame,
  createProviderSelectionResponseFrame,
  decodeBrokerError,
  decodeProviderRequest,
  decodeProviderResponse,
  decodeShimRequest,
  decodeShimResponse,
  encodeProviderRequest,
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

interface PresentationPolicy {
  unicode_version: string;
  code_point_count: number;
  ranges: { start: string; end: string }[];
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

async function loadPresentationPolicy(): Promise<PresentationPolicy> {
  const path = new URL(
    "../../../../crates/gus-ipc/tests/fixtures/presentation-forbidden-unicode17.json",
    import.meta.url,
  );
  const parsed = JSON.parse(await readFile(path, "utf8")) as PresentationPolicy;
  if (
    parsed.unicode_version !== "17.0.0" ||
    parsed.code_point_count !== 4_273 ||
    !Array.isArray(parsed.ranges) ||
    !parsed.ranges.every(
      (range) =>
        typeof range.start === "string" &&
        typeof range.end === "string" &&
        /^[0-9A-F]{4,6}$/u.test(range.start) &&
        /^[0-9A-F]{4,6}$/u.test(range.end),
    )
  ) {
    throw new Error("invalid Unicode presentation policy");
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

function providerRegistration(): ProviderRegistrationRequest {
  return {
    kind: "vscode",
    editor_session_id: "window-1",
    capabilities: ["profile_quick_pick", "status"],
  };
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
  const frame = createProviderRegistrationFrame(providerRegistration());
  assert.match(
    frame.request_id,
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

  const future =
    '{"protocol_version":2,"message_family":"future_event","request_id":{"future":"id"},"message":{"type":"future_v2"},"future_envelope_field":true}';
  assert.throws(
    () => decodeShimRequest(recordText(future)),
    (error: unknown) =>
      error instanceof Error && error.message === "unsupported GUS IPC protocol version 2",
  );
});

test("Rust and TypeScript enforce the complete Unicode 17 presentation deny policy", async () => {
  const policy = await loadPresentationPolicy();
  assert.equal(policy.ranges.length, 27);
  let testedCodePoints = 0;
  for (const range of policy.ranges) {
    const start = Number.parseInt(range.start, 16);
    const end = Number.parseInt(range.end, 16);
    for (let codePoint = start; codePoint <= end; codePoint += 1) {
      testedCodePoints += 1;
      const registration = providerRegistration();
      registration.editor_session_id = `Work${String.fromCodePoint(codePoint)}Profile`;
      assert.throws(
        () => createProviderRegistrationFrame(registration),
        `accepted forbidden presentation character U+${codePoint.toString(16).toUpperCase()}`,
      );
    }
  }
  assert.equal(testedCodePoints, policy.code_point_count);
});

test("provider encoder canonicalizes data properties and rejects smuggling surfaces", () => {
  const frame = createProviderRegistrationFrame(providerRegistration());
  assert(Object.isFrozen(frame));
  assert(Object.isFrozen(frame.message));

  const copied = structuredClone(frame) as typeof frame;
  assert.throws(() => encodeProviderRequest(copied));

  const extra = { ...frame, unexpected: "TOKEN=secret" } as typeof frame;
  assert.throws(() => encodeProviderRequest(extra));

  const registrationWire = encodeProviderRequest(frame);
  assert.equal(
    JSON.stringify(decodeProviderRequest(registrationWire)),
    JSON.stringify(frame),
  );
  assert.throws(() => encodeProviderRequest(frame));

  const inheritedRegistration = Object.assign(
    Object.create({
      toJSON: () => ({ TOKEN: "secret" }),
    }) as object,
    providerRegistration(),
  ) as ProviderRegistrationRequest;
  const inheritedFrame = createProviderRegistrationFrame(inheritedRegistration);
  const inheritedWire = new TextDecoder().decode(encodeProviderRequest(inheritedFrame));
  assert(!inheritedWire.includes("TOKEN"));

  const accessor = providerRegistration();
  Object.defineProperty(accessor, "editor_session_id", {
    enumerable: true,
    get: () => "window-1",
  });
  assert.throws(() => createProviderRegistrationFrame(accessor));

  const sparse = providerRegistration();
  sparse.capabilities = new Array(1) as typeof sparse.capabilities;
  assert.throws(() => createProviderRegistrationFrame(sparse));
});

test("duplicate-key diagnostics never reflect attacker-controlled keys", () => {
  const malicious = '{"x\\nTOKEN=secret":1,"x\\nTOKEN=secret":2}';
  assert.throws(
    () => decodeShimRequest(recordText(malicious)),
    (error: unknown) => error instanceof Error && error.message === "duplicate JSON key",
  );
});

test("provider factories enforce request ID roles and prompt correlation", async () => {
  const publicApi = await import("../src/ipc.js");
  assert(!Object.hasOwn(publicApi, "encodeFrame"));
  assert(!Object.hasOwn(publicApi, "newRequestId"));

  const registration = providerRegistration();
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
  const controlWire = encodeProviderRequest(controlFrame);
  assert.equal(
    JSON.stringify(decodeProviderRequest(controlWire)),
    JSON.stringify(controlFrame),
  );
  assert.throws(() => encodeProviderRequest(controlFrame));
  assert.throws(() =>
    createProviderControlFrame({
      type: "register",
      body: registration,
    } as unknown as ProviderControlMessage),
  );
  assert.throws(() =>
    createProviderControlFrame({
      type: "selection_decision",
      body: {
        registration_id: control.body.registration_id,
        provider_generation: control.body.provider_generation,
        selection_generation: "1",
        decision: { result: "cancelled" },
      },
    } as unknown as ProviderControlMessage),
  );

  const corpus = await loadCorpus();
  const promptCase = corpus.valid.find(
    (entry) =>
      entry.direction === "provider_response" &&
      (entry.payload as { message?: { type?: string } }).message?.type === "selection_prompt",
  );
  assert(promptCase !== undefined);
  const promptFrame = decodeProviderResponse(record(promptCase.payload));
  const forgedPrompt = structuredClone(promptFrame) as DecodedProviderResponseFrame;
  assert.throws(() =>
    createProviderSelectionResponseFrame(forgedPrompt, { result: "cancelled" }),
  );
  const response = createProviderSelectionResponseFrame(promptFrame, { result: "cancelled" });
  assert.throws(() =>
    createProviderSelectionResponseFrame(promptFrame, { result: "unavailable" }),
  );
  assert.equal(response.request_id, promptFrame.request_id);
  assert.equal(response.message.type, "selection_decision");
  const responseWire = encodeProviderRequest(response);
  assert.equal(
    JSON.stringify(decodeProviderRequest(responseWire)),
    JSON.stringify(response),
  );
  assert.throws(() => encodeProviderRequest(response));
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

  const reentrantPrompt = decodeProviderResponse(record(promptCase.payload));
  let attemptedReentry = false;
  let reentrantWire: Uint8Array | undefined;
  let reentrantError: unknown;
  const reentrantDecision = new Proxy(
    { result: "cancelled" } as const,
    {
      get(target, property, receiver) {
        if (property === "result" && !attemptedReentry) {
          attemptedReentry = true;
          try {
            const nestedResponse = createProviderSelectionResponseFrame(reentrantPrompt, {
              result: "unavailable",
            });
            reentrantWire = encodeProviderRequest(nestedResponse);
          } catch (error: unknown) {
            reentrantError = error;
          }
        }
        return Reflect.get(target, property, receiver);
      },
    },
  );
  const reentrySafeResponse = createProviderSelectionResponseFrame(
    reentrantPrompt,
    reentrantDecision,
  );
  assert(attemptedReentry);
  assert.equal(reentrantWire, undefined);
  assert(reentrantError instanceof Error);
  encodeProviderRequest(reentrySafeResponse);
  assert.throws(() => encodeProviderRequest(reentrySafeResponse));

  const invalidDecisionPrompt = decodeProviderResponse(record(promptCase.payload));
  assert.throws(() =>
    createProviderSelectionResponseFrame(
      invalidDecisionPrompt,
      { result: "not-a-decision" } as unknown as { result: "cancelled" },
    ),
  );
  assert.throws(() =>
    createProviderSelectionResponseFrame(invalidDecisionPrompt, { result: "cancelled" }),
  );

  const acknowledged = corpus.valid.find(
    (entry) =>
      entry.direction === "provider_response" &&
      (entry.payload as { message?: { type?: string } }).message?.type === "acknowledged",
  );
  assert(acknowledged !== undefined);
  assert.throws(() =>
    createProviderSelectionResponseFrame(
      decodeProviderResponse(record(acknowledged.payload)),
      { result: "unavailable" },
    ),
  );
});
