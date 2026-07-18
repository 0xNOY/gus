import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  FRAME_HEADER_BYTES,
  type MessageFamily,
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
