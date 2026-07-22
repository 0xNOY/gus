import type {
  DecodedProviderResponseFrame,
  EncodableProviderRequestFrame,
  ProfilePresentation,
  ProviderDecision,
  ProviderRegistrationRequest,
  ProviderStatusSnapshot,
  SelectionPrompt,
} from "./ipc.js";
import {
  FRAME_HEADER_BYTES,
  MAX_FRAME_BYTES,
  createProviderControlFrame,
  createProviderRegistrationFrame,
  createProviderSelectionResponseFrame,
  decodeProviderResponse,
  encodeProviderRequest,
} from "./ipc.js";

const MAX_OUTSTANDING_PROMPTS = 32;
const MAX_SEEN_PROMPTS = 4096;

export interface ProviderTransport {
  write(record: Uint8Array): Promise<void>;
  close(): void;
}

export interface ProviderScheduler {
  setInterval(callback: () => void, milliseconds: number): unknown;
  clearInterval(handle: unknown): void;
  setTimeout(callback: () => void, milliseconds: number): unknown;
  clearTimeout(handle: unknown): void;
}

export interface ProfilePicker {
  pick(prompt: SelectionPrompt, signal: AbortSignal): Promise<ProfilePresentation | undefined>;
}

export interface ProviderClientOptions {
  registration: ProviderRegistrationRequest;
  transport: ProviderTransport;
  picker: ProfilePicker;
  scheduler: ProviderScheduler;
  onStatus(snapshot: ProviderStatusSnapshot): void;
  onFatal(error: Error): void;
}

export class ProviderRecordDecoder {
  readonly #buffer: number[] = [];

  push(chunk: Uint8Array): Uint8Array[] {
    for (const byte of chunk) this.#buffer.push(byte);
    const records: Uint8Array[] = [];
    while (this.#buffer.length >= FRAME_HEADER_BYTES) {
      const length =
        this.#buffer[0]! * 0x1000000 +
        this.#buffer[1]! * 0x10000 +
        this.#buffer[2]! * 0x100 +
        this.#buffer[3]!;
      if (length === 0 || length > MAX_FRAME_BYTES) {
        throw new Error("invalid GUS IPC record length");
      }
      const recordLength = FRAME_HEADER_BYTES + length;
      if (this.#buffer.length < recordLength) break;
      records.push(Uint8Array.from(this.#buffer.splice(0, recordLength)));
    }
    return records;
  }
}

export class ProviderClient {
  readonly #options: ProviderClientOptions;
  #registrationFrame: EncodableProviderRequestFrame | undefined;
  readonly #statusCapability: boolean;
  #registrationRequestId: string | undefined;
  #registrationId: string | undefined;
  #providerGeneration: string | undefined;
  #heartbeat: unknown;
  #closed = false;
  #writeTail: Promise<void> = Promise.resolve();
  #repositories: Set<string>;
  readonly #seenPrompts = new Set<string>();
  readonly #prompts = new Map<string, { abort: AbortController; timeout: unknown }>();
  readonly #pendingControls = new Map<string, {
    membership?: { generation: string; repositories: Set<string> };
  }>();
  #membershipGeneration: bigint | undefined;

  constructor(options: ProviderClientOptions) {
    this.#options = options;
    this.#registrationFrame = createProviderRegistrationFrame(options.registration);
    const message = this.#registrationFrame.message;
    if (message.type !== "register") throw new Error("invalid GUS registration factory result");
    this.#repositories = new Set(message.body.repositories);
    this.#statusCapability = message.body.capabilities.includes("status");
  }

  start(): void {
    if (this.#registrationRequestId !== undefined || this.#closed) {
      throw new Error("GUS provider client cannot be started twice");
    }
    try {
      const frame = this.#registrationFrame;
      if (frame === undefined) throw new Error("missing GUS provider registration");
      this.#registrationFrame = undefined;
      this.#registrationRequestId = frame.request_id;
      this.#send(frame);
    } catch (error) {
      this.#fail(toError(error));
    }
  }

  receive(record: Uint8Array): void {
    if (this.#closed) return;
    let frame: DecodedProviderResponseFrame;
    try {
      frame = decodeProviderResponse(record);
      this.#accept(frame);
    } catch (error) {
      this.#fail(toError(error));
    }
  }

  close(): void {
    if (this.#closed) return;
    // Closing the authenticated transport is itself a terminal provider
    // transition. Do not enqueue an unregister record which may be only
    // partially written during extension-host shutdown.
    this.#shutdown();
  }

  updateRepositories(repositories: string[], membershipGeneration: string): void {
    const control = this.#control();
    if (control === undefined || this.#closed) {
      throw new Error("GUS provider is not registered");
    }
    if ([...this.#pendingControls.values()].some((pending) => pending.membership !== undefined)) {
      throw new Error("GUS repository membership update is already pending");
    }
    const parsedGeneration = BigInt(membershipGeneration);
    if (this.#membershipGeneration !== undefined && parsedGeneration <= this.#membershipGeneration) {
      throw new Error("GUS repository membership generation is stale");
    }
    const frame = createProviderControlFrame({
      type: "update_repositories",
      body: {
        ...control,
        membership_generation: membershipGeneration,
        repositories,
      },
    });
    const message = frame.message;
    if (message.type !== "update_repositories") {
      throw new Error("invalid GUS membership factory result");
    }
    this.#cancelPrompts();
    this.#pendingControls.set(frame.request_id, {
      membership: {
        generation: message.body.membership_generation,
        repositories: new Set(message.body.repositories),
      },
    });
    this.#send(frame);
  }

  #accept(frame: DecodedProviderResponseFrame): void {
    switch (frame.message.type) {
      case "registered": {
        if (
          this.#registrationId !== undefined ||
          frame.request_id !== this.#registrationRequestId ||
          frame.message.body.registration_id !== this.#registrationRequestId
        ) {
          throw new Error("invalid GUS provider registration response");
        }
        this.#registrationId = frame.message.body.registration_id;
        this.#providerGeneration = frame.message.body.provider_generation;
        const control = this.#control();
        if (control === undefined) throw new Error("missing GUS provider registration state");
        this.#heartbeat = this.#options.scheduler.setInterval(() => {
          this.#send(createProviderControlFrame({ type: "heartbeat", body: control }));
        }, frame.message.body.heartbeat_interval_millis);
        if (this.#statusCapability) {
          this.#send(createProviderControlFrame({ type: "subscribe_status", body: control }));
        }
        return;
      }
      case "selection_prompt":
        this.#requireControl(frame.message.body);
        if (!this.#repositories.has(frame.message.body.repository.identity)) {
          throw new Error("GUS prompt is outside provider repository membership");
        }
        if (this.#seenPrompts.has(frame.request_id)) {
          throw new Error("duplicate GUS selection prompt");
        }
        if (
          this.#seenPrompts.size >= MAX_SEEN_PROMPTS ||
          this.#prompts.size >= MAX_OUTSTANDING_PROMPTS
        ) {
          throw new Error("GUS selection prompt capacity exceeded");
        }
        this.#seenPrompts.add(frame.request_id);
        void this.#answer(frame);
        return;
      case "status_snapshot":
        this.#requireControl(frame.message.body);
        if (frame.message.body.entries.some(
          (entry) => !this.#repositories.has(entry.repository.identity),
        )) {
          throw new Error("GUS status is outside provider repository membership");
        }
        this.#options.onStatus(frame.message.body);
        return;
      case "acknowledged":
        {
          const pending = this.#pendingControls.get(frame.request_id);
          if (pending === undefined) {
            throw new Error("GUS provider acknowledged an unknown command");
          }
          this.#pendingControls.delete(frame.request_id);
          if (pending.membership !== undefined) {
            // A prompt for the old membership can cross this update on the
            // full-duplex transport after the request was queued. The broker
            // revokes it at the same transition represented by this ACK.
            this.#cancelPrompts();
            this.#repositories = pending.membership.repositories;
            this.#membershipGeneration = BigInt(pending.membership.generation);
          }
        }
        return;
      case "error":
        throw new Error(`GUS broker rejected provider request: ${frame.message.body.code}`);
    }
  }

  async #answer(frame: DecodedProviderResponseFrame): Promise<void> {
    const prompt = frame.message;
    if (prompt.type !== "selection_prompt") {
      this.#fail(new Error("invalid prompt dispatch"));
      return;
    }
    const abort = new AbortController();
    const timeout = this.#options.scheduler.setTimeout(() => {
      if (this.#prompts.delete(frame.request_id)) abort.abort();
    }, prompt.body.timeout_millis);
    this.#prompts.set(frame.request_id, { abort, timeout });
    let decision: ProviderDecision;
    try {
      const selected = await this.#options.picker.pick(prompt.body, abort.signal);
      if (!this.#prompts.delete(frame.request_id)) return;
      this.#options.scheduler.clearTimeout(timeout);
      if (selected === undefined) {
        decision = { result: "cancelled" };
      } else {
        const offered = prompt.body.profiles.find(
          (profile) => profile.profile_id === selected.profile_id,
        );
        decision = offered === undefined
          ? { result: "unavailable" }
          : { result: "selected", profile_id: offered.profile_id };
      }
    } catch {
      if (!this.#prompts.delete(frame.request_id)) return;
      this.#options.scheduler.clearTimeout(timeout);
      decision = { result: "unavailable" };
    }
    if (this.#closed) return;
    try {
      this.#send(createProviderSelectionResponseFrame(frame, decision));
    } catch (error) {
      this.#fail(toError(error));
    }
  }

  #control(): { registration_id: string; provider_generation: string } | undefined {
    if (this.#registrationId === undefined || this.#providerGeneration === undefined) {
      return undefined;
    }
    return {
      registration_id: this.#registrationId,
      provider_generation: this.#providerGeneration,
    };
  }

  #requireControl(value: { registration_id: string; provider_generation: string }): void {
    const control = this.#control();
    if (
      control === undefined ||
      value.registration_id !== control.registration_id ||
      value.provider_generation !== control.provider_generation
    ) {
      throw new Error("stale or foreign GUS provider response");
    }
  }

  #send(frame: EncodableProviderRequestFrame): void {
    if (this.#closed) return;
    let record: Uint8Array;
    try {
      record = encodeProviderRequest(frame);
    } catch (error) {
      this.#fail(toError(error));
      return;
    }
    if (frame.message.type !== "register" && !this.#pendingControls.has(frame.request_id)) {
      this.#pendingControls.set(frame.request_id, {});
    }
    this.#writeTail = this.#writeTail
      .then(() => {
        if (this.#closed) return;
        return this.#options.transport.write(record);
      })
      .catch((error: unknown) => this.#fail(toError(error)));
  }

  #fail(error: Error): void {
    if (this.#closed) return;
    this.#shutdown();
    this.#options.onFatal(error);
  }

  #shutdown(): void {
    if (this.#closed) return;
    this.#closed = true;
    if (this.#heartbeat !== undefined) {
      this.#options.scheduler.clearInterval(this.#heartbeat);
      this.#heartbeat = undefined;
    }
    this.#cancelPrompts();
    this.#options.transport.close();
  }

  #cancelPrompts(): void {
    for (const prompt of this.#prompts.values()) {
      this.#options.scheduler.clearTimeout(prompt.timeout);
      prompt.abort.abort();
    }
    this.#prompts.clear();
  }
}

function toError(value: unknown): Error {
  return value instanceof Error ? value : new Error(String(value));
}
