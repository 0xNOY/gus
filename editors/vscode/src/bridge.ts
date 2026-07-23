import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { isAbsolute } from "node:path";

import {
  ProviderClient,
  ProviderRecordDecoder,
  type ProfilePicker,
  type ProviderScheduler,
} from "./provider.js";
import type {
  ProviderRegistrationRequest,
  ProviderStatusSnapshot,
} from "./ipc.js";

export interface ProviderBridgeOptions {
  bridgePath: string;
  runtimeDirectory: string;
  registration: ProviderRegistrationRequest;
  picker: ProfilePicker;
  scheduler: ProviderScheduler;
  onStatus(snapshot: ProviderStatusSnapshot): void;
  onFatal(error: Error): void;
}

type BridgeSpawner = (
  executable: string,
  commandArguments: readonly string[],
) => ChildProcessWithoutNullStreams;

export function startProviderBridge(
  options: ProviderBridgeOptions,
  spawnBridge: BridgeSpawner = defaultSpawner,
): ProviderClient {
  if (!isAbsolute(options.bridgePath) || !isAbsolute(options.runtimeDirectory)) {
    throw new Error("GUS provider bridge and runtime paths must be absolute");
  }
  const process = spawnBridge(
    options.bridgePath,
    ["--runtime-dir", options.runtimeDirectory],
  );
  const decoder = new ProviderRecordDecoder();
  let client: ProviderClient | undefined;
  let transportClosed = false;
  let fatalReported = false;

  const fail = (error: Error): void => {
    if (fatalReported) return;
    fatalReported = true;
    client?.close();
    options.onFatal(error);
  };
  const transport = {
    write: async (record: Uint8Array): Promise<void> => {
      if (transportClosed || process.stdin.destroyed) {
        throw new Error("GUS provider bridge is closed");
      }
      const owned = Buffer.from(record);
      await new Promise<void>((resolve, reject) => {
        process.stdin.write(owned, (error) => {
          if (error === null || error === undefined) resolve();
          else reject(error);
        });
      });
    },
    close: (): void => {
      if (transportClosed) return;
      transportClosed = true;
      process.stdin.destroy();
      process.stdout.destroy();
      process.stderr.destroy();
      if (process.exitCode === null && process.signalCode === null) {
        process.kill();
      }
    },
  };

  client = new ProviderClient({
    registration: options.registration,
    transport,
    picker: options.picker,
    scheduler: options.scheduler,
    onStatus: options.onStatus,
    onFatal: fail,
  });
  process.stdout.on("data", (chunk: Buffer) => {
    try {
      for (const record of decoder.push(chunk)) client?.receive(record);
    } catch (error) {
      fail(toError(error));
    }
  });
  process.stdin.on("error", (error) => fail(error));
  process.stdout.on("error", (error) => fail(error));
  process.stderr.resume();
  process.once("error", (error) => fail(error));
  process.once("exit", (code, signal) => {
    if (!transportClosed) {
      fail(new Error(
        `GUS provider bridge exited (${code === null ? "signal" : `code ${String(code)}`}${signal === null ? "" : ` ${signal}`})`,
      ));
    }
  });
  client.start();
  return client;
}

function defaultSpawner(
  executable: string,
  commandArguments: readonly string[],
): ChildProcessWithoutNullStreams {
  return spawn(executable, commandArguments, {
    shell: false,
    windowsHide: true,
    stdio: ["pipe", "pipe", "pipe"],
  });
}

function toError(value: unknown): Error {
  return value instanceof Error ? value : new Error(String(value));
}
