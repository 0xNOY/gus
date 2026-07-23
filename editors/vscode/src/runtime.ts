import {
  startProviderBridge,
  type ProviderBridgeOptions,
} from "./bridge.js";
import type {
  ProviderRegistrationRequest,
  ProviderStatusSnapshot,
} from "./ipc.js";
import type { ProviderClient, ProviderScheduler } from "./provider.js";
import {
  VscodeProfilePicker,
  presentStatus,
  type QuickPickWindow,
  type StatusPresentation,
} from "./ui.js";

export interface StatusBar {
  show(presentation: StatusPresentation): void;
  dispose(): void;
}

export interface ProviderRuntimeOptions {
  bridgePath: string;
  runtimeDirectory: string;
  registration: ProviderRegistrationRequest;
  quickPickWindow: QuickPickWindow;
  statusBar: StatusBar;
  scheduler?: ProviderScheduler;
  onFatal(error: Error): void;
}

export interface ProviderRuntime {
  ready: Promise<void>;
  dispose(): void;
}

const RECONNECT_DELAYS_MILLIS = [100, 250, 500, 1000, 2000] as const;

export function startProviderRuntime(
  options: ProviderRuntimeOptions,
  startBridge: (options: ProviderBridgeOptions) => ProviderClient = startProviderBridge,
): ProviderRuntime {
  let disposed = false;
  let client: ProviderClient | undefined;
  let reconnectTimer: unknown;
  let reconnectAttempts = 0;
  let connectionGeneration = 0;
  let resolveReady: (() => void) | undefined;
  let rejectReady: ((error: Error) => void) | undefined;
  const ready = new Promise<void>((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });
  // Keep a rejected readiness signal from becoming an unhandled rejection
  // when a caller only needs disposal. Awaiting `ready` still observes the
  // original rejection.
  void ready.catch(() => {});
  const showStatus = (snapshot: ProviderStatusSnapshot): void => {
    if (!disposed) options.statusBar.show(presentStatus(snapshot));
  };
  const scheduler = options.scheduler ?? systemScheduler;
  const terminalFailure = (error: Error): void => {
    rejectReady?.(error);
    resolveReady = undefined;
    rejectReady = undefined;
    options.statusBar.show({
      text: "$(error) GUS: Provider unavailable",
      tooltip: "The GUS provider connection closed. Git operations requiring a user are blocked.",
      warning: true,
    });
    options.onFatal(error);
  };
  const connect = (initial: boolean): void => {
    const generation = ++connectionGeneration;
    const bridgeOptions: ProviderBridgeOptions = {
      bridgePath: options.bridgePath,
      runtimeDirectory: options.runtimeDirectory,
      registration: options.registration,
      picker: new VscodeProfilePicker(options.quickPickWindow),
      scheduler,
      onReady: () => {
        if (disposed || generation !== connectionGeneration) return;
        reconnectAttempts = 0;
        resolveReady?.();
        resolveReady = undefined;
        rejectReady = undefined;
      },
      onStatus: (snapshot) => {
        if (generation === connectionGeneration) showStatus(snapshot);
      },
      onFatal: (error) => {
        if (disposed || generation !== connectionGeneration) return;
        client?.close();
        client = undefined;
        if (reconnectAttempts >= RECONNECT_DELAYS_MILLIS.length) {
          terminalFailure(error);
          return;
        }
        options.statusBar.show({
          text: "$(sync~spin) GUS: Reconnecting",
          tooltip: "Reconnecting this VS Code window to the GUS broker.",
          warning: false,
        });
        const delay = RECONNECT_DELAYS_MILLIS[reconnectAttempts]!;
        reconnectAttempts += 1;
        reconnectTimer = scheduler.setTimeout(() => {
          reconnectTimer = undefined;
          if (disposed) return;
          try {
            connect(false);
          } catch (retryError) {
            bridgeOptions.onFatal(toError(retryError));
          }
        }, delay);
      },
    };
    try {
      client = startBridge(bridgeOptions);
    } catch (error) {
      if (initial) throw error;
      bridgeOptions.onFatal(toError(error));
    }
  };
  try {
    connect(true);
  } catch (error) {
    options.statusBar.dispose();
    throw error;
  }

  return {
    ready,
    dispose(): void {
      if (disposed) return;
      disposed = true;
      connectionGeneration += 1;
      if (reconnectTimer !== undefined) {
        scheduler.clearTimeout(reconnectTimer);
        reconnectTimer = undefined;
      }
      client?.close();
      options.statusBar.dispose();
    },
  };
}

const systemScheduler: ProviderScheduler = {
  setInterval(callback, milliseconds) {
    return globalThis.setInterval(callback, milliseconds);
  },
  clearInterval(handle) {
    globalThis.clearInterval(handle as ReturnType<typeof setInterval>);
  },
  setTimeout(callback, milliseconds) {
    return globalThis.setTimeout(callback, milliseconds);
  },
  clearTimeout(handle) {
    globalThis.clearTimeout(handle as ReturnType<typeof setTimeout>);
  },
};

function toError(value: unknown): Error {
  return value instanceof Error ? value : new Error(String(value));
}
