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
  dispose(): void;
}

export function startProviderRuntime(
  options: ProviderRuntimeOptions,
  startBridge: (options: ProviderBridgeOptions) => ProviderClient = startProviderBridge,
): ProviderRuntime {
  let disposed = false;
  let client: ProviderClient | undefined;
  const showStatus = (snapshot: ProviderStatusSnapshot): void => {
    if (!disposed) options.statusBar.show(presentStatus(snapshot));
  };
  try {
    client = startBridge({
      bridgePath: options.bridgePath,
      runtimeDirectory: options.runtimeDirectory,
      registration: options.registration,
      picker: new VscodeProfilePicker(options.quickPickWindow),
      scheduler: options.scheduler ?? systemScheduler,
      onStatus: showStatus,
      onFatal: (error) => {
        if (disposed) return;
        options.statusBar.show({
          text: "$(error) GUS: Provider unavailable",
          tooltip: "The GUS provider connection closed. Git operations requiring a user are blocked.",
          warning: true,
        });
        options.onFatal(error);
      },
    });
  } catch (error) {
    options.statusBar.dispose();
    throw error;
  }

  return {
    dispose(): void {
      if (disposed) return;
      disposed = true;
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
