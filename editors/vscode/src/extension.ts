import { existsSync } from "node:fs";

import * as vscode from "vscode";

import { resolveProviderLaunch } from "./activation.js";
import { startProviderRuntime, type StatusBar } from "./runtime.js";
import type {
  QuickPickItem,
  QuickPickOptions,
  QuickPickWindow,
  StatusPresentation,
} from "./ui.js";

export function activate(context: vscode.ExtensionContext): void {
  const output = vscode.window.createOutputChannel("GUS");
  context.subscriptions.push(output);
  context.subscriptions.push(vscode.commands.registerCommand(
    "gus.showDiagnostics",
    () => output.show(true),
  ));
  output.appendLine(
    `GUS ${String(context.extension.packageJSON.version)}; `
      + `platform=${process.platform}/${process.arch}; `
      + `remote=${vscode.env.remoteName ?? "local"}`,
  );
  const item = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    50,
  );
  const statusBar = new VscodeStatusBar(item);
  statusBar.show({
    text: "$(sync~spin) GUS: Connecting",
    tooltip: "Connecting this VS Code window to the GUS broker.",
    warning: false,
  });

  try {
    const launch = resolveProviderLaunch(
      context.extensionPath,
      process.env,
      process.platform,
      process.getuid?.(),
    );
    if (!existsSync(launch.bridgePath)) {
      throw new Error(`bundled provider bridge is missing: ${launch.bridgePath}`);
    }
    if (vscode.env.sessionId.length === 0) {
      throw new Error("VS Code did not provide a session identifier");
    }
    const runtime = startProviderRuntime({
      ...launch,
      registration: {
        kind: "vscode",
        editor_session_id: vscode.env.sessionId,
        capabilities: ["profile_quick_pick", "status", "diagnostics"],
      },
      quickPickWindow: new VscodeQuickPickWindow(),
      statusBar,
      onFatal: (error) => {
        output.appendLine(`Provider connection failed: ${error.message}`);
        void vscode.window.showErrorMessage(
          "GUS provider is unavailable. Git operations requiring a user are blocked.",
        );
      },
    });
    void runtime.ready.catch(() => {});
    context.subscriptions.push(runtime);
  } catch (error) {
    const message = toError(error).message;
    output.appendLine(`Activation failed: ${message}`);
    statusBar.show({
      text: "$(error) GUS: Provider unavailable",
      tooltip: "GUS could not start its authenticated provider bridge.",
      warning: true,
    });
    context.subscriptions.push(statusBar);
    void vscode.window.showErrorMessage(
      "GUS could not connect to its provider. Protected Git operations remain blocked.",
    );
  }
}

class VscodeQuickPickWindow implements QuickPickWindow {
  async showQuickPick(
    items: readonly QuickPickItem[],
    options: QuickPickOptions,
    signal: AbortSignal,
  ): Promise<QuickPickItem | undefined> {
    const cancellation = new vscode.CancellationTokenSource();
    const cancel = (): void => cancellation.cancel();
    if (signal.aborted) cancel();
    signal.addEventListener("abort", cancel, { once: true });
    try {
      return await vscode.window.showQuickPick(items, options, cancellation.token);
    } finally {
      signal.removeEventListener("abort", cancel);
      cancellation.dispose();
    }
  }
}

class VscodeStatusBar implements StatusBar {
  readonly #item: vscode.StatusBarItem;

  constructor(item: vscode.StatusBarItem) {
    this.#item = item;
    this.#item.command = "gus.showDiagnostics";
  }

  show(presentation: StatusPresentation): void {
    this.#item.text = presentation.text;
    this.#item.tooltip = presentation.tooltip;
    this.#item.backgroundColor = presentation.warning
      ? new vscode.ThemeColor("statusBarItem.warningBackground")
      : undefined;
    this.#item.show();
  }

  dispose(): void {
    this.#item.dispose();
  }
}

function toError(value: unknown): Error {
  return value instanceof Error ? value : new Error(String(value));
}
