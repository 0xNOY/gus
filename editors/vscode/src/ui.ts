import type {
  OperationPresentation,
  ProfilePresentation,
  ProviderStatusEntry,
  ProviderStatusSnapshot,
  SelectionPrompt,
} from "./ipc.js";
import type { ProfilePicker } from "./provider.js";

export interface QuickPickItem {
  label: string;
  description?: string;
  detail: string;
  profile: ProfilePresentation;
}

export interface QuickPickOptions {
  title: string;
  placeHolder: string;
  matchOnDescription: boolean;
  matchOnDetail: boolean;
}

export interface QuickPickWindow {
  showQuickPick(
    items: readonly QuickPickItem[],
    options: QuickPickOptions,
    signal: AbortSignal,
  ): Promise<QuickPickItem | undefined>;
}

export class VscodeProfilePicker implements ProfilePicker {
  readonly #window: QuickPickWindow;

  constructor(window: QuickPickWindow) {
    this.#window = window;
  }

  async pick(
    prompt: SelectionPrompt,
    signal: AbortSignal,
  ): Promise<ProfilePresentation | undefined> {
    const items = prompt.profiles.map((profile) => ({
      label: profile.display_name,
      ...(profile.email === null ? {} : { description: profile.email }),
      detail: `Profile: ${profile.profile_id}`,
      profile,
    }));
    const selected = await this.#window.showQuickPick(items, {
      title: "GUS: Select User",
      placeHolder:
        `${prompt.repository.label} · ${prompt.scope.label} · ${operationLabel(prompt.operation)}`,
      matchOnDescription: true,
      matchOnDetail: true,
    }, signal);
    return selected?.profile;
  }
}

export interface StatusPresentation {
  text: string;
  tooltip: string;
  warning: boolean;
}

export function presentStatus(snapshot: ProviderStatusSnapshot): StatusPresentation {
  if (snapshot.entries.length === 0) {
    return {
      text: "$(person) GUS: Select on protected operation",
      tooltip: "No GUS user is selected for this window.",
      warning: false,
    };
  }

  const unsafe = snapshot.entries.find((entry) => entry.protection !== "verified");
  if (unsafe !== undefined) {
    const unavailable = unsafe.protection === "unavailable";
    return {
      text: unavailable
        ? "$(error) GUS: Protection unavailable"
        : "$(warning) GUS: Protection not verified",
      tooltip: `${unsafe.repository.label}: ${
        unavailable ? "GUS protection is unavailable." : "The GUS Git shim is not verified."
      }`,
      warning: true,
    };
  }

  const selected = snapshot.entries.filter((entry) => entry.selected_profile !== null);
  const headline = chooseHeadline(selected);
  if (headline === undefined) {
    return {
      text: "$(person) GUS: Select on protected operation",
      tooltip: snapshot.entries
        .map((entry) => `${entry.repository.label} (${entry.scope.label}): not selected`)
        .join("\n"),
      warning: false,
    };
  }
  return {
    text: `$(${headline.scope.kind === "terminal" ? "terminal" : "git-commit"}) ${
      headline.scope.kind === "terminal" ? "GUS Terminal" : "GUS SCM"
    }: ${headline.selected_profile!.display_name}`,
    tooltip: selected.map(statusLine).join("\n"),
    warning: false,
  };
}

function chooseHeadline(entries: readonly ProviderStatusEntry[]): ProviderStatusEntry | undefined {
  return entries.find((entry) => entry.scope.kind === "ide_window")
    ?? entries.find((entry) => entry.scope.kind === "terminal")
    ?? entries[0];
}

function statusLine(entry: ProviderStatusEntry): string {
  const profile = entry.selected_profile;
  if (profile === null) return `${entry.repository.label} (${entry.scope.label}): not selected`;
  const email = profile.email === null ? "" : ` <${profile.email}>`;
  return `${entry.repository.label} (${entry.scope.label}): ${profile.display_name}${email}`;
}

function operationLabel(operation: OperationPresentation): string {
  switch (operation) {
    case "local_read":
      return "Read repository";
    case "worktree_mutation":
      return "Modify worktree";
    case "commit":
      return "Commit";
    case "tag":
      return "Create tag";
    case "history_rewrite":
      return "Rewrite history";
    case "merge":
      return "Merge";
    case "remote_read":
      return "Fetch from remote";
    case "push":
      return "Push";
    case "unknown_protected":
      return "Protected Git operation";
  }
}
