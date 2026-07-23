import assert from "node:assert/strict";
import { test } from "node:test";

import type {
  ProfilePresentation,
  ProviderStatusSnapshot,
  SelectionPrompt,
} from "../src/ipc.js";
import {
  VscodeProfilePicker,
  presentStatus,
  type QuickPickItem,
  type QuickPickOptions,
} from "../src/ui.js";

const CONTROL = {
  registration_id: "10000000-0000-4000-8000-000000000001",
  provider_generation: "1",
} as const;
const REPOSITORY = {
  identity: "22".repeat(32),
  label: "gus",
} as const;
const PROFILE: ProfilePresentation = {
  profile_id: "alice",
  display_name: "Alice Example",
  email: "alice@example.test",
};

function prompt(): SelectionPrompt {
  return {
    ...CONTROL,
    selection_generation: "2",
    scope: {
      kind: "ide_window",
      opaque_id: "33".repeat(32),
      label: "SCM",
    },
    repository: REPOSITORY,
    operation: "commit",
    profiles: [PROFILE],
    timeout_millis: 10_000,
  };
}

test("profile picker presents the repository, scope, operation, and identity", async () => {
  let receivedItems: readonly QuickPickItem[] = [];
  let receivedOptions: QuickPickOptions | undefined;
  const abort = new AbortController();
  const picker = new VscodeProfilePicker({
    showQuickPick: async (items, options, signal) => {
      receivedItems = items;
      receivedOptions = options;
      assert.equal(signal, abort.signal);
      return items[0];
    },
  });

  assert.equal(await picker.pick(prompt(), abort.signal), PROFILE);
  assert.deepEqual(receivedItems.map(({ label, description, detail }) => ({
    label,
    description,
    detail,
  })), [{
    label: "Alice Example",
    description: "alice@example.test",
    detail: "Profile: alice",
  }]);
  assert.equal(receivedOptions?.title, "GUS: Select User");
  assert.equal(receivedOptions?.placeHolder, "gus · SCM · Commit");
});

test("profile picker cancellation does not select a fallback identity", async () => {
  const picker = new VscodeProfilePicker({
    showQuickPick: async () => undefined,
  });
  assert.equal(await picker.pick(prompt(), new AbortController().signal), undefined);
});

test("status gives protection failures precedence over selected profiles", () => {
  const snapshot: ProviderStatusSnapshot = {
    ...CONTROL,
    entries: [{
      scope: prompt().scope,
      repository: REPOSITORY,
      selected_profile: PROFILE,
      protection: "unverified",
    }],
  };
  assert.deepEqual(presentStatus(snapshot), {
    text: "$(warning) GUS: Protection not verified",
    tooltip: "gus: The GUS Git shim is not verified.",
    warning: true,
  });
});

test("status shows SCM identity and keeps other scopes in the tooltip", () => {
  const snapshot: ProviderStatusSnapshot = {
    ...CONTROL,
    entries: [
      {
        scope: {
          kind: "terminal",
          opaque_id: "44".repeat(32),
          label: "Terminal 1",
        },
        repository: REPOSITORY,
        selected_profile: {
          profile_id: "bob",
          display_name: "Bob Example",
          email: null,
        },
        protection: "verified",
      },
      {
        scope: prompt().scope,
        repository: REPOSITORY,
        selected_profile: PROFILE,
        protection: "verified",
      },
    ],
  };
  const status = presentStatus(snapshot);
  assert.equal(status.text, "$(git-commit) GUS SCM: Alice Example");
  assert.match(status.tooltip, /Terminal 1\): Bob Example/u);
  assert.match(status.tooltip, /SCM\): Alice Example <alice@example\.test>/u);
});
