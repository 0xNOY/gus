import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, mkdtemp, mkdir, rename, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { startProviderRuntime } from "../dist/src/runtime.js";

const extensionRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const workspaceRoot = resolve(extensionRoot, "..", "..");
const target = join(workspaceRoot, "target", "debug");
const brokerPath = join(target, "gus-broker");
const bridgePath = join(target, "gus-provider-bridge");
const shimPath = join(target, "gus-git-shim");

test("VS Code provider selects the identity used by a real shimmed commit", async (context) => {
  if (process.platform !== "linux") context.skip("the native daemon is currently Linux-only");
  await Promise.all([brokerPath, bridgePath, shimPath].map(requireExecutable));

  const root = await mkdtemp(join(tmpdir(), "gus-vscode-e2e-"));
  const runtimeDirectory = join(root, "runtime");
  const repository = join(root, "repository");
  const profileStore = join(root, "profiles.toml");
  await mkdir(runtimeDirectory, { mode: 0o700 });
  await mkdir(repository, { mode: 0o700 });
  await writeFile(profileStore, profileToml, { mode: 0o600 });

  const environment = {
    ...process.env,
    GUS_RUNTIME_DIR: runtimeDirectory,
    GUS_PROFILE_STORE: profileStore,
  };
  const broker = spawn(brokerPath, [], {
    env: environment,
    shell: false,
    stdio: ["ignore", "ignore", "pipe"],
  });
  let brokerError = "";
  broker.stderr.setEncoding("utf8");
  broker.stderr.on("data", (chunk) => {
    brokerError += chunk;
  });
  let runtime;
  try {
    await waitForPath(join(runtimeDirectory, "provider.current"));
    await run("git", ["init", "--quiet"], { cwd: repository, env: environment });

    let prompts = 0;
    let fatal;
    let repositoryToReplace;
    const statuses = [];
    runtime = startProviderRuntime({
      bridgePath,
      runtimeDirectory,
      registration: {
        kind: "vscode",
        editor_session_id: "native-e2e-window",
        capabilities: ["profile_quick_pick", "status"],
      },
      quickPickWindow: {
        async showQuickPick(items, _options, signal) {
          assert.equal(signal.aborted, false);
          assert.equal(items.length, 1);
          prompts += 1;
          if (prompts === 1) {
            assert.equal(items[0].profile.display_name, "Alice Example");
          } else if (prompts === 2) {
            assert.equal(items[0].profile.display_name, "Mallory Example");
            await writeFile(profileStore, racedProfileToml, { mode: 0o600 });
          } else {
            assert.equal(items[0].profile.display_name, "Eve Example");
            assert.notEqual(repositoryToReplace, undefined);
            await rename(
              join(repositoryToReplace, ".git"),
              join(repositoryToReplace, ".git-original"),
            );
            await mkdir(join(repositoryToReplace, ".git"), { mode: 0o700 });
          }
          return items[0];
        },
      },
      statusBar: {
        show(status) {
          statuses.push(status);
        },
        dispose() {},
      },
      onFatal(error) {
        fatal = error;
      },
    });
    await runtime.ready;

    const commit = await run(
      shimPath,
      ["commit", "--allow-empty", "-m", "brokered identity"],
      {
        cwd: repository,
        env: environment,
        detached: true,
      },
    );
    assert.equal(commit.stderr.includes("GUS_E_"), false, commit.stderr);
    assert.equal(prompts, 1);
    assert.equal(fatal, undefined);
    assert.equal(statuses.at(-1)?.text, "$(git-commit) GUS SCM: Alice Example");

    const log = await run(
      "git",
      ["log", "-1", "--format=%an%x00%ae%x00%cn%x00%ce"],
      { cwd: repository, env: environment },
    );
    assert.deepEqual(
      log.stdout.trimEnd().split("\0"),
      ["Alice Example", "alice@example.com", "Alice Example", "alice@example.com"],
    );

    await writeFile(profileStore, replacementProfileToml, { mode: 0o600 });
    const replaced = await runUnchecked(
      shimPath,
      ["commit", "--allow-empty", "-m", "replaced identity"],
      {
        cwd: repository,
        env: environment,
        detached: true,
      },
    );
    assert.equal(replaced.signal, null);
    assert.notEqual(replaced.code, 0, "same-generation profile replacement was accepted");
    assert.match(replaced.stderr, /GUS_E_SELECTION_FAILED/u);
    assert.equal(prompts, 2, "changed profile content must require a new confirmation");
    const count = await run("git", ["rev-list", "--count", "HEAD"], {
      cwd: repository,
      env: environment,
    });
    assert.equal(count.stdout.trim(), "1");

    repositoryToReplace = join(root, "replaced-repository");
    await mkdir(repositoryToReplace, { mode: 0o700 });
    await run("git", ["init", "--quiet"], {
      cwd: repositoryToReplace,
      env: environment,
    });
    const repositoryRace = await runUnchecked(
      shimPath,
      ["commit", "--allow-empty", "-m", "replaced repository"],
      {
        cwd: repositoryToReplace,
        env: environment,
        detached: true,
      },
    );
    assert.equal(repositoryRace.signal, null);
    assert.notEqual(repositoryRace.code, 0);
    assert.match(repositoryRace.stderr, /GUS_E_REAL_GIT/u);
    assert.equal(prompts, 3);
  } finally {
    runtime?.dispose();
    broker.kill("SIGTERM");
    await onceExited(broker);
    await rm(root, { recursive: true, force: true });
  }
  assert.equal(brokerError, "");
});

async function requireExecutable(path) {
  const metadata = await stat(path);
  assert.equal(metadata.isFile(), true, `${path} is not a file`);
  assert.notEqual(metadata.mode & 0o111, 0, `${path} is not executable`);
}

async function waitForPath(path) {
  const deadline = Date.now() + 5_000;
  while (true) {
    try {
      await stat(path);
      return;
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    assert.ok(Date.now() < deadline, `${path} was not published`);
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 10));
  }
}

async function run(executable, commandArguments, options) {
  const result = await runUnchecked(executable, commandArguments, options);
  assert.equal(
    result.signal,
    null,
    `${executable} exited from ${result.signal ?? "no signal"}: ${result.stderr}`,
  );
  assert.equal(
    result.code,
    0,
    `${executable} exited with ${String(result.code)}: ${result.stderr}`,
  );
  return result;
}

async function runUnchecked(executable, commandArguments, options) {
  const child = spawn(executable, commandArguments, {
    cwd: options.cwd,
    env: options.env,
    detached: options.detached ?? false,
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  const { code, signal } = await onceExited(child);
  return { stdout, stderr, code, signal };
}

function onceExited(child) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return Promise.resolve({ code: child.exitCode, signal: child.signalCode });
  }
  return new Promise((resolvePromise, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => resolvePromise({ code, signal }));
  });
}

const profileToml = `version = 2
generation = 1

[profiles.alice]
id = "alice"
generation = 1

[profiles.alice.author]
name = "Alice Example"
email = "alice@example.com"

[profiles.alice.committer]
name = "Alice Example"
email = "alice@example.com"
`;

const replacementProfileToml = `version = 2
generation = 1

[profiles.alice]
id = "alice"
generation = 1

[profiles.alice.author]
name = "Mallory Example"
email = "mallory@example.com"

[profiles.alice.committer]
name = "Mallory Example"
email = "mallory@example.com"
`;

const racedProfileToml = `version = 2
generation = 1

[profiles.alice]
id = "alice"
generation = 1

[profiles.alice.author]
name = "Eve Example"
email = "eve@example.com"

[profiles.alice.committer]
name = "Eve Example"
email = "eve@example.com"
`;
