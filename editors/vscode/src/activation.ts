import { isAbsolute, join } from "node:path";

export interface ProviderLaunch {
  bridgePath: string;
  runtimeDirectory: string;
}

export function resolveProviderLaunch(
  extensionPath: string,
  environment: Readonly<Record<string, string | undefined>>,
  platform: NodeJS.Platform,
  userId: number | undefined,
): ProviderLaunch {
  if (!isAbsolute(extensionPath)) {
    throw new Error("GUS extension path must be absolute");
  }
  const bridgeName = platform === "win32"
    ? "gus-provider-bridge.exe"
    : "gus-provider-bridge";
  const bridgePath = join(extensionPath, "bin", bridgeName);

  const configuredRuntime = environment.GUS_RUNTIME_DIR;
  if (configuredRuntime !== undefined) {
    if (!isAbsolute(configuredRuntime)) {
      throw new Error("GUS_RUNTIME_DIR must be absolute");
    }
    return { bridgePath, runtimeDirectory: configuredRuntime };
  }

  const xdgRuntime = environment.XDG_RUNTIME_DIR;
  if (xdgRuntime !== undefined) {
    if (!isAbsolute(xdgRuntime)) {
      throw new Error("XDG_RUNTIME_DIR must be absolute");
    }
    return { bridgePath, runtimeDirectory: join(xdgRuntime, "gus") };
  }

  if (platform !== "win32" && userId !== undefined) {
    return {
      bridgePath,
      runtimeDirectory: `/tmp/gus-${String(userId)}`,
    };
  }
  throw new Error("GUS runtime directory is unavailable on this platform");
}
