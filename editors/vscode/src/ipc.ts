import { randomUUID } from "node:crypto";

export const PROTOCOL_VERSION = 1 as const;
export const FRAME_HEADER_BYTES = 4;
export const MAX_FRAME_BYTES = 64 * 1024;

export type MessageFamily =
  | "shim_request"
  | "shim_response"
  | "provider_request"
  | "provider_response";
export type RequestId = string;
export type Generation = string;
export type Digest32 = string;
export type ProfileId = string;

export interface WireFrame<F extends MessageFamily, M> {
  protocol_version: typeof PROTOCOL_VERSION;
  message_family: F;
  request_id: RequestId;
  message: M;
}

export type OperationPresentation =
  | "local_read"
  | "worktree_mutation"
  | "commit"
  | "tag"
  | "history_rewrite"
  | "merge"
  | "remote_read"
  | "push"
  | "unknown_protected";

export interface ResolveSelectionRequest {
  plan_digest: Digest32;
  repository_identity: Digest32;
  operation: OperationPresentation;
  explicit_profile: ProfileId | null;
}

export interface ClearSelectionRequest {
  repository_identity: Digest32;
  expected_session_generation: Generation | null;
}

export interface StatusRequest {
  repository_identity: Digest32;
}

export type ShimRequest =
  | { type: "resolve_selection"; body: ResolveSelectionRequest }
  | { type: "clear_selection"; body: ClearSelectionRequest }
  | { type: "status"; body: StatusRequest };

export type ProviderKind = "vscode" | "jet_brains" | "native_prompt";
export type ProviderCapability =
  | "profile_quick_pick"
  | "status"
  | "diagnostics"
  | "reload_action";

export interface ProviderRegistrationRequest {
  kind: ProviderKind;
  editor_session_id: string;
  host_instance: Digest32;
  repositories: Digest32[];
  capabilities: ProviderCapability[];
}

export interface ProviderControlRequest {
  registration_id: RequestId;
  provider_generation: Generation;
}

export interface ProviderRepositoryMembership extends ProviderControlRequest {
  membership_generation: Generation;
  repositories: Digest32[];
}

export type ProviderDecision =
  | { result: "selected"; profile_id: ProfileId }
  | { result: "cancelled" }
  | { result: "unavailable" };

export interface ProviderSelectionDecision extends ProviderControlRequest {
  selection_generation: Generation;
  decision: ProviderDecision;
}

export type ProviderRequest =
  | { type: "register"; body: ProviderRegistrationRequest }
  | { type: "heartbeat"; body: ProviderControlRequest }
  | { type: "subscribe_status"; body: ProviderControlRequest }
  | { type: "update_repositories"; body: ProviderRepositoryMembership }
  | { type: "selection_decision"; body: ProviderSelectionDecision }
  | { type: "unregister"; body: ProviderControlRequest };

export type ProviderControlMessage = Exclude<
  ProviderRequest,
  { type: "register" } | { type: "selection_decision" }
>;

export interface ResolvedSelection {
  profile_id: ProfileId;
  profile_generation: Generation;
  session_generation: Generation;
}

export interface SelectionStatus {
  repository_identity: Digest32;
  selected_profile: ProfileId | null;
  session_generation: Generation;
}

export type ErrorCode =
  | "GUS_E_AMBIGUOUS_INVOCATION"
  | "GUS_E_PROFILE_REQUIRED"
  | "GUS_E_PROFILE_INVALID"
  | "GUS_E_SELECTION_CANCELLED"
  | "GUS_E_SELECTION_TIMEOUT"
  | "GUS_E_PROVIDER_UNAVAILABLE"
  | "GUS_E_BROKER_UNAVAILABLE"
  | "GUS_E_SHIM_UNVERIFIED"
  | "GUS_E_REAL_GIT_CHANGED"
  | "GUS_E_ARTIFACT_CHANGED"
  | "GUS_E_HTTP_CREDENTIAL_REQUIRED"
  | "GUS_E_CREDENTIAL_DENIED"
  | "GUS_E_HTTP_PREFLIGHT_UNSUPPORTED"
  | "GUS_E_SSH_CONTEXT_MISMATCH"
  | "GUS_E_CAPABILITY_INVALID"
  | "GUS_E_CAPABILITY_EXPIRED"
  | "GUS_E_BROKER_CAPACITY"
  | "GUS_E_PROTOCOL_MISMATCH"
  | "GUS_E_VSCODE_RELOAD_REQUIRED"
  | "GUS_E_NO_REMOTE_CONTEXT"
  | "GUS_E_INSTALL_RESERVATION_STALE"
  | "GUS_E_INSTALL_ROOT_CONFLICT"
  | "GUS_E_RECONCILE_REQUIRED"
  | "GUS_E_ROLLBACK_PENDING"
  | "GUS_E_OWNED_SETTING_CONFLICT"
  | "GUS_E_EXTENSION_BLOCKED"
  | "GUS_E_EXTENSION_UNTRUSTED"
  | "GUS_E_EXTENSION_INSTALL_FAILED"
  | "GUS_E_UPDATE_IN_PROGRESS"
  | "GUS_E_UPDATE_ROLLED_BACK"
  | "GUS_E_INTERNAL";
export type ErrorPhase = "preflight" | "deferred_helper";
export type RetryDisposition =
  | "no"
  | "immediate"
  | "after_correction"
  | "after_selection"
  | "after_repair"
  | "after_reload";
export type RemediationAction =
  | "none"
  | "retry"
  | "correct_invocation"
  | "select_profile"
  | "set_explicit_profile"
  | "run_doctor"
  | "repair"
  | "reload_window"
  | "contact_administrator";
export type ErrorDetail =
  | { type: "none" }
  | { type: "provider"; body: { provider: ProviderKind } }
  | { type: "journal"; body: { journal_id: RequestId } }
  | {
      type: "protocol";
      body: { expected: number; received: number };
    };

export interface BrokerError {
  code: ErrorCode;
  phase: ErrorPhase;
  retry: RetryDisposition;
  diagnostic_id: RequestId;
  real_git_started: boolean;
  action: RemediationAction;
  detail: ErrorDetail;
}

export type BrokerShimMessage =
  | { type: "resolved"; body: ResolvedSelection }
  | { type: "cleared"; body: { session_generation: Generation } }
  | { type: "status"; body: SelectionStatus }
  | { type: "error"; body: BrokerError };

export type SelectionScopePresentation =
  | "terminal"
  | "ide_window"
  | "ide_task";
export interface ScopePresentation {
  kind: SelectionScopePresentation;
  opaque_id: Digest32;
  label: string;
}
export interface RepositoryPresentation {
  identity: Digest32;
  label: string;
}
export interface ProfilePresentation {
  profile_id: ProfileId;
  display_name: string;
  email: string | null;
}
export interface RegistrationAccepted extends ProviderControlRequest {
  heartbeat_interval_millis: number;
}
export interface SelectionPrompt extends ProviderControlRequest {
  selection_generation: Generation;
  scope: ScopePresentation;
  repository: RepositoryPresentation;
  operation: OperationPresentation;
  profiles: ProfilePresentation[];
  timeout_millis: number;
}
export type ProtectionStatus = "verified" | "unverified" | "unavailable";
export interface ProviderStatusEntry {
  scope: ScopePresentation;
  repository: RepositoryPresentation;
  selected_profile: ProfilePresentation | null;
  protection: ProtectionStatus;
}
export interface ProviderStatusSnapshot extends ProviderControlRequest {
  entries: ProviderStatusEntry[];
}
export type BrokerProviderMessage =
  | { type: "registered"; body: RegistrationAccepted }
  | { type: "selection_prompt"; body: SelectionPrompt }
  | { type: "status_snapshot"; body: ProviderStatusSnapshot }
  | { type: "acknowledged" }
  | { type: "error"; body: BrokerError };

export type ShimRequestFrame = WireFrame<"shim_request", ShimRequest>;
export type ShimResponseFrame = WireFrame<"shim_response", BrokerShimMessage>;
export type ProviderRequestFrame = WireFrame<"provider_request", ProviderRequest>;
export type ProviderResponseFrame = WireFrame<
  "provider_response",
  BrokerProviderMessage
>;

declare const decodedProviderResponseBrand: unique symbol;
export type DecodedProviderResponseFrame = ProviderResponseFrame & {
  readonly [decodedProviderResponseBrand]: true;
};

declare const encodableProviderRequestBrand: unique symbol;
export type EncodableProviderRequestFrame = ProviderRequestFrame & {
  readonly [encodableProviderRequestBrand]: true;
};

type JsonObject = Record<string, unknown>;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const requestIdPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const digestPattern = /^[0-9a-f]{64}$/u;
const generationPattern = /^(?:[1-9][0-9]*)$/u;
const profileIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u;
const u64Maximum = 18_446_744_073_709_551_615n;
const decodedProviderResponses = new WeakSet<object>();
const consumedSelectionPrompts = new WeakSet<object>();

const operationValues = new Set<OperationPresentation>([
  "local_read",
  "worktree_mutation",
  "commit",
  "tag",
  "history_rewrite",
  "merge",
  "remote_read",
  "push",
  "unknown_protected",
]);
const providerKinds = new Set<ProviderKind>([
  "vscode",
  "jet_brains",
  "native_prompt",
]);
const providerCapabilities = new Set<ProviderCapability>([
  "profile_quick_pick",
  "status",
  "diagnostics",
  "reload_action",
]);
const scopeKinds = new Set<SelectionScopePresentation>([
  "terminal",
  "ide_window",
  "ide_task",
]);
const protectionStatuses = new Set<ProtectionStatus>([
  "verified",
  "unverified",
  "unavailable",
]);
const errorCodes = new Set<ErrorCode>([
  "GUS_E_AMBIGUOUS_INVOCATION",
  "GUS_E_PROFILE_REQUIRED",
  "GUS_E_PROFILE_INVALID",
  "GUS_E_SELECTION_CANCELLED",
  "GUS_E_SELECTION_TIMEOUT",
  "GUS_E_PROVIDER_UNAVAILABLE",
  "GUS_E_BROKER_UNAVAILABLE",
  "GUS_E_SHIM_UNVERIFIED",
  "GUS_E_REAL_GIT_CHANGED",
  "GUS_E_ARTIFACT_CHANGED",
  "GUS_E_HTTP_CREDENTIAL_REQUIRED",
  "GUS_E_CREDENTIAL_DENIED",
  "GUS_E_HTTP_PREFLIGHT_UNSUPPORTED",
  "GUS_E_SSH_CONTEXT_MISMATCH",
  "GUS_E_CAPABILITY_INVALID",
  "GUS_E_CAPABILITY_EXPIRED",
  "GUS_E_BROKER_CAPACITY",
  "GUS_E_PROTOCOL_MISMATCH",
  "GUS_E_VSCODE_RELOAD_REQUIRED",
  "GUS_E_NO_REMOTE_CONTEXT",
  "GUS_E_INSTALL_RESERVATION_STALE",
  "GUS_E_INSTALL_ROOT_CONFLICT",
  "GUS_E_RECONCILE_REQUIRED",
  "GUS_E_ROLLBACK_PENDING",
  "GUS_E_OWNED_SETTING_CONFLICT",
  "GUS_E_EXTENSION_BLOCKED",
  "GUS_E_EXTENSION_UNTRUSTED",
  "GUS_E_EXTENSION_INSTALL_FAILED",
  "GUS_E_UPDATE_IN_PROGRESS",
  "GUS_E_UPDATE_ROLLED_BACK",
  "GUS_E_INTERNAL",
]);

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(
  value: JsonObject,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const keys = Object.keys(value);
  const allowed = new Set([...required, ...optional]);
  return (
    required.every((key) => Object.hasOwn(value, key)) &&
    keys.every((key) => allowed.has(key))
  );
}

function isRequestId(value: unknown): value is RequestId {
  return typeof value === "string" && requestIdPattern.test(value);
}

function isGeneration(value: unknown): value is Generation {
  if (typeof value !== "string" || !generationPattern.test(value)) return false;
  try {
    return BigInt(value) <= u64Maximum;
  } catch {
    return false;
  }
}

function isDigest(value: unknown): value is Digest32 {
  return typeof value === "string" && digestPattern.test(value);
}

function isProfileId(value: unknown): value is ProfileId {
  return typeof value === "string" && profileIdPattern.test(value);
}

function isUnicodeScalarString(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      if (index + 1 >= value.length) return false;
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return false;
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function isPresentationText(value: unknown, minimumCharacters = 1): value is string {
  if (typeof value !== "string") return false;
  if (
    !isUnicodeScalarString(value) ||
    [...value].length < minimumCharacters ||
    textEncoder.encode(value).length > 256
  ) {
    return false;
  }
  // Unicode 17.0 Default_Ignorable_Code_Point plus every assigned Cf.
  return !/[\u0000-\u001f\u007f-\u009f\u00ad\u034f\u0600-\u0605\u061c\u06dd\u070f\u0890-\u0891\u08e2\u115f-\u1160\u17b4-\u17b5\u180b-\u180f\u200b-\u200f\u2028-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufffb\u{110bd}\u{110cd}\u{13430}-\u{1343f}\u{1bca0}-\u{1bca3}\u{1d173}-\u{1d17a}\u{e0000}-\u{e0fff}]/u.test(value);
}

function isUniqueArray<T>(
  value: unknown,
  maximum: number,
  guard: (entry: unknown) => entry is T,
  key: (entry: T) => string,
): value is T[] {
  if (!Array.isArray(value) || value.length > maximum || !value.every(guard)) return false;
  return new Set(value.map(key)).size === value.length;
}

function isProviderControl(value: unknown): value is ProviderControlRequest {
  return (
    isObject(value) &&
    hasExactKeys(value, ["registration_id", "provider_generation"]) &&
    isRequestId(value.registration_id) &&
    isGeneration(value.provider_generation)
  );
}

function isRepository(value: unknown): value is RepositoryPresentation {
  return (
    isObject(value) &&
    hasExactKeys(value, ["identity", "label"]) &&
    isDigest(value.identity) &&
    isPresentationText(value.label)
  );
}

function isScope(value: unknown): value is ScopePresentation {
  return (
    isObject(value) &&
    hasExactKeys(value, ["kind", "opaque_id", "label"]) &&
    typeof value.kind === "string" &&
    scopeKinds.has(value.kind as SelectionScopePresentation) &&
    isDigest(value.opaque_id) &&
    isPresentationText(value.label)
  );
}

function isProfile(value: unknown): value is ProfilePresentation {
  if (
    !isObject(value) ||
    !hasExactKeys(value, ["profile_id", "display_name", "email"]) ||
    !isProfileId(value.profile_id) ||
    !isPresentationText(value.display_name)
  ) {
    return false;
  }
  if (value.email === null) return true;
  if (!isPresentationText(value.email, 3) || /[<> ]/u.test(value.email)) return false;
  const parts = value.email.split("@");
  return parts.length === 2 && parts[0] !== "" && parts[1] !== "";
}

function isProviderDecision(value: unknown): value is ProviderDecision {
  if (!isObject(value) || typeof value.result !== "string") return false;
  switch (value.result) {
    case "selected":
      return hasExactKeys(value, ["result", "profile_id"]) && isProfileId(value.profile_id);
    case "cancelled":
    case "unavailable":
      return hasExactKeys(value, ["result"]);
    default:
      return false;
  }
}

function isErrorDetail(value: unknown): value is ErrorDetail {
  if (!isObject(value) || typeof value.type !== "string") return false;
  switch (value.type) {
    case "none":
      return hasExactKeys(value, ["type"]);
    case "provider":
      return (
        hasExactKeys(value, ["type", "body"]) &&
        isObject(value.body) &&
        hasExactKeys(value.body, ["provider"]) &&
        typeof value.body.provider === "string" &&
        providerKinds.has(value.body.provider as ProviderKind)
      );
    case "journal":
      return (
        hasExactKeys(value, ["type", "body"]) &&
        isObject(value.body) &&
        hasExactKeys(value.body, ["journal_id"]) &&
        isRequestId(value.body.journal_id)
      );
    case "protocol":
      return (
        hasExactKeys(value, ["type", "body"]) &&
        isObject(value.body) &&
        hasExactKeys(value.body, ["expected", "received"]) &&
        Number.isInteger(value.body.expected) &&
        Number.isInteger(value.body.received) &&
        Number(value.body.expected) >= 0 &&
        Number(value.body.expected) <= 65_535 &&
        Number(value.body.received) >= 0 &&
        Number(value.body.received) <= 65_535
      );
    default:
      return false;
  }
}

interface ErrorContract {
  readonly phases: readonly ErrorPhase[];
  readonly retry: RetryDisposition;
  readonly action: RemediationAction;
  readonly detail: ErrorDetail["type"];
}

const bothPhases: readonly ErrorPhase[] = ["preflight", "deferred_helper"];
const preflightOnly: readonly ErrorPhase[] = ["preflight"];
const deferredOnly: readonly ErrorPhase[] = ["deferred_helper"];
const errorContracts: Readonly<Record<ErrorCode, ErrorContract>> = {
  GUS_E_AMBIGUOUS_INVOCATION: {
    phases: preflightOnly,
    retry: "after_correction",
    action: "correct_invocation",
    detail: "none",
  },
  GUS_E_PROFILE_REQUIRED: {
    phases: preflightOnly,
    retry: "after_selection",
    action: "select_profile",
    detail: "none",
  },
  GUS_E_PROFILE_INVALID: {
    phases: bothPhases,
    retry: "after_repair",
    action: "run_doctor",
    detail: "none",
  },
  GUS_E_SELECTION_CANCELLED: {
    phases: bothPhases,
    retry: "immediate",
    action: "retry",
    detail: "none",
  },
  GUS_E_SELECTION_TIMEOUT: {
    phases: bothPhases,
    retry: "immediate",
    action: "retry",
    detail: "none",
  },
  GUS_E_PROVIDER_UNAVAILABLE: {
    phases: bothPhases,
    retry: "after_repair",
    action: "run_doctor",
    detail: "none",
  },
  GUS_E_BROKER_UNAVAILABLE: {
    phases: bothPhases,
    retry: "immediate",
    action: "retry",
    detail: "none",
  },
  GUS_E_SHIM_UNVERIFIED: {
    phases: preflightOnly,
    retry: "after_repair",
    action: "repair",
    detail: "none",
  },
  GUS_E_REAL_GIT_CHANGED: {
    phases: preflightOnly,
    retry: "after_repair",
    action: "repair",
    detail: "none",
  },
  GUS_E_ARTIFACT_CHANGED: {
    phases: preflightOnly,
    retry: "after_repair",
    action: "run_doctor",
    detail: "none",
  },
  GUS_E_HTTP_CREDENTIAL_REQUIRED: {
    phases: deferredOnly,
    retry: "after_selection",
    action: "select_profile",
    detail: "none",
  },
  GUS_E_CREDENTIAL_DENIED: {
    phases: deferredOnly,
    retry: "after_repair",
    action: "run_doctor",
    detail: "none",
  },
  GUS_E_HTTP_PREFLIGHT_UNSUPPORTED: {
    phases: preflightOnly,
    retry: "after_repair",
    action: "run_doctor",
    detail: "none",
  },
  GUS_E_SSH_CONTEXT_MISMATCH: {
    phases: deferredOnly,
    retry: "after_repair",
    action: "run_doctor",
    detail: "none",
  },
  GUS_E_CAPABILITY_INVALID: {
    phases: bothPhases,
    retry: "no",
    action: "run_doctor",
    detail: "none",
  },
  GUS_E_CAPABILITY_EXPIRED: {
    phases: bothPhases,
    retry: "immediate",
    action: "retry",
    detail: "none",
  },
  GUS_E_BROKER_CAPACITY: {
    phases: preflightOnly,
    retry: "immediate",
    action: "retry",
    detail: "none",
  },
  GUS_E_PROTOCOL_MISMATCH: {
    phases: preflightOnly,
    retry: "after_repair",
    action: "repair",
    detail: "protocol",
  },
  GUS_E_VSCODE_RELOAD_REQUIRED: {
    phases: preflightOnly,
    retry: "after_reload",
    action: "reload_window",
    detail: "provider",
  },
  GUS_E_NO_REMOTE_CONTEXT: {
    phases: preflightOnly,
    retry: "after_repair",
    action: "run_doctor",
    detail: "provider",
  },
  GUS_E_INSTALL_RESERVATION_STALE: {
    phases: preflightOnly,
    retry: "after_repair",
    action: "run_doctor",
    detail: "journal",
  },
  GUS_E_INSTALL_ROOT_CONFLICT: {
    phases: preflightOnly,
    retry: "after_repair",
    action: "run_doctor",
    detail: "none",
  },
  GUS_E_RECONCILE_REQUIRED: {
    phases: preflightOnly,
    retry: "immediate",
    action: "retry",
    detail: "none",
  },
  GUS_E_ROLLBACK_PENDING: {
    phases: preflightOnly,
    retry: "after_repair",
    action: "repair",
    detail: "journal",
  },
  GUS_E_OWNED_SETTING_CONFLICT: {
    phases: preflightOnly,
    retry: "after_repair",
    action: "run_doctor",
    detail: "none",
  },
  GUS_E_EXTENSION_BLOCKED: {
    phases: preflightOnly,
    retry: "after_repair",
    action: "contact_administrator",
    detail: "provider",
  },
  GUS_E_EXTENSION_UNTRUSTED: {
    phases: preflightOnly,
    retry: "after_repair",
    action: "repair",
    detail: "provider",
  },
  GUS_E_EXTENSION_INSTALL_FAILED: {
    phases: preflightOnly,
    retry: "after_repair",
    action: "run_doctor",
    detail: "provider",
  },
  GUS_E_UPDATE_IN_PROGRESS: {
    phases: preflightOnly,
    retry: "immediate",
    action: "retry",
    detail: "none",
  },
  GUS_E_UPDATE_ROLLED_BACK: {
    phases: preflightOnly,
    retry: "after_repair",
    action: "run_doctor",
    detail: "journal",
  },
  GUS_E_INTERNAL: {
    phases: preflightOnly,
    retry: "no",
    action: "run_doctor",
    detail: "none",
  },
};

function isBrokerError(value: unknown): value is BrokerError {
  if (
    !isObject(value) ||
    !hasExactKeys(value, [
      "code",
      "phase",
      "retry",
      "diagnostic_id",
      "real_git_started",
      "action",
      "detail",
    ]) ||
    typeof value.code !== "string" ||
    !errorCodes.has(value.code as ErrorCode) ||
    (value.phase !== "preflight" && value.phase !== "deferred_helper") ||
    !isRequestId(value.diagnostic_id) ||
    typeof value.real_git_started !== "boolean" ||
    !isErrorDetail(value.detail)
  ) {
    return false;
  }
  const contract = errorContracts[value.code as ErrorCode];
  const contractMatches =
    contract.phases.includes(value.phase) &&
    value.retry === contract.retry &&
    value.action === contract.action &&
    value.real_git_started === (value.phase === "deferred_helper") &&
    value.detail.type === contract.detail;
  if (!contractMatches) return false;
  if (value.code === "GUS_E_PROTOCOL_MISMATCH") {
    return (
      value.detail.type === "protocol" &&
      value.detail.body.expected === PROTOCOL_VERSION &&
      value.detail.body.received !== value.detail.body.expected
    );
  }
  if (
    value.code === "GUS_E_VSCODE_RELOAD_REQUIRED" ||
    value.code === "GUS_E_NO_REMOTE_CONTEXT"
  ) {
    return value.detail.type === "provider" && value.detail.body.provider === "vscode";
  }
  return true;
}

export function decodeBrokerError(value: unknown): BrokerError {
  if (!isBrokerError(value)) throw new Error("invalid GUS broker error contract");
  return value;
}

function isResolveSelection(value: unknown): value is ResolveSelectionRequest {
  return (
    isObject(value) &&
    hasExactKeys(value, [
      "plan_digest",
      "repository_identity",
      "operation",
      "explicit_profile",
    ]) &&
    isDigest(value.plan_digest) &&
    isDigest(value.repository_identity) &&
    typeof value.operation === "string" &&
    operationValues.has(value.operation as OperationPresentation) &&
    (value.explicit_profile === null || isProfileId(value.explicit_profile))
  );
}

function isShimRequest(value: unknown): value is ShimRequest {
  if (!isObject(value) || typeof value.type !== "string") return false;
  switch (value.type) {
    case "resolve_selection":
      return hasExactKeys(value, ["type", "body"]) && isResolveSelection(value.body);
    case "clear_selection":
      return (
        hasExactKeys(value, ["type", "body"]) &&
        isObject(value.body) &&
        hasExactKeys(value.body, ["repository_identity", "expected_session_generation"]) &&
        isDigest(value.body.repository_identity) &&
        (value.body.expected_session_generation === null ||
          isGeneration(value.body.expected_session_generation))
      );
    case "status":
      return (
        hasExactKeys(value, ["type", "body"]) &&
        isObject(value.body) &&
        hasExactKeys(value.body, ["repository_identity"]) &&
        isDigest(value.body.repository_identity)
      );
    default:
      return false;
  }
}

function isProviderRegistration(value: unknown): value is ProviderRegistrationRequest {
  if (
    !isObject(value) ||
    !hasExactKeys(value, [
      "kind",
      "editor_session_id",
      "host_instance",
      "repositories",
      "capabilities",
    ]) ||
    typeof value.kind !== "string" ||
    !providerKinds.has(value.kind as ProviderKind) ||
    !isPresentationText(value.editor_session_id) ||
    !isDigest(value.host_instance) ||
    !isUniqueArray(value.repositories, 128, isDigest, String) ||
    !isUniqueArray(
      value.capabilities,
      16,
      (entry): entry is ProviderCapability =>
        typeof entry === "string" && providerCapabilities.has(entry as ProviderCapability),
      String,
    )
  ) {
    return false;
  }
  return value.capabilities.includes("profile_quick_pick");
}

function isProviderRequest(value: unknown): value is ProviderRequest {
  if (!isObject(value) || typeof value.type !== "string") return false;
  if (!hasExactKeys(value, ["type", "body"])) return false;
  switch (value.type) {
    case "register":
      return isProviderRegistration(value.body);
    case "heartbeat":
    case "subscribe_status":
    case "unregister":
      return isProviderControl(value.body);
    case "update_repositories":
      return (
        isObject(value.body) &&
        hasExactKeys(value.body, [
          "registration_id",
          "provider_generation",
          "membership_generation",
          "repositories",
        ]) &&
        isRequestId(value.body.registration_id) &&
        isGeneration(value.body.provider_generation) &&
        isGeneration(value.body.membership_generation) &&
        isUniqueArray(value.body.repositories, 128, isDigest, String)
      );
    case "selection_decision":
      return (
        isObject(value.body) &&
        hasExactKeys(value.body, [
          "registration_id",
          "provider_generation",
          "selection_generation",
          "decision",
        ]) &&
        isRequestId(value.body.registration_id) &&
        isGeneration(value.body.provider_generation) &&
        isGeneration(value.body.selection_generation) &&
        isProviderDecision(value.body.decision)
      );
    default:
      return false;
  }
}

function isShimResponse(value: unknown): value is BrokerShimMessage {
  if (!isObject(value) || typeof value.type !== "string") return false;
  if (!hasExactKeys(value, ["type", "body"])) return false;
  if (!isObject(value.body)) return false;
  switch (value.type) {
    case "resolved":
      return (
        hasExactKeys(value.body, ["profile_id", "profile_generation", "session_generation"]) &&
        isProfileId(value.body.profile_id) &&
        isGeneration(value.body.profile_generation) &&
        isGeneration(value.body.session_generation)
      );
    case "cleared":
      return hasExactKeys(value.body, ["session_generation"]) && isGeneration(value.body.session_generation);
    case "status":
      return (
        hasExactKeys(value.body, [
          "repository_identity",
          "selected_profile",
          "session_generation",
        ]) &&
        isDigest(value.body.repository_identity) &&
        (value.body.selected_profile === null || isProfileId(value.body.selected_profile)) &&
        isGeneration(value.body.session_generation)
      );
    case "error":
      return isBrokerError(value.body);
    default:
      return false;
  }
}

function isStatusEntry(value: unknown): value is ProviderStatusEntry {
  return (
    isObject(value) &&
    hasExactKeys(value, ["scope", "repository", "selected_profile", "protection"]) &&
    isScope(value.scope) &&
    isRepository(value.repository) &&
    (value.selected_profile === null || isProfile(value.selected_profile)) &&
    typeof value.protection === "string" &&
    protectionStatuses.has(value.protection as ProtectionStatus)
  );
}

function isProviderResponse(value: unknown): value is BrokerProviderMessage {
  if (!isObject(value) || typeof value.type !== "string") return false;
  if (value.type === "acknowledged") return hasExactKeys(value, ["type"]);
  if (!hasExactKeys(value, ["type", "body"]) || !isObject(value.body)) return false;
  switch (value.type) {
    case "registered":
      return (
        hasExactKeys(value.body, [
          "registration_id",
          "provider_generation",
          "heartbeat_interval_millis",
        ]) &&
        isRequestId(value.body.registration_id) &&
        isGeneration(value.body.provider_generation) &&
        Number.isInteger(value.body.heartbeat_interval_millis) &&
        Number(value.body.heartbeat_interval_millis) >= 1_000 &&
        Number(value.body.heartbeat_interval_millis) <= 120_000
      );
    case "selection_prompt": {
      if (
        !hasExactKeys(value.body, [
          "registration_id",
          "provider_generation",
          "selection_generation",
          "scope",
          "repository",
          "operation",
          "profiles",
          "timeout_millis",
        ]) ||
        !isRequestId(value.body.registration_id) ||
        !isGeneration(value.body.provider_generation) ||
        !isGeneration(value.body.selection_generation) ||
        !isScope(value.body.scope) ||
        !isRepository(value.body.repository) ||
        typeof value.body.operation !== "string" ||
        !operationValues.has(value.body.operation as OperationPresentation) ||
        !isUniqueArray(value.body.profiles, 32, isProfile, (entry) => entry.profile_id) ||
        value.body.profiles.length === 0 ||
        !Number.isInteger(value.body.timeout_millis)
      ) {
        return false;
      }
      return (
        Number(value.body.timeout_millis) >= 1_000 &&
        Number(value.body.timeout_millis) <= 300_000
      );
    }
    case "status_snapshot": {
      if (
        !hasExactKeys(value.body, ["registration_id", "provider_generation", "entries"]) ||
        !isRequestId(value.body.registration_id) ||
        !isGeneration(value.body.provider_generation) ||
        !Array.isArray(value.body.entries) ||
        value.body.entries.length > 16 ||
        !value.body.entries.every(isStatusEntry)
      ) {
        return false;
      }
      const keys = value.body.entries.map(
        (entry) => `${entry.scope.opaque_id}:${entry.repository.identity}`,
      );
      return new Set(keys).size === keys.length;
    }
    case "error":
      return isBrokerError(value.body);
    default:
      return false;
  }
}

function parseStrictJson(text: string): unknown {
  let index = 0;

  function skipWhitespace(): void {
    while (index < text.length && /[\u0009\u000a\u000d\u0020]/u.test(text[index] ?? "")) {
      index += 1;
    }
  }

  function parseString(): string {
    if (text[index] !== '"') throw new Error("expected JSON string");
    const start = index;
    index += 1;
    while (index < text.length) {
      const character = text[index];
      if (character === '"') {
        index += 1;
        const parsed: unknown = JSON.parse(text.slice(start, index));
        if (typeof parsed !== "string" || !isUnicodeScalarString(parsed)) {
          throw new Error("invalid JSON string");
        }
        return parsed;
      }
      if (character === "\\") {
        index += 2;
      } else {
        index += 1;
      }
    }
    throw new Error("unterminated JSON string");
  }

  function parseValue(depth: number): unknown {
    if (depth > 64) throw new Error("JSON nesting exceeds GUS protocol limit");
    skipWhitespace();
    const character = text[index];
    if (character === '"') return parseString();
    if (character === "{") {
      index += 1;
      skipWhitespace();
      const object: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
      const keys = new Set<string>();
      if (text[index] === "}") {
        index += 1;
        return object;
      }
      while (true) {
        skipWhitespace();
        const key = parseString();
        if (keys.has(key)) throw new Error("duplicate JSON key");
        keys.add(key);
        skipWhitespace();
        if (text[index] !== ":") throw new Error("expected JSON colon");
        index += 1;
        object[key] = parseValue(depth + 1);
        skipWhitespace();
        if (text[index] === "}") {
          index += 1;
          return object;
        }
        if (text[index] !== ",") throw new Error("expected JSON object separator");
        index += 1;
      }
    }
    if (character === "[") {
      index += 1;
      skipWhitespace();
      const array: unknown[] = [];
      if (text[index] === "]") {
        index += 1;
        return array;
      }
      while (true) {
        array.push(parseValue(depth + 1));
        skipWhitespace();
        if (text[index] === "]") {
          index += 1;
          return array;
        }
        if (text[index] !== ",") throw new Error("expected JSON array separator");
        index += 1;
      }
    }
    for (const [literal, value] of [
      ["true", true],
      ["false", false],
      ["null", null],
    ] as const) {
      if (text.startsWith(literal, index)) {
        index += literal.length;
        return value;
      }
    }
    const number = /^(?:0|[1-9][0-9]*)/u.exec(text.slice(index))?.[0];
    if (number !== undefined) {
      index += number.length;
      const parsed: unknown = JSON.parse(number);
      if (typeof parsed !== "number" || !Number.isFinite(parsed)) {
        throw new Error("invalid JSON number");
      }
      return parsed;
    }
    throw new Error("invalid JSON value");
  }

  const value = parseValue(0);
  skipWhitespace();
  if (index !== text.length) throw new Error("trailing JSON content");
  return value;
}

function decodeRecord<F extends MessageFamily, M>(
  record: Uint8Array,
  expectedFamily: F,
  messageGuard: (value: unknown) => value is M,
): WireFrame<F, M> {
  if (record.byteLength < FRAME_HEADER_BYTES) throw new Error("GUS IPC record is incomplete");
  const view = new DataView(record.buffer, record.byteOffset, record.byteLength);
  const payloadLength = view.getUint32(0, false);
  if (payloadLength === 0 || payloadLength > MAX_FRAME_BYTES) {
    throw new Error("GUS IPC payload length is invalid");
  }
  if (record.byteLength !== FRAME_HEADER_BYTES + payloadLength) {
    throw new Error("GUS IPC record length mismatch");
  }
  const parsed = parseStrictJson(textDecoder.decode(record.subarray(FRAME_HEADER_BYTES)));
  if (
    !isObject(parsed) ||
    !Object.hasOwn(parsed, "protocol_version") ||
    !Number.isInteger(parsed.protocol_version) ||
    Number(parsed.protocol_version) < 0 ||
    Number(parsed.protocol_version) > 65_535
  ) {
    throw new Error("invalid GUS IPC protocol version");
  }
  if (parsed.protocol_version !== PROTOCOL_VERSION) {
    throw new Error(`unsupported GUS IPC protocol version ${String(parsed.protocol_version)}`);
  }
  if (
    !hasExactKeys(parsed, ["protocol_version", "message_family", "request_id", "message"]) ||
    parsed.message_family !== expectedFamily ||
    !isRequestId(parsed.request_id) ||
    !messageGuard(parsed.message)
  ) {
    throw new Error(`invalid ${expectedFamily} GUS IPC frame`);
  }
  return parsed as unknown as WireFrame<F, M>;
}

export function decodeShimRequest(record: Uint8Array): ShimRequestFrame {
  return decodeRecord(record, "shim_request", isShimRequest);
}

export function decodeShimResponse(record: Uint8Array): ShimResponseFrame {
  return decodeRecord(record, "shim_response", isShimResponse);
}

export function decodeProviderRequest(record: Uint8Array): ProviderRequestFrame {
  return decodeRecord(record, "provider_request", isProviderRequest);
}

export function decodeProviderResponse(record: Uint8Array): DecodedProviderResponseFrame {
  const decoded = deepFreezeJson(
    decodeRecord(record, "provider_response", isProviderResponse),
  ) as DecodedProviderResponseFrame;
  decodedProviderResponses.add(decoded);
  return decoded;
}

function cloneCanonicalJson(value: unknown, depth = 0): unknown {
  if (depth > 64) throw new Error("cannot encode deeply nested GUS IPC data");
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length > 128) throw new Error("cannot encode oversized GUS IPC array");
    const copy: unknown[] = [];
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.hasOwn(value, index)) {
        throw new Error("cannot encode sparse GUS IPC array");
      }
      copy.push(cloneCanonicalJson(value[index], depth + 1));
    }
    const expectedKeys = new Set(Array.from({ length: value.length }, (_, index) => String(index)));
    if (Object.keys(value).some((key) => !expectedKeys.has(key))) {
      throw new Error("cannot encode array properties in GUS IPC data");
    }
    return copy;
  }
  if (!isObject(value) || Object.getOwnPropertySymbols(value).length !== 0) {
    throw new Error("cannot encode non-JSON GUS IPC data");
  }

  const copy: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (descriptor.get !== undefined || descriptor.set !== undefined) {
      throw new Error("cannot encode accessor-backed GUS IPC data");
    }
    if (descriptor.enumerable) {
      copy[key] = cloneCanonicalJson(descriptor.value, depth + 1);
    }
  }
  return copy;
}

function deepFreezeJson<T>(value: T): T {
  if (typeof value === "object" && value !== null) {
    for (const entry of Object.values(value)) deepFreezeJson(entry);
    Object.freeze(value);
  }
  return value;
}

const authorizedProviderRequests = new WeakSet<object>();

function authorizeProviderRequest(frame: ProviderRequestFrame): EncodableProviderRequestFrame {
  const canonical = cloneCanonicalJson(frame);
  if (!isObject(canonical)) throw new Error("cannot authorize invalid provider request");
  encodeFrame(canonical as unknown as ProviderRequestFrame);
  const authorized = deepFreezeJson(canonical) as unknown as EncodableProviderRequestFrame;
  authorizedProviderRequests.add(authorized);
  return authorized;
}

function encodeFrame(
  frame:
    | ShimRequestFrame
    | ShimResponseFrame
    | ProviderRequestFrame
    | ProviderResponseFrame,
): Uint8Array {
  const candidate = cloneCanonicalJson(frame);
  if (
    !isObject(candidate) ||
    !hasExactKeys(candidate, ["protocol_version", "message_family", "request_id", "message"])
  ) {
    throw new Error("cannot encode invalid GUS IPC frame");
  }
  const family = candidate.message_family;
  const messageValid =
    (family === "shim_request" && isShimRequest(candidate.message)) ||
    (family === "shim_response" && isShimResponse(candidate.message)) ||
    (family === "provider_request" && isProviderRequest(candidate.message)) ||
    (family === "provider_response" && isProviderResponse(candidate.message));
  if (
    candidate.protocol_version !== PROTOCOL_VERSION ||
    !isRequestId(candidate.request_id) ||
    !messageValid
  ) {
    throw new Error("cannot encode invalid GUS IPC frame");
  }
  const canonical = {
    protocol_version: PROTOCOL_VERSION,
    message_family: family,
    request_id: candidate.request_id,
    message: candidate.message,
  };
  const payload = textEncoder.encode(JSON.stringify(canonical));
  if (payload.byteLength === 0 || payload.byteLength > MAX_FRAME_BYTES) {
    throw new Error("GUS IPC payload is oversized");
  }
  const record = new Uint8Array(FRAME_HEADER_BYTES + payload.byteLength);
  new DataView(record.buffer).setUint32(0, payload.byteLength, false);
  record.set(payload, FRAME_HEADER_BYTES);
  return record;
}

function newRequestId(): RequestId {
  return randomUUID();
}

export function encodeProviderRequest(frame: EncodableProviderRequestFrame): Uint8Array {
  if (!authorizedProviderRequests.delete(frame)) {
    throw new Error("provider request was not created by a GUS role factory");
  }
  return encodeFrame(frame);
}

export function createProviderRegistrationFrame(
  registration: ProviderRegistrationRequest,
): EncodableProviderRequestFrame {
  if (!isProviderRegistration(registration)) {
    throw new Error("cannot create invalid provider registration");
  }
  return authorizeProviderRequest({
    protocol_version: PROTOCOL_VERSION,
    message_family: "provider_request",
    request_id: newRequestId(),
    message: { type: "register", body: registration },
  });
}

export function createProviderControlFrame(
  message: ProviderControlMessage,
): EncodableProviderRequestFrame {
  const candidate: unknown = message;
  if (
    !isProviderRequest(candidate) ||
    candidate.type === "register" ||
    candidate.type === "selection_decision"
  ) {
    throw new Error("cannot create invalid provider control command");
  }
  return authorizeProviderRequest({
    protocol_version: PROTOCOL_VERSION,
    message_family: "provider_request",
    request_id: newRequestId(),
    message,
  });
}

export function createProviderSelectionResponseFrame(
  promptFrame: DecodedProviderResponseFrame,
  decision: ProviderDecision,
): EncodableProviderRequestFrame {
  if (
    !decodedProviderResponses.has(promptFrame) ||
    consumedSelectionPrompts.has(promptFrame) ||
    promptFrame.protocol_version !== PROTOCOL_VERSION ||
    promptFrame.message_family !== "provider_response" ||
    !isRequestId(promptFrame.request_id) ||
    !isProviderResponse(promptFrame.message) ||
    promptFrame.message.type !== "selection_prompt" ||
    !isProviderDecision(decision)
  ) {
    throw new Error("selection response requires an unconsumed decoded broker prompt");
  }
  const prompt = promptFrame.message.body;
  const response = authorizeProviderRequest({
    protocol_version: PROTOCOL_VERSION,
    message_family: "provider_request",
    request_id: promptFrame.request_id,
    message: {
      type: "selection_decision",
      body: {
        registration_id: prompt.registration_id,
        provider_generation: prompt.provider_generation,
        selection_generation: prompt.selection_generation,
        decision,
      },
    },
  });
  consumedSelectionPrompts.add(promptFrame);
  return response;
}
