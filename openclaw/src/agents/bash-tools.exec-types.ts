import type { ExecAsk, ExecHost, ExecSecurity } from "../infra/exec-approvals.js";
import type { ClassifierContext } from "../infra/backboard-exec-classifier.js";
import type { SafeBinProfileFixture } from "../infra/exec-safe-bin-policy.js";
import type { BashSandboxConfig } from "./bash-tools.shared.js";

export type ExecToolDefaults = {
  host?: ExecHost;
  security?: ExecSecurity;
  ask?: ExecAsk;
  node?: string;
  pathPrepend?: string[];
  safeBins?: string[];
  safeBinTrustedDirs?: string[];
  safeBinProfiles?: Record<string, SafeBinProfileFixture>;
  agentId?: string;
  backgroundMs?: number;
  timeoutSec?: number;
  approvalRunningNoticeMs?: number;
  sandbox?: BashSandboxConfig;
  elevated?: ExecElevatedDefaults;
  allowBackground?: boolean;
  scopeKey?: string;
  sessionKey?: string;
  messageProvider?: string;
  currentChannelId?: string;
  currentThreadTs?: string;
  accountId?: string;
  notifyOnExit?: boolean;
  notifyOnExitEmptySuccess?: boolean;
  cwd?: string;
  /**
   * Optional callback invoked at exec time to supply conversation context for the
   * Backboard exec classifier. Returns the current user message, AI reasoning, and
   * recent history so the classifier can make intent-aware decisions.
   */
  getClassifierContext?: () => ClassifierContext | undefined;
};

export type ExecElevatedDefaults = {
  enabled: boolean;
  allowed: boolean;
  defaultLevel: "on" | "off" | "ask" | "full";
};

export type ExecToolDetails =
  | {
      status: "running";
      sessionId: string;
      pid?: number;
      startedAt: number;
      cwd?: string;
      tail?: string;
    }
  | {
      status: "completed" | "failed";
      exitCode: number | null;
      durationMs: number;
      aggregated: string;
      cwd?: string;
    }
  | {
      status: "approval-pending";
      approvalId: string;
      approvalSlug: string;
      expiresAtMs: number;
      host: ExecHost;
      command: string;
      cwd?: string;
      nodeId?: string;
    };
