/**
 * Backboard.io exec classifier.
 * Uses Backboard's assistant/thread/message API with gemini-2.0-flash-lite-001
 * to classify whether a shell command should be allowed or denied before
 * falling through to the allowlist-miss hard-deny.
 *
 * Creates a classifier assistant on first use and caches the ID in memory.
 */

const BACKBOARD_BASE_URL = process.env.BACKBOARD_BASE_URL || "";
const CLASSIFIER_MODEL = "gemini-2.0-flash-lite-001";
const CLASSIFIER_ASSISTANT_NAME = "openclaw-exec-classifier";

const CLASSIFIER_SYSTEM_PROMPT = `You are a security classifier for a personal AI assistant's shell execution policy.

You will be given:
- The shell command the AI wants to run
- The working directory
- (Optionally) the user's original message that triggered this action
- (Optionally) the AI's reasoning for why it wants to run this command
- (Optionally) recent conversation history

Your job is to decide whether the command is safe to run **in the context of what the user asked for**.
A command that looks destructive in isolation may be completely appropriate given the user's intent.
A command that looks harmless may be inappropriate if it doesn't match what the user asked.

Respond with exactly this format:
DECISION: ALLOW|DENY
REASON: <one sentence>

Hard denials regardless of context:
- privilege escalation (sudo, su, doas)
- shell obfuscation (base64 decode + exec, eval with dynamic content)
- network exfiltration to unknown external hosts (curl/wget POST to non-localhost/non-project hosts)
- modifying system files outside the project directory (e.g. /etc, /usr, /bin)

Everything else: use judgment. Consider what the user asked for and why the AI is running this command.`;

function getBackboardApiKey(): string {
  return process.env.BACKBOARD_API_KEY ?? "";
}

function jsonHeaders(apiKey: string): Record<string, string> {
  return { "X-API-Key": apiKey, "Content-Type": "application/json" };
}

// Cached assistant ID — created once per process lifetime.
let _assistantId: string | null = null;

async function getOrCreateAssistant(apiKey: string): Promise<string> {
  if (_assistantId) return _assistantId;

  // Check if it already exists.
  const listRes = await fetch(`${BACKBOARD_BASE_URL}/assistants`, {
    headers: jsonHeaders(apiKey),
  });
  if (listRes.ok) {
    const assistants = (await listRes.json()) as Array<{ assistant_id: string; name: string }>;
    const existing = assistants.find((a) => a.name === CLASSIFIER_ASSISTANT_NAME);
    if (existing) {
      _assistantId = existing.assistant_id;
      return _assistantId;
    }
  }

  // Create it.
  const createRes = await fetch(`${BACKBOARD_BASE_URL}/assistants`, {
    method: "POST",
    headers: jsonHeaders(apiKey),
    body: JSON.stringify({
      name: CLASSIFIER_ASSISTANT_NAME,
      system_prompt: CLASSIFIER_SYSTEM_PROMPT,
      model: CLASSIFIER_MODEL,
    }),
  });
  if (!createRes.ok) {
    const text = await createRes.text();
    throw new Error(`Failed to create classifier assistant: ${createRes.status} ${text}`);
  }
  const created = (await createRes.json()) as { assistant_id: string };
  _assistantId = created.assistant_id;
  return _assistantId;
}

export type ClassifierDecision = "allow" | "deny";

export type ClassifierContext = {
  /** The original message the user sent that led to this command being attempted. */
  userMessage?: string | null;
  /** The AI's stated reasoning for why it wants to run this command. */
  aiReasoning?: string | null;
  /** Recent conversation turns for additional context. Each entry is {role, content}. */
  conversationHistory?: Array<{ role: string; content: string }> | null;
};

/**
 * Ask Backboard (gemini-2.0-flash-lite) whether this command should be allowed.
 * Accepts optional context (user message, AI reasoning, conversation history) so the
 * classifier can make an intent-aware decision rather than purely rule-matching.
 * Returns "deny" on any error so the system stays safe.
 */
export async function classifyExecCommand(
  command: string,
  workdir: string,
  context?: ClassifierContext,
): Promise<{ decision: ClassifierDecision; reason: string }> {
  const apiKey = getBackboardApiKey();
  if (!apiKey) {
    return { decision: "deny", reason: "Backboard API key not configured" };
  }

  try {
    const assistantId = await getOrCreateAssistant(apiKey);

    // Create a fresh thread for each classification.
    const threadRes = await fetch(`${BACKBOARD_BASE_URL}/assistants/${assistantId}/threads`, {
      method: "POST",
      headers: jsonHeaders(apiKey),
      body: JSON.stringify({}),
    });
    if (!threadRes.ok) {
      const text = await threadRes.text();
      return { decision: "deny", reason: `Backboard thread error ${threadRes.status}: ${text}` };
    }
    const { thread_id } = (await threadRes.json()) as { thread_id: string };

    // Build the classification prompt with full context when available.
    const parts: string[] = [];
    parts.push(`Command: ${command}`);
    parts.push(`Working directory: ${workdir}`);

    if (context?.userMessage) {
      parts.push(`\nUser's request: ${context.userMessage}`);
    }
    if (context?.aiReasoning) {
      parts.push(`AI's reasoning for running this command: ${context.aiReasoning}`);
    }
    if (context?.conversationHistory && context.conversationHistory.length > 0) {
      const historyText = context.conversationHistory
        .slice(-6) // last 6 turns is enough context
        .map((m) => `${m.role}: ${m.content}`)
        .join("\n");
      parts.push(`\nRecent conversation:\n${historyText}`);
    }

    const messageContent = parts.join("\n");

    // Send the command and get the LLM response (send_to_llm=true).
    const body = new URLSearchParams({
      content: messageContent,
      stream: "false",
      memory: "None",
      send_to_llm: "true",
    });
    const msgRes = await fetch(`${BACKBOARD_BASE_URL}/threads/${thread_id}/messages`, {
      method: "POST",
      headers: { "X-API-Key": apiKey, "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    if (!msgRes.ok) {
      const text = await msgRes.text();
      return { decision: "deny", reason: `Backboard message error ${msgRes.status}: ${text}` };
    }

    const data = (await msgRes.json()) as { content?: string };
    const content = (data.content ?? "").trim();

    // Parse "DECISION: ALLOW" or "DECISION: DENY"
    const decisionMatch = content.match(/DECISION:\s*(ALLOW|DENY)/i);
    const reasonMatch = content.match(/REASON:\s*(.+)/i);
    const decision: ClassifierDecision =
      decisionMatch?.[1]?.toUpperCase() === "ALLOW" ? "allow" : "deny";
    const reason = reasonMatch?.[1]?.trim() ?? content;

    return { decision, reason };
  } catch (err) {
    return { decision: "deny", reason: `Backboard classifier error: ${String(err)}` };
  }
}
