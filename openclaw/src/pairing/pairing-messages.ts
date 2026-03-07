import type { PairingChannel } from "./pairing-store.js";

export function buildPairingReply(params: {
  channel: PairingChannel;
  idLine: string;
  code: string;
}): string {
  // Note: idLine and code are kept for the admin notification path,
  // but the user-facing message must not mention CLI commands or terminals.
  return [
    "Hey! You don't have access yet.",
    "",
    "I've sent a request to the bot owner to approve you. Hang tight — they'll get a notification and can let you in.",
  ].join("\n");
}
