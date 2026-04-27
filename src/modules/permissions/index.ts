/**
 * Permissions module — sender resolution + access gate.
 *
 * Registers two hooks into the core router:
 *   1. setSenderResolver — runs before agent resolution. Parses the payload,
 *      derives a namespaced user id, and upserts the `users` row on first
 *      sight. Returns null when the payload doesn't carry enough to identify
 *      a sender.
 *   2. setAccessGate — runs after agent resolution. Enforces the
 *      unknown_sender_policy (strict/request_approval/public) and the
 *      owner/global-admin/scoped-admin/member access hierarchy. Records its
 *      own `dropped_messages` row on refusal (structural drops are recorded
 *      by core).
 *
 * Without this module: sender resolution is a no-op (userId=null); the
 * access gate is not registered and core defaults to allow-all.
 */
import { getAllAgentGroups } from '../../db/agent-groups.js';
import { recordDroppedMessage } from '../../db/dropped-messages.js';
import { createMessagingGroupAgent, setMessagingGroupDeniedAt } from '../../db/messaging-groups.js';
import { getDeliveryAdapter } from '../../delivery.js';
import {
  routeInbound,
  setAccessGate,
  setChannelRequestGate,
  setSenderResolver,
  setSenderScopeGate,
  type AccessGateResult,
} from '../../router.js';
import type { InboundEvent } from '../../channels/adapter.js';
import { registerResponseHandler, type ResponsePayload } from '../../response-registry.js';
import { log } from '../../log.js';
import type { AgentGroup, MessagingGroup, MessagingGroupAgent } from '../../types.js';
import { canAccessAgentGroup } from './access.js';
import { requestChannelApproval } from './channel-approval.js';
import { addMember } from './db/agent-group-members.js';
import { deletePendingChannelApproval, getPendingChannelApproval } from './db/pending-channel-approvals.js';
import { deletePendingSenderApproval, getPendingSenderApproval } from './db/pending-sender-approvals.js';
import { getOwners, hasAdminPrivilege, isOwner } from './db/user-roles.js';
import { ensureUserDm } from './user-dm.js';
import { getUser, upsertUser } from './db/users.js';
import { requestSenderApproval } from './sender-approval.js';

function extractAndUpsertUser(event: InboundEvent): string | null {
  let content: Record<string, unknown>;
  try {
    content = JSON.parse(event.message.content) as Record<string, unknown>;
  } catch {
    return null;
  }

  // chat-sdk-bridge serializes author info as a nested `author.userId` and
  // does NOT populate top-level `senderId`. Older adapters (v1, native) put
  // `senderId` or `sender` directly at the top level. Check all three.
  const senderIdField = typeof content.senderId === 'string' ? content.senderId : undefined;
  const senderField = typeof content.sender === 'string' ? content.sender : undefined;
  const author =
    typeof content.author === 'object' && content.author !== null
      ? (content.author as Record<string, unknown>)
      : undefined;
  const authorUserId = typeof author?.userId === 'string' ? (author.userId as string) : undefined;
  const senderName =
    (typeof content.senderName === 'string' ? content.senderName : undefined) ??
    (typeof author?.fullName === 'string' ? (author.fullName as string) : undefined) ??
    (typeof author?.userName === 'string' ? (author.userName as string) : undefined);

  const rawHandle = senderIdField ?? senderField ?? authorUserId;
  if (!rawHandle) return null;

  const userId = rawHandle.includes(':') ? rawHandle : `${event.channelType}:${rawHandle}`;
  if (!getUser(userId)) {
    upsertUser({
      id: userId,
      kind: event.channelType,
      display_name: senderName ?? null,
      created_at: new Date().toISOString(),
    });
  }
  return userId;
}

function safeParseContent(raw: string): { text?: string; sender?: string; senderId?: string } {
  try {
    return JSON.parse(raw);
  } catch {
    return { text: raw };
  }
}

function handleUnknownSender(
  mg: MessagingGroup,
  userId: string | null,
  agentGroupId: string,
  accessReason: string,
  event: InboundEvent,
): void {
  const parsed = safeParseContent(event.message.content);
  const senderName = parsed.sender ?? null;
  const dropRecord = {
    channel_type: event.channelType,
    platform_id: event.platformId,
    user_id: userId,
    sender_name: senderName,
    reason: `unknown_sender_${mg.unknown_sender_policy}`,
    messaging_group_id: mg.id,
    agent_group_id: agentGroupId,
  };

  if (mg.unknown_sender_policy === 'strict') {
    log.info('MESSAGE DROPPED — unknown sender (strict policy)', {
      messagingGroupId: mg.id,
      agentGroupId,
      userId,
      accessReason,
    });
    recordDroppedMessage(dropRecord);
    return;
  }

  if (mg.unknown_sender_policy === 'request_approval') {
    log.info('MESSAGE DROPPED — unknown sender (approval requested)', {
      messagingGroupId: mg.id,
      agentGroupId,
      userId,
      accessReason,
    });
    recordDroppedMessage(dropRecord);
    // Fire-and-forget; pick-approver + delivery + row-insert are all async.
    // If it fails it logs internally — the user's message still stays dropped
    // either way. Requires a resolved userId (senderResolver populates users
    // row before the gate fires); if we got here without one, there's nothing
    // to identify for approval and we just stay in the "silent strict" branch.
    if (userId) {
      requestSenderApproval({
        messagingGroupId: mg.id,
        agentGroupId,
        senderIdentity: userId,
        senderName,
        event,
      }).catch((err) => log.error('Sender-approval flow threw', { err }));
    }
    return;
  }

  // 'public' should have been handled before the gate; fall through silently.
}

setSenderResolver(extractAndUpsertUser);

setAccessGate((event, userId, mg, agentGroupId): AccessGateResult => {
  // Public channels skip the access check entirely.
  if (mg.unknown_sender_policy === 'public') {
    return { allowed: true };
  }

  if (!userId) {
    handleUnknownSender(mg, null, agentGroupId, 'unknown_user', event);
    return { allowed: false, reason: 'unknown_user' };
  }

  const decision = canAccessAgentGroup(userId, agentGroupId);
  if (decision.allowed) {
    return { allowed: true };
  }

  handleUnknownSender(mg, userId, agentGroupId, decision.reason, event);
  return { allowed: false, reason: decision.reason };
});

/**
 * Per-wiring sender-scope enforcement. Stricter than the messaging-group
 * `unknown_sender_policy` — a wiring can require `sender_scope='known'`
 * (explicit owner / admin / member) even on a 'public' messaging group.
 *
 * 'all' is a no-op; any sender passes. 'known' requires a userId that
 * canAccessAgentGroup accepts (owner, admin, or group member).
 */
setSenderScopeGate(
  (_event: InboundEvent, userId: string | null, _mg: MessagingGroup, agent: MessagingGroupAgent): AccessGateResult => {
    if (agent.sender_scope === 'all') return { allowed: true };
    if (!userId) return { allowed: false, reason: 'unknown_user_scope' };
    const decision = canAccessAgentGroup(userId, agent.agent_group_id);
    if (decision.allowed) return { allowed: true };
    return { allowed: false, reason: `sender_scope_${decision.reason}` };
  },
);

/**
 * Response handler for the unknown-sender approval card.
 *
 * Claim rule: questionId matches a row in pending_sender_approvals. If no
 * such row, return false so the next handler (approvals module, OneCLI,
 * interactive) gets a shot.
 *
 * Approve: add the sender to agent_group_members + re-invoke routeInbound
 * with the stored event. The second routing attempt clears the gate because
 * the user is now a member.
 *
 * Deny: delete the row (no "deny list" — a future message re-triggers a
 * fresh card per ACTION-ITEMS item 5 "no denial persistence").
 */
async function handleSenderApprovalResponse(payload: ResponsePayload): Promise<boolean> {
  const row = getPendingSenderApproval(payload.questionId);
  if (!row) return false;

  // payload.userId is the raw platform userId (e.g. "6037840640"); namespace it
  // with the channel type so it matches users(id) format. Then verify the
  // clicker is the designated approver OR has owner/admin privilege over this
  // agent group — any other click is rejected so random users can't self-admit
  // via stolen card forwarding.
  const clickerId = payload.userId ? `${payload.channelType}:${payload.userId}` : null;
  const isAuthorized =
    clickerId !== null && (clickerId === row.approver_user_id || hasAdminPrivilege(clickerId, row.agent_group_id));
  if (!isAuthorized) {
    log.warn('Unknown-sender approval click rejected — unauthorized clicker', {
      approvalId: row.id,
      clickerId,
      expectedApprover: row.approver_user_id,
    });
    return true; // claim the response so it's not unclaimed-logged, but do nothing
  }
  const approverId = clickerId;
  const approved = payload.value === 'approve';

  if (approved) {
    addMember({
      user_id: row.sender_identity,
      agent_group_id: row.agent_group_id,
      added_by: approverId,
      added_at: new Date().toISOString(),
    });
    log.info('Unknown sender approved — member added', {
      approvalId: row.id,
      senderIdentity: row.sender_identity,
      agentGroupId: row.agent_group_id,
      approverId,
    });

    // Clear the pending row BEFORE re-routing so the gate check on the
    // second attempt doesn't see the in-flight row and short-circuit.
    deletePendingSenderApproval(row.id);

    try {
      const event = JSON.parse(row.original_message) as InboundEvent;
      await routeInbound(event);
    } catch (err) {
      log.error('Failed to replay message after sender approval', { approvalId: row.id, err });
    }
    return true;
  }

  log.info('Unknown sender denied', {
    approvalId: row.id,
    senderIdentity: row.sender_identity,
    agentGroupId: row.agent_group_id,
    approverId,
  });
  deletePendingSenderApproval(row.id);
  return true;
}

registerResponseHandler(handleSenderApprovalResponse);

// ── Unknown-channel registration flow ──

/**
 * Persist a channel→agent wiring with MVP defaults and replay the
 * triggering event so the user's original message reaches the agent
 * without a manual retry.
 *
 * Shared between the approval-card path (handleChannelApprovalResponse)
 * and the sole-owner shortcut (gate auto-approve). Caller is responsible
 * for clearing any pending_channel_approvals row before invoking this.
 */
async function applyChannelWiring(
  messagingGroupId: string,
  agentGroupId: string,
  event: InboundEvent,
  approverUserId: string,
): Promise<void> {
  // Decide engage_mode from the original event. DMs (`isMention=true` &
  // not in a group) get `pattern='.'` (always respond). Group mentions
  // get `mention-sticky` (respond now + follow the thread).
  //
  // We can't read `mg.is_group` reliably here because we only auto-create
  // the mg with `is_group=0` on first sight — the adapter hasn't told us
  // yet whether it's actually a group. Fall back to the InboundEvent's
  // `threadId`: a non-null threadId implies a threaded platform (Slack
  // channel thread, Discord thread), which we treat as a group.
  const isGroup = event.threadId !== null;
  const engageMode: MessagingGroupAgent['engage_mode'] = isGroup ? 'mention-sticky' : 'pattern';
  const engagePattern = isGroup ? null : '.';

  const mgaId = `mga-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  createMessagingGroupAgent({
    id: mgaId,
    messaging_group_id: messagingGroupId,
    agent_group_id: agentGroupId,
    engage_mode: engageMode,
    engage_pattern: engagePattern,
    sender_scope: 'known',
    ignored_message_policy: 'accumulate',
    session_mode: 'shared',
    priority: 0,
    created_at: new Date().toISOString(),
  });
  log.info('Channel wiring created', {
    messagingGroupId,
    agentGroupId,
    mgaId,
    engageMode,
    approverId: approverUserId,
  });

  // Auto-admit the triggering sender. Without this, the replay below
  // would bounce through sender-approval (sender_scope='known' +
  // sender-is-not-a-member). Owners/admins are implicit members per
  // isMember(), so this is a no-op INSERT OR IGNORE for them.
  const senderUserId = extractAndUpsertUser(event);
  if (senderUserId) {
    addMember({
      user_id: senderUserId,
      agent_group_id: agentGroupId,
      added_by: approverUserId,
      added_at: new Date().toISOString(),
    });
  }

  try {
    await routeInbound(event);
  } catch (err) {
    log.error('Failed to replay message after channel wiring', { messagingGroupId, err });
  }
}

/**
 * Send a plain-text DM to the owner confirming an auto-wired channel.
 * Used by the sole-owner shortcut so the wiring isn't fully invisible —
 * if it happened on a server the owner didn't intend, they see it
 * immediately and can react.
 */
async function sendAutoWireConfirmation(
  ownerUserId: string,
  channelMg: MessagingGroup,
  agent: AgentGroup,
): Promise<void> {
  const ownerDm = await ensureUserDm(ownerUserId);
  if (!ownerDm) {
    log.warn('Auto-wire confirmation skipped — no DM channel for owner', { ownerUserId });
    return;
  }
  const adapter = getDeliveryAdapter();
  if (!adapter) {
    log.warn('Auto-wire confirmation skipped — no delivery adapter', { ownerUserId });
    return;
  }
  const channelLabel = channelMg.name || channelMg.platform_id;
  const text = `Auto-wired ${channelLabel} to ${agent.name} (sole-owner shortcut).`;
  try {
    await adapter.deliver(
      ownerDm.channel_type,
      ownerDm.platform_id,
      null,
      'chat-sdk',
      JSON.stringify({ text }),
    );
  } catch (err) {
    log.error('Auto-wire confirmation delivery failed', { ownerUserId, err });
  }
}

setChannelRequestGate(async (mg, event) => {
  // Sole-owner shortcut: skip the approval card when the sender is the
  // sole owner AND there's exactly one agent group to wire to. The choice
  // of target is unambiguous and the approver is the same person who'd
  // receive the card — the click adds friction without protection.
  //
  // Falls back to the approval flow the moment a co-owner is added or a
  // second agent group exists. The co-owner gate is intentional: new
  // owners get full visibility into what gets wired even though their
  // single click would have approved it anyway.
  const senderUserId = extractAndUpsertUser(event);
  if (senderUserId && isOwner(senderUserId)) {
    const owners = getOwners();
    const agentGroups = getAllAgentGroups();
    if (owners.length === 1 && agentGroups.length === 1) {
      const target = agentGroups[0];
      log.info('Channel auto-wired — sole-owner shortcut', {
        messagingGroupId: mg.id,
        agentGroupId: target.id,
        owner: senderUserId,
      });
      await applyChannelWiring(mg.id, target.id, event, senderUserId);
      await sendAutoWireConfirmation(senderUserId, mg, target);
      return;
    }
  }
  await requestChannelApproval({ messagingGroupId: mg.id, event });
});

/**
 * Response handler for the unknown-channel registration card.
 *
 * Claim rule: questionId matches a pending_channel_approvals row (keyed
 * by messaging_group_id). If no such row, return false so downstream
 * handlers get a shot.
 *
 * Approve: create the wiring with MVP defaults (mention-sticky for
 * groups / pattern='.' for DMs; sender_scope='known';
 * ignored_message_policy='accumulate'), add the triggering sender as a
 * member so sender_scope doesn't immediately bounce them into a
 * sender-approval card, then replay the original event.
 *
 * Deny: set `messaging_groups.denied_at = now()` so future mentions on
 * this channel drop silently until an admin explicitly wires it.
 */
async function handleChannelApprovalResponse(payload: ResponsePayload): Promise<boolean> {
  const row = getPendingChannelApproval(payload.questionId);
  if (!row) return false;

  // Click-auth: same pattern as sender-approval (see commit 68058cb).
  // Raw platform userId → namespace with channelType → must match the
  // designated approver OR have admin privilege over the target agent.
  const clickerId = payload.userId ? `${payload.channelType}:${payload.userId}` : null;
  const isAuthorized =
    clickerId !== null && (clickerId === row.approver_user_id || hasAdminPrivilege(clickerId, row.agent_group_id));
  if (!isAuthorized) {
    log.warn('Channel registration click rejected — unauthorized clicker', {
      messagingGroupId: row.messaging_group_id,
      clickerId,
      expectedApprover: row.approver_user_id,
    });
    return true; // claim but take no action
  }
  const approverId = clickerId;
  const approved = payload.value === 'approve';

  if (!approved) {
    setMessagingGroupDeniedAt(row.messaging_group_id, new Date().toISOString());
    deletePendingChannelApproval(row.messaging_group_id);
    log.info('Channel registration denied', {
      messagingGroupId: row.messaging_group_id,
      agentGroupId: row.agent_group_id,
      approverId,
    });
    return true;
  }

  // Rehydrate the original event to know (a) whether it was a DM or group
  // (chooses engage_mode default), and (b) who the triggering sender was
  // (auto-member-add so sender_scope='known' doesn't bounce the replay).
  let event: InboundEvent;
  try {
    event = JSON.parse(row.original_message) as InboundEvent;
  } catch (err) {
    log.error('Channel registration: failed to parse stored event', {
      messagingGroupId: row.messaging_group_id,
      err,
    });
    deletePendingChannelApproval(row.messaging_group_id);
    return true;
  }

  // Clear the pending row BEFORE wiring + replay so the gate check on
  // the replayed event sees a wired channel (agentCount > 0) and takes
  // the fan-out path instead of re-escalating.
  deletePendingChannelApproval(row.messaging_group_id);
  log.info('Channel registration approved', {
    messagingGroupId: row.messaging_group_id,
    agentGroupId: row.agent_group_id,
    approverId,
  });
  await applyChannelWiring(row.messaging_group_id, row.agent_group_id, event, approverId);
  return true;
}

registerResponseHandler(handleChannelApprovalResponse);
