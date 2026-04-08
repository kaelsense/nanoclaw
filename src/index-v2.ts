/**
 * NanoClaw v2 — main entry point.
 *
 * Thin orchestrator: init DB, run migrations, start channel adapters,
 * start delivery polls, start sweep, handle shutdown.
 */
import path from 'path';

import { DATA_DIR } from './config.js';
import { initDb } from './db/connection.js';
import { runMigrations } from './db/migrations/index.js';
import { getMessagingGroupsByChannel, getMessagingGroupAgents } from './db/messaging-groups.js';
import { ensureContainerRuntimeRunning, cleanupOrphans } from './container-runtime.js';
import { startActiveDeliveryPoll, startSweepDeliveryPoll, setDeliveryAdapter, stopDeliveryPolls } from './delivery.js';
import { startHostSweep, stopHostSweep } from './host-sweep.js';
import { routeInbound } from './router-v2.js';
import { log } from './log.js';

// Channel imports — each triggers self-registration
// import './channels/discord-v2.js';

import type { ChannelAdapter, ChannelSetup, ConversationConfig } from './channels/adapter.js';
import { initChannelAdapters, teardownChannelAdapters, getChannelAdapter } from './channels/channel-registry.js';

async function main(): Promise<void> {
  log.info('NanoClaw v2 starting');

  // 1. Init central DB
  const dbPath = path.join(DATA_DIR, 'v2.db');
  const db = initDb(dbPath);
  runMigrations(db);
  log.info('Central DB ready', { path: dbPath });

  // 2. Container runtime
  ensureContainerRuntimeRunning();
  cleanupOrphans();

  // 3. Channel adapters
  await initChannelAdapters((adapter: ChannelAdapter): ChannelSetup => {
    const conversations = buildConversationConfigs(adapter.channelType);
    return {
      conversations,
      onInbound(platformId, threadId, message) {
        routeInbound({
          channelType: adapter.channelType,
          platformId,
          threadId,
          message: {
            id: message.id,
            kind: message.kind,
            content: JSON.stringify(message.content),
            timestamp: message.timestamp,
          },
        }).catch((err) => {
          log.error('Failed to route inbound message', { channelType: adapter.channelType, err });
        });
      },
      onMetadata(platformId, name, isGroup) {
        log.info('Channel metadata discovered', {
          channelType: adapter.channelType,
          platformId,
          name,
          isGroup,
        });
      },
    };
  });

  // 4. Delivery adapter bridge — dispatches to channel adapters
  setDeliveryAdapter({
    async deliver(channelType, platformId, threadId, kind, content) {
      const adapter = getChannelAdapter(channelType);
      if (!adapter) {
        log.warn('No adapter for channel type', { channelType });
        return;
      }
      await adapter.deliver(platformId, threadId, { kind, content: JSON.parse(content) });
    },
    async setTyping(channelType, platformId, threadId) {
      const adapter = getChannelAdapter(channelType);
      await adapter?.setTyping?.(platformId, threadId);
    },
  });

  // 5. Start delivery polls
  startActiveDeliveryPoll();
  startSweepDeliveryPoll();
  log.info('Delivery polls started');

  // 6. Start host sweep
  startHostSweep();
  log.info('Host sweep started');

  log.info('NanoClaw v2 running');
}

/** Build ConversationConfig[] for a channel type from the central DB. */
function buildConversationConfigs(channelType: string): ConversationConfig[] {
  const groups = getMessagingGroupsByChannel(channelType);
  const configs: ConversationConfig[] = [];

  for (const mg of groups) {
    const agents = getMessagingGroupAgents(mg.id);
    for (const agent of agents) {
      const triggerRules = agent.trigger_rules ? JSON.parse(agent.trigger_rules) : null;
      configs.push({
        platformId: mg.platform_id,
        agentGroupId: agent.agent_group_id,
        triggerPattern: triggerRules?.pattern,
        requiresTrigger: triggerRules?.requiresTrigger ?? false,
        sessionMode: agent.session_mode,
      });
    }
  }

  return configs;
}

/** Graceful shutdown. */
async function shutdown(signal: string): Promise<void> {
  log.info('Shutdown signal received', { signal });
  stopDeliveryPolls();
  stopHostSweep();
  await teardownChannelAdapters();
  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

main().catch((err) => {
  log.fatal('Startup failed', { err });
  process.exit(1);
});
