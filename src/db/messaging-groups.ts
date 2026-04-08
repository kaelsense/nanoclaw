import type { MessagingGroup, MessagingGroupAgent } from '../types-v2.js';
import { getDb } from './connection.js';

// ── Messaging Groups ──

export function createMessagingGroup(group: MessagingGroup): void {
  getDb()
    .prepare(
      `INSERT INTO messaging_groups (id, channel_type, platform_id, name, is_group, admin_user_id, created_at)
       VALUES (@id, @channel_type, @platform_id, @name, @is_group, @admin_user_id, @created_at)`,
    )
    .run(group);
}

export function getMessagingGroup(id: string): MessagingGroup | undefined {
  return getDb().prepare('SELECT * FROM messaging_groups WHERE id = ?').get(id) as MessagingGroup | undefined;
}

export function getMessagingGroupByPlatform(channelType: string, platformId: string): MessagingGroup | undefined {
  return getDb()
    .prepare('SELECT * FROM messaging_groups WHERE channel_type = ? AND platform_id = ?')
    .get(channelType, platformId) as MessagingGroup | undefined;
}

export function getAllMessagingGroups(): MessagingGroup[] {
  return getDb().prepare('SELECT * FROM messaging_groups ORDER BY name').all() as MessagingGroup[];
}

export function getMessagingGroupsByChannel(channelType: string): MessagingGroup[] {
  return getDb().prepare('SELECT * FROM messaging_groups WHERE channel_type = ?').all(channelType) as MessagingGroup[];
}

export function updateMessagingGroup(
  id: string,
  updates: Partial<Pick<MessagingGroup, 'name' | 'is_group' | 'admin_user_id'>>,
): void {
  const fields: string[] = [];
  const values: Record<string, unknown> = { id };

  for (const [key, value] of Object.entries(updates)) {
    if (value !== undefined) {
      fields.push(`${key} = @${key}`);
      values[key] = value;
    }
  }
  if (fields.length === 0) return;

  getDb()
    .prepare(`UPDATE messaging_groups SET ${fields.join(', ')} WHERE id = @id`)
    .run(values);
}

export function deleteMessagingGroup(id: string): void {
  getDb().prepare('DELETE FROM messaging_groups WHERE id = ?').run(id);
}

// ── Messaging Group Agents ──

export function createMessagingGroupAgent(mga: MessagingGroupAgent): void {
  getDb()
    .prepare(
      `INSERT INTO messaging_group_agents (id, messaging_group_id, agent_group_id, trigger_rules, response_scope, session_mode, priority, created_at)
       VALUES (@id, @messaging_group_id, @agent_group_id, @trigger_rules, @response_scope, @session_mode, @priority, @created_at)`,
    )
    .run(mga);
}

export function getMessagingGroupAgents(messagingGroupId: string): MessagingGroupAgent[] {
  return getDb()
    .prepare('SELECT * FROM messaging_group_agents WHERE messaging_group_id = ? ORDER BY priority DESC')
    .all(messagingGroupId) as MessagingGroupAgent[];
}

export function getMessagingGroupAgent(id: string): MessagingGroupAgent | undefined {
  return getDb().prepare('SELECT * FROM messaging_group_agents WHERE id = ?').get(id) as
    | MessagingGroupAgent
    | undefined;
}

export function updateMessagingGroupAgent(
  id: string,
  updates: Partial<Pick<MessagingGroupAgent, 'trigger_rules' | 'response_scope' | 'session_mode' | 'priority'>>,
): void {
  const fields: string[] = [];
  const values: Record<string, unknown> = { id };

  for (const [key, value] of Object.entries(updates)) {
    if (value !== undefined) {
      fields.push(`${key} = @${key}`);
      values[key] = value;
    }
  }
  if (fields.length === 0) return;

  getDb()
    .prepare(`UPDATE messaging_group_agents SET ${fields.join(', ')} WHERE id = @id`)
    .run(values);
}

export function deleteMessagingGroupAgent(id: string): void {
  getDb().prepare('DELETE FROM messaging_group_agents WHERE id = ?').run(id);
}
