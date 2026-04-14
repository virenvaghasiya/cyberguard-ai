import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { colors, spacing, radius } from '../theme';
import SeverityBadge from './SeverityBadge';

const TYPE_ICONS = {
  brute_force: '🔨',
  root_login: '⚠️',
  privilege_escalation: '🔑',
  user_enumeration: '👤',
  account_lockout: '🔒',
  port_scan: '🔍',
  c2_beacon: '📡',
  web_scanning: '🌐',
  web_brute_force: '🔨',
  cron_modification: '⏰',
  service_failure: '💥',
  anomaly: '📊',
};

export default function AlertCard({ event }) {
  const data = event.data || {};
  const attackType = data.attack_type || event.event_type || 'unknown';
  const icon = TYPE_ICONS[attackType] || '🛡️';
  const source = event.source || 'system';
  const ts = event.timestamp
    ? new Date(event.timestamp).toLocaleTimeString()
    : '';
  const description = data.description || attackType.replace(/_/g, ' ');

  return (
    <View style={styles.card}>
      <View style={styles.header}>
        <Text style={styles.icon}>{icon}</Text>
        <View style={styles.headerText}>
          <Text style={styles.title} numberOfLines={1}>
            {attackType.replace(/_/g, ' ').toUpperCase()}
          </Text>
          <Text style={styles.source}>{source} · {ts}</Text>
        </View>
        <SeverityBadge level={event.severity} small />
      </View>
      <Text style={styles.description} numberOfLines={2}>{description}</Text>
      {data.source_ip && (
        <Text style={styles.meta}>Source IP: {data.source_ip}</Text>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    backgroundColor: colors.card,
    borderRadius: radius.md,
    padding: spacing.md,
    marginBottom: spacing.sm,
    borderLeftWidth: 3,
    borderLeftColor: colors.border,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: spacing.xs,
  },
  icon: { fontSize: 20, marginRight: spacing.sm },
  headerText: { flex: 1 },
  title: {
    fontSize: 13,
    fontWeight: '700',
    color: colors.textPrimary,
    letterSpacing: 0.3,
  },
  source: { fontSize: 11, color: colors.textMuted, marginTop: 1 },
  description: { fontSize: 13, color: colors.textSecondary, lineHeight: 18 },
  meta: { fontSize: 11, color: colors.primary, marginTop: 4, fontFamily: 'monospace' },
});
