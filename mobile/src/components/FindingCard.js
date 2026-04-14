import React, { useState } from 'react';
import { View, Text, StyleSheet, TouchableOpacity } from 'react-native';
import { colors, spacing, radius } from '../theme';
import SeverityBadge from './SeverityBadge';

export default function FindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false);
  const d = finding.details || {};

  return (
    <TouchableOpacity onPress={() => setExpanded(e => !e)} activeOpacity={0.8}>
      <View style={styles.card}>
        <View style={styles.header}>
          <View style={styles.headerLeft}>
            <Text style={styles.title}>
              {finding.attack_type.replace(/_/g, ' ').toUpperCase()}
            </Text>
            {d.service && <Text style={styles.service}>{d.service}</Text>}
          </View>
          <View style={styles.headerRight}>
            <SeverityBadge level={finding.severity} small />
            <Text style={styles.confidence}>
              {Math.round(finding.confidence * 100)}%
            </Text>
          </View>
        </View>

        <Text style={styles.description} numberOfLines={expanded ? 0 : 2}>
          {d.description || finding.attack_type}
        </Text>

        {expanded && (
          <View style={styles.details}>
            {d.host && <DetailRow label="Host" value={d.host} />}
            {d.port && <DetailRow label="Port" value={String(d.port)} />}
            {d.source_ip && <DetailRow label="Source IP" value={d.source_ip} />}
            {d.failed_attempts && (
              <DetailRow label="Failed attempts" value={String(d.failed_attempts)} />
            )}
            {d.recommendation && (
              <View style={styles.rec}>
                <Text style={styles.recLabel}>Recommendation</Text>
                <Text style={styles.recText}>{d.recommendation}</Text>
              </View>
            )}
          </View>
        )}

        <Text style={styles.expand}>{expanded ? '▲ less' : '▼ more'}</Text>
      </View>
    </TouchableOpacity>
  );
}

function DetailRow({ label, value }) {
  return (
    <View style={styles.row}>
      <Text style={styles.rowLabel}>{label}</Text>
      <Text style={styles.rowValue}>{value}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    backgroundColor: colors.card,
    borderRadius: radius.md,
    padding: spacing.md,
    marginBottom: spacing.sm,
  },
  header: { flexDirection: 'row', justifyContent: 'space-between', marginBottom: spacing.xs },
  headerLeft: { flex: 1, marginRight: spacing.sm },
  headerRight: { alignItems: 'flex-end' },
  title: { fontSize: 12, fontWeight: '700', color: colors.textPrimary, letterSpacing: 0.3 },
  service: { fontSize: 11, color: colors.primary, marginTop: 2 },
  confidence: { fontSize: 10, color: colors.textMuted, marginTop: 4 },
  description: { fontSize: 13, color: colors.textSecondary, lineHeight: 18 },
  details: { marginTop: spacing.sm, paddingTop: spacing.sm, borderTopWidth: 1, borderTopColor: colors.border },
  row: { flexDirection: 'row', justifyContent: 'space-between', paddingVertical: 3 },
  rowLabel: { fontSize: 12, color: colors.textMuted },
  rowValue: { fontSize: 12, color: colors.textPrimary, fontFamily: 'monospace' },
  rec: { marginTop: spacing.sm },
  recLabel: { fontSize: 11, color: colors.warning, fontWeight: '600', marginBottom: 2 },
  recText: { fontSize: 12, color: colors.textSecondary, lineHeight: 17 },
  expand: { fontSize: 10, color: colors.textMuted, textAlign: 'right', marginTop: spacing.xs },
});
