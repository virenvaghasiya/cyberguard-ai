import React, { useState, useEffect, useCallback } from 'react';
import {
  View, Text, ScrollView, StyleSheet, RefreshControl,
  TouchableOpacity, ActivityIndicator,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { colors, spacing, radius, typography } from '../theme';
import StatCard from '../components/StatCard';
import { fetchHealth, fetchStatsSummary, fetchStatsTimeline } from '../services/api';

export default function DashboardScreen() {
  const [health, setHealth] = useState(null);
  const [summary, setSummary] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    try {
      setError(null);
      const [h, s, t] = await Promise.all([
        fetchHealth(),
        fetchStatsSummary(),
        fetchStatsTimeline(24),
      ]);
      setHealth(h);
      setSummary(s);
      setTimeline(t.timeline || []);
    } catch (e) {
      setError('Cannot reach server. Check Settings.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const onRefresh = () => { setRefreshing(true); load(); };

  if (loading) {
    return (
      <SafeAreaView style={styles.center}>
        <ActivityIndicator color={colors.primary} size="large" />
        <Text style={styles.loadingText}>Connecting to CyberGuard AI...</Text>
      </SafeAreaView>
    );
  }

  const bySev = summary?.by_severity || {};
  const totalEvents = summary?.total_events || 0;
  const topThreats = Object.entries(summary?.by_attack_type || {})
    .sort((a, b) => b[1] - a[1]).slice(0, 5);

  const detectors = health?.detectors || [];
  const allOnline = detectors.every(d => d.running);

  return (
    <SafeAreaView style={styles.safe}>
      <ScrollView
        style={styles.scroll}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor={colors.primary} />}
      >
        {/* Header */}
        <View style={styles.header}>
          <View>
            <Text style={typography.h1}>CyberGuard AI</Text>
            <Text style={styles.subtitle}>Personal Security Dashboard</Text>
          </View>
          <View style={[styles.statusDot, { backgroundColor: allOnline ? colors.success : colors.danger }]} />
        </View>

        {error && (
          <View style={styles.errorBanner}>
            <Text style={styles.errorText}>{error}</Text>
          </View>
        )}

        {/* Severity stats */}
        <Text style={styles.sectionTitle}>THREAT OVERVIEW</Text>
        <View style={styles.statsRow}>
          <StatCard label="Total Events" value={totalEvents} color={colors.primary} />
          <StatCard label="Critical"     value={bySev.critical || 0} color={colors.critical} />
        </View>
        <View style={styles.statsRow}>
          <StatCard label="High"   value={bySev.high   || 0} color={colors.high} />
          <StatCard label="Medium" value={bySev.medium || 0} color={colors.warning} />
          <StatCard label="Low"    value={bySev.low    || 0} color={colors.info} />
        </View>

        {/* Timeline mini-chart */}
        <Text style={styles.sectionTitle}>LAST 24 HOURS</Text>
        <View style={styles.timelineCard}>
          {timeline.length === 0 ? (
            <Text style={styles.empty}>No events yet — run a demo scan to generate data</Text>
          ) : (
            <MiniTimeline data={timeline} />
          )}
        </View>

        {/* Top threat types */}
        {topThreats.length > 0 && (
          <>
            <Text style={styles.sectionTitle}>TOP THREAT TYPES</Text>
            <View style={styles.card}>
              {topThreats.map(([type, count]) => (
                <View key={type} style={styles.threatRow}>
                  <Text style={styles.threatName}>{type.replace(/_/g, ' ')}</Text>
                  <View style={styles.bar}>
                    <View style={[styles.barFill, {
                      width: `${Math.min(100, (count / topThreats[0][1]) * 100)}%`,
                    }]} />
                  </View>
                  <Text style={styles.threatCount}>{count}</Text>
                </View>
              ))}
            </View>
          </>
        )}

        {/* Detector status */}
        <Text style={styles.sectionTitle}>DETECTORS</Text>
        <View style={styles.card}>
          {detectors.map(d => (
            <View key={d.name} style={styles.detectorRow}>
              <View style={[styles.dot, { backgroundColor: d.running ? colors.success : colors.danger }]} />
              <Text style={styles.detectorName}>{d.name.replace(/_/g, ' ')}</Text>
              <Text style={styles.detectorStats}>
                {d.events_processed} events · {d.anomalies_detected} anomalies
              </Text>
            </View>
          ))}
          {detectors.length === 0 && (
            <Text style={styles.empty}>No detectors registered</Text>
          )}
        </View>

        <View style={{ height: spacing.xl }} />
      </ScrollView>
    </SafeAreaView>
  );
}

function MiniTimeline({ data }) {
  const maxCount = Math.max(...data.map(d => d.count), 1);
  const recent = data.slice(-12); // show last 12 hours
  return (
    <View style={styles.timeline}>
      {recent.map((bucket, i) => (
        <View key={i} style={styles.barCol}>
          <View style={styles.barContainer}>
            <View style={[styles.timelineBar, {
              height: `${Math.max(4, (bucket.count / maxCount) * 100)}%`,
              backgroundColor: bucket.critical_count > 0 ? colors.critical : colors.primary,
            }]} />
          </View>
          {i % 3 === 0 && (
            <Text style={styles.barLabel}>{bucket.hour.split('T')[1]}</Text>
          )}
        </View>
      ))}
    </View>
  );
}

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: colors.background },
  center: { flex: 1, backgroundColor: colors.background, alignItems: 'center', justifyContent: 'center' },
  scroll: { flex: 1, paddingHorizontal: spacing.md },
  header: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', paddingVertical: spacing.lg },
  subtitle: { fontSize: 12, color: colors.textMuted, marginTop: 2 },
  statusDot: { width: 12, height: 12, borderRadius: 6 },
  loadingText: { color: colors.textMuted, marginTop: spacing.md },
  errorBanner: { backgroundColor: '#2d0a14', borderRadius: radius.sm, padding: spacing.md, marginBottom: spacing.md },
  errorText: { color: colors.critical, fontSize: 13 },
  sectionTitle: { fontSize: 11, fontWeight: '700', color: colors.textMuted, letterSpacing: 1, marginBottom: spacing.sm, marginTop: spacing.md },
  statsRow: { flexDirection: 'row', marginHorizontal: -spacing.xs },
  card: { backgroundColor: colors.card, borderRadius: radius.md, padding: spacing.md, marginBottom: spacing.sm },
  timelineCard: { backgroundColor: colors.card, borderRadius: radius.md, padding: spacing.md, marginBottom: spacing.sm, height: 100 },
  timeline: { flexDirection: 'row', flex: 1, alignItems: 'flex-end' },
  barCol: { flex: 1, alignItems: 'center' },
  barContainer: { flex: 1, width: '80%', justifyContent: 'flex-end' },
  timelineBar: { width: '100%', borderRadius: 2, minHeight: 2 },
  barLabel: { fontSize: 8, color: colors.textMuted, marginTop: 2 },
  empty: { color: colors.textMuted, fontSize: 13, textAlign: 'center', paddingVertical: spacing.sm },
  threatRow: { flexDirection: 'row', alignItems: 'center', paddingVertical: 5 },
  threatName: { fontSize: 12, color: colors.textSecondary, width: 120 },
  bar: { flex: 1, height: 6, backgroundColor: colors.border, borderRadius: 3, marginHorizontal: spacing.sm, overflow: 'hidden' },
  barFill: { height: '100%', backgroundColor: colors.primary, borderRadius: 3 },
  threatCount: { fontSize: 12, color: colors.textPrimary, width: 30, textAlign: 'right' },
  detectorRow: { flexDirection: 'row', alignItems: 'center', paddingVertical: 6 },
  dot: { width: 8, height: 8, borderRadius: 4, marginRight: spacing.sm },
  detectorName: { flex: 1, fontSize: 13, color: colors.textPrimary, textTransform: 'capitalize' },
  detectorStats: { fontSize: 11, color: colors.textMuted },
});
