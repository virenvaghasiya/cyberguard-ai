import React, { useState, useCallback } from 'react';
import {
  View, Text, ScrollView, StyleSheet,
  TouchableOpacity, RefreshControl, ActivityIndicator,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { colors, spacing, radius, typography } from '../theme';
import StatCard from '../components/StatCard';
import AlertCard from '../components/AlertCard';
import { fetchNetworkStatus, runDemoAnalysis } from '../services/api';

export default function NetworkScreen() {
  const [status, setStatus]       = useState(null);
  const [loading, setLoading]     = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [demoRunning, setDemoRunning] = useState(false);
  const [demoResult, setDemoResult]   = useState(null);
  const [error, setError]         = useState(null);

  const load = useCallback(async () => {
    try {
      setError(null);
      const s = await fetchNetworkStatus();
      setStatus(s);
    } catch {
      setError('Cannot reach server.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  const runDemo = async () => {
    setDemoRunning(true);
    setDemoResult(null);
    try {
      const r = await runDemoAnalysis();
      setDemoResult(r);
      load();
    } catch {
      setError('Demo failed.');
    } finally {
      setDemoRunning(false);
    }
  };

  const onRefresh = () => { setRefreshing(true); load(); };

  React.useEffect(() => { setLoading(true); load(); }, [load]);

  const detector = status?.detector || {};
  const recent   = status?.recent_anomalies || [];

  return (
    <SafeAreaView style={styles.safe}>
      <ScrollView
        style={styles.scroll}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor={colors.primary} />}
      >
        <Text style={[typography.h2, styles.title]}>Network Monitor</Text>

        {error && <View style={styles.errorBanner}><Text style={styles.errorText}>{error}</Text></View>}

        {loading ? (
          <ActivityIndicator color={colors.primary} style={{ marginTop: spacing.xl }} />
        ) : (
          <>
            {/* Detector stats */}
            <Text style={styles.section}>ANOMALY DETECTOR</Text>
            <View style={styles.row}>
              <StatCard label="Events Processed" value={detector.events_processed || 0} color={colors.primary} />
              <StatCard label="Anomalies Found"  value={detector.anomalies_detected || 0} color={colors.danger} />
            </View>
            <View style={[styles.statusRow, { backgroundColor: colors.card, borderRadius: radius.md, padding: spacing.md, marginBottom: spacing.sm }]}>
              <View style={[styles.dot, { backgroundColor: detector.running ? colors.success : colors.danger }]} />
              <Text style={styles.statusText}>{detector.running ? 'Detector online' : 'Detector offline'}</Text>
              {detector.last_run && (
                <Text style={styles.lastRun}>
                  Last run: {new Date(detector.last_run).toLocaleTimeString()}
                </Text>
              )}
            </View>

            {/* Demo button */}
            <Text style={styles.section}>ANALYSIS</Text>
            <TouchableOpacity style={styles.demoBtn} onPress={runDemo} disabled={demoRunning}>
              {demoRunning
                ? <ActivityIndicator color={colors.background} />
                : <Text style={styles.demoBtnText}>▶  Run Demo Scan (2100 flows)</Text>
              }
            </TouchableOpacity>

            {demoResult && (
              <View style={styles.demoResult}>
                <Text style={styles.demoResultTitle}>Demo Results</Text>
                <View style={styles.row}>
                  <StatCard label="Total Flows"   value={demoResult.total_flows}       color={colors.primary} />
                  <StatCard label="Anomalies"      value={demoResult.anomalies_detected} color={colors.danger} />
                  <StatCard label="Rate"           value={`${(demoResult.anomaly_rate * 100).toFixed(1)}%`} color={colors.warning} />
                </View>
              </View>
            )}

            {/* Recent anomalies */}
            <Text style={styles.section}>RECENT ANOMALIES</Text>
            {recent.length === 0 ? (
              <View style={[styles.card, styles.center]}>
                <Text style={styles.empty}>No anomalies detected yet.</Text>
                <Text style={styles.emptySub}>Run a demo scan or upload traffic data.</Text>
              </View>
            ) : (
              recent.map((e, i) => <AlertCard key={e.event_id || i} event={e} />)
            )}
          </>
        )}
        <View style={{ height: spacing.xl }} />
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: colors.background },
  scroll: { flex: 1, paddingHorizontal: spacing.md },
  title: { paddingTop: spacing.lg, paddingBottom: spacing.sm },
  section: { fontSize: 11, fontWeight: '700', color: colors.textMuted, letterSpacing: 1, marginBottom: spacing.sm, marginTop: spacing.md },
  row: { flexDirection: 'row', marginHorizontal: -spacing.xs, marginBottom: spacing.sm },
  statusRow: { flexDirection: 'row', alignItems: 'center' },
  dot: { width: 8, height: 8, borderRadius: 4, marginRight: spacing.sm },
  statusText: { flex: 1, fontSize: 13, color: colors.textPrimary },
  lastRun: { fontSize: 11, color: colors.textMuted },
  card: { backgroundColor: colors.card, borderRadius: radius.md, padding: spacing.md, marginBottom: spacing.sm },
  center: { alignItems: 'center', paddingVertical: spacing.lg },
  empty: { color: colors.textSecondary, fontSize: 14, fontWeight: '600' },
  emptySub: { color: colors.textMuted, fontSize: 12, marginTop: 4, textAlign: 'center' },
  demoBtn: { backgroundColor: colors.primary, borderRadius: radius.md, padding: spacing.md, alignItems: 'center', marginBottom: spacing.sm },
  demoBtnText: { color: colors.background, fontWeight: '700', fontSize: 14 },
  demoResult: { backgroundColor: colors.card, borderRadius: radius.md, padding: spacing.md, marginBottom: spacing.sm },
  demoResultTitle: { fontSize: 13, fontWeight: '600', color: colors.textPrimary, marginBottom: spacing.sm },
  errorBanner: { backgroundColor: '#2d0a14', borderRadius: radius.sm, padding: spacing.md, marginBottom: spacing.sm },
  errorText: { color: colors.critical, fontSize: 13 },
});
