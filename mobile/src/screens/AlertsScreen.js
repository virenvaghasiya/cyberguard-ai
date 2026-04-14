import React, { useState, useEffect, useRef } from 'react';
import {
  View, Text, FlatList, StyleSheet,
  TouchableOpacity, ActivityIndicator,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { colors, spacing, radius, typography } from '../theme';
import AlertCard from '../components/AlertCard';
import { alertWS } from '../services/websocket';
import { fetchEvents } from '../services/api';

const SEVERITY_FILTERS = ['all', 'critical', 'high', 'medium', 'low'];

export default function AlertsScreen() {
  const [alerts, setAlerts]       = useState([]);
  const [filter, setFilter]       = useState('all');
  const [connected, setConnected] = useState(false);
  const [loading, setLoading]     = useState(true);
  const removeListener            = useRef(null);

  // Load recent events from REST on mount, then switch to WebSocket
  useEffect(() => {
    fetchEvents(100)
      .then(data => {
        setAlerts(data.events || []);
        setLoading(false);
      })
      .catch(() => setLoading(false));

    alertWS.connect();

    removeListener.current = alertWS.addListener((type, data) => {
      if (type === 'status') {
        setConnected(data.connected);
      } else if (type === 'alert') {
        // Skip connection welcome messages
        if (data.type === 'connected') return;
        setAlerts(prev => [data, ...prev].slice(0, 500));
      }
    });

    return () => {
      if (removeListener.current) removeListener.current();
      alertWS.disconnect();
    };
  }, []);

  const filtered = filter === 'all'
    ? alerts
    : alerts.filter(a => a.severity === filter);

  return (
    <SafeAreaView style={styles.safe}>
      {/* Header */}
      <View style={styles.header}>
        <Text style={typography.h2}>Live Alerts</Text>
        <View style={styles.wsStatus}>
          <View style={[styles.dot, { backgroundColor: connected ? colors.success : colors.danger }]} />
          <Text style={styles.wsLabel}>{connected ? 'Live' : 'Offline'}</Text>
        </View>
      </View>

      {/* Severity filter pills */}
      <View style={styles.filters}>
        {SEVERITY_FILTERS.map(f => (
          <TouchableOpacity
            key={f}
            onPress={() => setFilter(f)}
            style={[styles.pill, filter === f && styles.pillActive]}
          >
            <Text style={[styles.pillText, filter === f && styles.pillTextActive]}>
              {f.toUpperCase()}
            </Text>
          </TouchableOpacity>
        ))}
      </View>

      {loading ? (
        <View style={styles.center}>
          <ActivityIndicator color={colors.primary} />
        </View>
      ) : filtered.length === 0 ? (
        <View style={styles.center}>
          <Text style={styles.empty}>No alerts{filter !== 'all' ? ` at ${filter} severity` : ''}.</Text>
          <Text style={styles.emptySub}>Run a scan or wait for live detections.</Text>
        </View>
      ) : (
        <FlatList
          data={filtered}
          keyExtractor={(item, i) => item.event_id || String(i)}
          renderItem={({ item }) => <AlertCard event={item} />}
          contentContainerStyle={styles.list}
          showsVerticalScrollIndicator={false}
        />
      )}

      {/* Alert count bar */}
      <View style={styles.footer}>
        <Text style={styles.footerText}>
          {filtered.length} alert{filtered.length !== 1 ? 's' : ''}
          {filter !== 'all' ? ` · ${filter}` : ''}
        </Text>
        <TouchableOpacity onPress={() => setAlerts([])}>
          <Text style={styles.clearBtn}>Clear</Text>
        </TouchableOpacity>
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: colors.background },
  header: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', paddingHorizontal: spacing.md, paddingTop: spacing.md, paddingBottom: spacing.sm },
  wsStatus: { flexDirection: 'row', alignItems: 'center' },
  dot: { width: 8, height: 8, borderRadius: 4, marginRight: 5 },
  wsLabel: { fontSize: 12, color: colors.textSecondary },
  filters: { flexDirection: 'row', paddingHorizontal: spacing.md, marginBottom: spacing.sm },
  pill: { paddingHorizontal: 10, paddingVertical: 4, borderRadius: 20, borderWidth: 1, borderColor: colors.border, marginRight: 6 },
  pillActive: { backgroundColor: colors.primary, borderColor: colors.primary },
  pillText: { fontSize: 10, fontWeight: '600', color: colors.textMuted },
  pillTextActive: { color: colors.background },
  center: { flex: 1, alignItems: 'center', justifyContent: 'center' },
  empty: { color: colors.textSecondary, fontSize: 15, fontWeight: '600' },
  emptySub: { color: colors.textMuted, fontSize: 12, marginTop: 4 },
  list: { paddingHorizontal: spacing.md, paddingBottom: spacing.lg },
  footer: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', paddingHorizontal: spacing.md, paddingVertical: spacing.sm, borderTopWidth: 1, borderTopColor: colors.border },
  footerText: { fontSize: 12, color: colors.textMuted },
  clearBtn: { fontSize: 12, color: colors.danger },
});
