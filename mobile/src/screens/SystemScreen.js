/**
 * CyberGuard AI — System Screen
 * Four tabs: Processes | USB | Persistence | Rules
 */

import { useState, useEffect, useCallback } from 'react';
import {
  View, Text, ScrollView, StyleSheet,
  TouchableOpacity, ActivityIndicator, Alert, RefreshControl,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { colors, spacing, radius, typography } from '../theme';
import {
  fetchProcesses, analyzeProcesses, killProcess,
  analyzePersistence, takePersistenceBaseline, approvePersistenceChange,
  fetchUSBDevices, analyzeUSB, trustUSBDevice,
  fetchRules, setRuleEnabled, fetchPendingActions,
  confirmPendingAction, dismissPendingAction,
} from '../services/api';

const TABS = ['Processes', 'USB', 'Persistence', 'Rules'];

export default function SystemScreen() {
  const [tab, setTab] = useState('Processes');

  return (
    <SafeAreaView style={styles.safe}>
      <Text style={[typography.h2, styles.title]}>System</Text>

      <View style={styles.tabBar}>
        {TABS.map(t => (
          <TouchableOpacity
            key={t}
            style={[styles.tab, tab === t && styles.tabActive]}
            onPress={() => setTab(t)}
          >
            <Text style={[styles.tabText, tab === t && styles.tabTextActive]}>{t}</Text>
          </TouchableOpacity>
        ))}
      </View>

      {tab === 'Processes'  && <ProcessesTab />}
      {tab === 'USB'        && <USBTab />}
      {tab === 'Persistence'&& <PersistenceTab />}
      {tab === 'Rules'      && <RulesTab />}
    </SafeAreaView>
  );
}

// =============================================================================
// PROCESSES TAB
// =============================================================================
function ProcessesTab() {
  const [procs, setProcs]         = useState([]);
  const [findings, setFindings]   = useState([]);
  const [loading, setLoading]     = useState(true);
  const [scanning, setScanning]   = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError]         = useState(null);
  const [showAll, setShowAll]     = useState(false);

  const load = useCallback(async () => {
    try {
      setError(null);
      const data = await fetchProcesses();
      setProcs(data.processes || []);
    } catch {
      setError('Failed to load processes.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const runScan = async () => {
    setScanning(true);
    setError(null);
    try {
      const data = await analyzeProcesses();
      setFindings(data.findings || []);
    } catch {
      setError('Scan failed.');
    } finally {
      setScanning(false);
    }
  };

  const handleKill = (pid, name) => {
    Alert.alert(
      'Kill Process',
      `Terminate "${name}" (PID ${pid})?`,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Kill', style: 'destructive',
          onPress: async () => {
            try {
              const r = await killProcess(pid);
              if (r.success) {
                Alert.alert('Done', `Process "${r.name}" terminated.`);
                load();
              } else {
                Alert.alert('Failed', r.error || 'Could not kill process.');
              }
            } catch {
              Alert.alert('Error', 'Request failed.');
            }
          },
        },
      ]
    );
  };

  const display = showAll ? procs : procs.slice(0, 20);
  const suspicious = procs.filter(p => p.suspicious);

  if (loading) return <Loader />;

  return (
    <ScrollView
      style={styles.scroll}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={() => { setRefreshing(true); load(); }} tintColor={colors.primary} />}
    >
      {/* Summary row */}
      <View style={styles.pillRow}>
        <SummaryPill label="Total"      value={procs.length}      color={colors.primary} />
        <SummaryPill label="Suspicious" value={suspicious.length} color={colors.critical} />
        <SummaryPill label="Flagged"    value={findings.length}   color={colors.warning} />
      </View>

      {/* Scan button */}
      <TouchableOpacity style={styles.btn} onPress={runScan} disabled={scanning}>
        {scanning
          ? <ActivityIndicator color={colors.background} />
          : <Text style={styles.btnText}>🔍  Deep Scan Processes</Text>}
      </TouchableOpacity>

      {error && <Text style={styles.error}>{error}</Text>}

      {/* Threat findings */}
      {findings.length > 0 && (
        <>
          <Text style={styles.sectionTitle}>THREATS DETECTED</Text>
          {findings.map((f, i) => (
            <View key={i} style={[styles.card, styles.threatCard]}>
              <View style={styles.cardRow}>
                <View style={[styles.riskBadge, { backgroundColor: f.risk === 'critical' ? colors.critical : colors.high }]}>
                  <Text style={styles.riskText}>{f.risk?.toUpperCase()}</Text>
                </View>
                <Text style={styles.procName}>{f.name || '?'}</Text>
                <Text style={styles.procPid}>PID {f.pid}</Text>
              </View>
              {(f.reasons || []).map((r, j) => (
                <Text key={j} style={styles.reason}>• {r}</Text>
              ))}
              <TouchableOpacity style={styles.killBtn} onPress={() => handleKill(f.pid, f.name)}>
                <Text style={styles.killBtnText}>Kill Process</Text>
              </TouchableOpacity>
            </View>
          ))}
        </>
      )}

      {/* Process list */}
      <Text style={styles.sectionTitle}>RUNNING PROCESSES (top by CPU)</Text>
      {display.map(p => (
        <View key={p.pid} style={[styles.card, p.suspicious && styles.suspCard]}>
          <View style={styles.cardRow}>
            {p.suspicious && <Text style={styles.suspDot}>⚠️ </Text>}
            <Text style={[styles.procName, { flex: 1 }]} numberOfLines={1}>{p.name}</Text>
            <Text style={styles.procPid}>PID {p.pid}</Text>
          </View>
          <View style={styles.cardRow}>
            <Text style={styles.metaText}>CPU {p.cpu_percent}%</Text>
            <Text style={styles.metaText}>  MEM {p.memory_percent}%</Text>
            <Text style={[styles.metaText, { flex: 1 }]}>  {p.username}</Text>
            {p.suspicious && (
              <TouchableOpacity onPress={() => handleKill(p.pid, p.name)}>
                <Text style={styles.killSmall}>Kill</Text>
              </TouchableOpacity>
            )}
          </View>
        </View>
      ))}

      {procs.length > 20 && (
        <TouchableOpacity onPress={() => setShowAll(v => !v)} style={styles.showMore}>
          <Text style={styles.showMoreText}>{showAll ? 'Show less' : `Show all ${procs.length} processes`}</Text>
        </TouchableOpacity>
      )}

      <View style={{ height: spacing.xl }} />
    </ScrollView>
  );
}

// =============================================================================
// USB TAB
// =============================================================================
function USBTab() {
  const [devices, setDevices]     = useState([]);
  const [findings, setFindings]   = useState([]);
  const [loading, setLoading]     = useState(true);
  const [scanning, setScanning]   = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError]         = useState(null);

  const load = useCallback(async () => {
    try {
      setError(null);
      const data = await fetchUSBDevices();
      setDevices(data.devices || []);
    } catch {
      setError('Failed to load USB devices.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const runScan = async () => {
    setScanning(true);
    setError(null);
    try {
      const data = await analyzeUSB();
      setFindings(data.findings || []);
    } catch {
      setError('USB scan failed.');
    } finally {
      setScanning(false);
    }
  };

  const handleTrust = async (deviceId) => {
    try {
      await trustUSBDevice(deviceId);
      load();
    } catch {
      Alert.alert('Error', 'Could not update trust status.');
    }
  };

  if (loading) return <Loader />;

  return (
    <ScrollView
      style={styles.scroll}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={() => { setRefreshing(true); load(); }} tintColor={colors.primary} />}
    >
      <View style={styles.pillRow}>
        <SummaryPill label="Connected" value={devices.length}                        color={colors.primary} />
        <SummaryPill label="Trusted"   value={devices.filter(d => d.trusted).length} color={colors.success} />
        <SummaryPill label="Unknown"   value={devices.filter(d => !d.trusted).length}color={colors.warning} />
      </View>

      <TouchableOpacity style={styles.btn} onPress={runScan} disabled={scanning}>
        {scanning
          ? <ActivityIndicator color={colors.background} />
          : <Text style={styles.btnText}>🔌  Scan USB Devices</Text>}
      </TouchableOpacity>

      {error && <Text style={styles.error}>{error}</Text>}

      {findings.length > 0 && (
        <>
          <Text style={styles.sectionTitle}>THREATS</Text>
          {findings.map((f, i) => (
            <View key={i} style={[styles.card, styles.threatCard]}>
              <Text style={styles.procName}>{f.product_name || f.vendor || 'Unknown device'}</Text>
              <Text style={styles.reason}>Risk: {f.risk}</Text>
              {(f.reasons || []).map((r, j) => (
                <Text key={j} style={styles.reason}>• {r}</Text>
              ))}
            </View>
          ))}
        </>
      )}

      <Text style={styles.sectionTitle}>CONNECTED DEVICES</Text>
      {devices.length === 0 && (
        <Text style={styles.empty}>No USB devices detected.</Text>
      )}
      {devices.map((d, i) => (
        <View key={i} style={styles.card}>
          <View style={styles.cardRow}>
            <View style={[styles.dot, { backgroundColor: d.trusted ? colors.success : colors.warning }]} />
            <Text style={[styles.procName, { flex: 1 }]} numberOfLines={1}>
              {d.product_name || d.vendor || 'Unknown'}
            </Text>
            <TouchableOpacity
              style={[styles.trustBtn, d.trusted && styles.trustBtnActive]}
              onPress={() => handleTrust(d.device_id || d.vendor_id || String(i))}
            >
              <Text style={[styles.trustBtnText, d.trusted && styles.trustBtnTextActive]}>
                {d.trusted ? 'Trusted' : 'Trust'}
              </Text>
            </TouchableOpacity>
          </View>
          {d.vendor && <Text style={styles.metaText}>Vendor: {d.vendor}</Text>}
          {d.serial && <Text style={styles.metaText}>Serial: {d.serial}</Text>}
        </View>
      ))}

      <View style={{ height: spacing.xl }} />
    </ScrollView>
  );
}

// =============================================================================
// PERSISTENCE TAB
// =============================================================================
function PersistenceTab() {
  const [findings, setFindings]   = useState([]);
  const [scanning, setScanning]   = useState(false);
  const [baselining, setBaselining] = useState(false);
  const [error, setError]         = useState(null);
  const [lastScan, setLastScan]   = useState(null);

  const runScan = async () => {
    setScanning(true);
    setError(null);
    try {
      const data = await analyzePersistence();
      setFindings(data.findings || []);
      setLastScan(new Date().toLocaleTimeString());
    } catch {
      setError('Persistence scan failed.');
    } finally {
      setScanning(false);
    }
  };

  const runBaseline = async () => {
    Alert.alert(
      'Take Baseline',
      'This records current state of all watched files. Run only after verifying your system is clean.',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Take Baseline', onPress: async () => {
            setBaselining(true);
            try {
              await takePersistenceBaseline();
              Alert.alert('Done', 'Persistence baseline recorded.');
              setFindings([]);
            } catch {
              Alert.alert('Error', 'Failed to take baseline.');
            } finally {
              setBaselining(false);
            }
          },
        },
      ]
    );
  };

  const handleApprove = async (path) => {
    try {
      await approvePersistenceChange(path);
      setFindings(prev => prev.filter(f => f.path !== path));
    } catch {
      Alert.alert('Error', 'Failed to approve change.');
    }
  };

  const RISK_COLOR = { critical: colors.critical, high: colors.high, medium: colors.warning, low: colors.info };

  return (
    <ScrollView style={styles.scroll}>
      <Text style={styles.desc}>
        Monitors LaunchAgents, /etc/hosts, authorized_keys, shell configs, and sudoers for unauthorized changes.
      </Text>

      <View style={styles.buttonRow}>
        <TouchableOpacity style={[styles.btn, { flex: 1, marginRight: spacing.sm }]} onPress={runScan} disabled={scanning}>
          {scanning
            ? <ActivityIndicator color={colors.background} />
            : <Text style={styles.btnText}>🔍  Scan</Text>}
        </TouchableOpacity>
        <TouchableOpacity style={[styles.btnSecondary, { flex: 1 }]} onPress={runBaseline} disabled={baselining}>
          {baselining
            ? <ActivityIndicator color={colors.primary} />
            : <Text style={styles.btnSecondaryText}>📸  Baseline</Text>}
        </TouchableOpacity>
      </View>

      {lastScan && <Text style={styles.lastScan}>Last scan: {lastScan}</Text>}
      {error && <Text style={styles.error}>{error}</Text>}

      {findings.length === 0 && lastScan && (
        <Text style={styles.clean}>✅  No persistence changes detected.</Text>
      )}

      {findings.map((f, i) => (
        <View key={i} style={[styles.card, { borderLeftWidth: 3, borderLeftColor: RISK_COLOR[f.risk] || colors.border }]}>
          <View style={styles.cardRow}>
            <View style={[styles.riskBadge, { backgroundColor: RISK_COLOR[f.risk] || colors.border }]}>
              <Text style={styles.riskText}>{f.risk?.toUpperCase()}</Text>
            </View>
            <Text style={[styles.procName, { flex: 1 }]} numberOfLines={1}>{f.path}</Text>
          </View>
          <Text style={styles.metaText}>{f.change_type}: {f.details || f.description || ''}</Text>
          {f.timestamp && <Text style={styles.metaText}>{new Date(f.timestamp).toLocaleString()}</Text>}
          <TouchableOpacity style={styles.approveBtn} onPress={() => handleApprove(f.path)}>
            <Text style={styles.approveBtnText}>Approve Change</Text>
          </TouchableOpacity>
        </View>
      ))}

      <View style={{ height: spacing.xl }} />
    </ScrollView>
  );
}

// =============================================================================
// RULES TAB
// =============================================================================
function RulesTab() {
  const [rules, setRules]         = useState([]);
  const [pending, setPending]     = useState([]);
  const [loading, setLoading]     = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError]         = useState(null);

  const load = useCallback(async () => {
    try {
      setError(null);
      const [rData, pData] = await Promise.all([fetchRules(), fetchPendingActions()]);
      setRules(rData.rules || []);
      setPending(pData.pending || []);
    } catch {
      setError('Failed to load rules engine data.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const toggleRule = async (ruleId, currentEnabled) => {
    try {
      await setRuleEnabled(ruleId, !currentEnabled);
      setRules(prev => prev.map(r => r.id === ruleId ? { ...r, enabled: !currentEnabled } : r));
    } catch {
      Alert.alert('Error', 'Could not update rule.');
    }
  };

  const handleConfirm = async (actionId) => {
    try {
      await confirmPendingAction(actionId);
      setPending(prev => prev.filter(p => p.id !== actionId));
    } catch {
      Alert.alert('Error', 'Failed to confirm action.');
    }
  };

  const handleDismiss = async (actionId) => {
    try {
      await dismissPendingAction(actionId);
      setPending(prev => prev.filter(p => p.id !== actionId));
    } catch {
      Alert.alert('Error', 'Failed to dismiss action.');
    }
  };

  if (loading) return <Loader />;

  return (
    <ScrollView
      style={styles.scroll}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={() => { setRefreshing(true); load(); }} tintColor={colors.primary} />}
    >
      {error && <Text style={styles.error}>{error}</Text>}

      {/* Pending Actions */}
      {pending.length > 0 && (
        <>
          <Text style={styles.sectionTitle}>PENDING ACTIONS ({pending.length})</Text>
          {pending.map((p, i) => (
            <View key={`pending-${p.id ?? i}-${i}`} style={[styles.card, styles.threatCard]}>
              <Text style={styles.procName}>{p.action_type?.replace(/_/g, ' ').toUpperCase()}</Text>
              <Text style={styles.reason}>Rule: {p.rule_name || p.rule_id}</Text>
              {p.target && <Text style={styles.metaText}>Target: {p.target}</Text>}
              {p.created_at && <Text style={styles.metaText}>{new Date(p.created_at).toLocaleString()}</Text>}
              <View style={styles.buttonRow}>
                <TouchableOpacity style={[styles.btn, { flex: 1, marginRight: spacing.sm, paddingVertical: 8 }]} onPress={() => handleConfirm(p.id)}>
                  <Text style={styles.btnText}>Confirm</Text>
                </TouchableOpacity>
                <TouchableOpacity style={[styles.btnDanger, { flex: 1, paddingVertical: 8 }]} onPress={() => handleDismiss(p.id)}>
                  <Text style={styles.btnDangerText}>Dismiss</Text>
                </TouchableOpacity>
              </View>
            </View>
          ))}
        </>
      )}

      {/* Rules list */}
      <Text style={styles.sectionTitle}>RESPONSE RULES</Text>
      {rules.length === 0 && (
        <Text style={styles.empty}>No rules loaded. Check server configuration.</Text>
      )}
      {rules.map((rule, i) => (
        <View key={`rule-${rule.id ?? rule.name ?? i}-${i}`} style={styles.card}>
          <View style={styles.cardRow}>
            <View style={[styles.dot, { backgroundColor: rule.enabled ? colors.success : colors.border }]} />
            <View style={{ flex: 1 }}>
              <Text style={styles.procName}>{rule.name || rule.id}</Text>
              {rule.description && (
                <Text style={styles.metaText} numberOfLines={2}>{rule.description}</Text>
              )}
            </View>
            <TouchableOpacity
              style={[styles.toggleBtn, rule.enabled && styles.toggleBtnOn]}
              onPress={() => toggleRule(rule.id, rule.enabled)}
            >
              <Text style={[styles.toggleBtnText, rule.enabled && styles.toggleBtnTextOn]}>
                {rule.enabled ? 'ON' : 'OFF'}
              </Text>
            </TouchableOpacity>
          </View>
          {rule.actions && rule.actions.length > 0 && (
            <Text style={styles.metaText}>Actions: {rule.actions.join(', ')}</Text>
          )}
          {rule.requires_confirmation && (
            <Text style={[styles.metaText, { color: colors.warning }]}>⚠️  Requires manual confirmation</Text>
          )}
        </View>
      ))}

      <View style={{ height: spacing.xl }} />
    </ScrollView>
  );
}

// =============================================================================
// Shared sub-components
// =============================================================================
function Loader() {
  return (
    <View style={styles.center}>
      <ActivityIndicator color={colors.primary} size="large" />
    </View>
  );
}

function SummaryPill({ label, value, color }) {
  return (
    <View style={styles.pill}>
      <Text style={[styles.pillValue, { color }]}>{value}</Text>
      <Text style={styles.pillLabel}>{label}</Text>
    </View>
  );
}

// =============================================================================
// Styles
// =============================================================================
const styles = StyleSheet.create({
  safe:              { flex: 1, backgroundColor: colors.background },
  title:             { paddingHorizontal: spacing.md, paddingTop: spacing.lg, paddingBottom: spacing.sm },
  tabBar:            { flexDirection: 'row', paddingHorizontal: spacing.md, marginBottom: spacing.md },
  tab:               { flex: 1, paddingVertical: 8, alignItems: 'center', borderBottomWidth: 2, borderBottomColor: colors.border },
  tabActive:         { borderBottomColor: colors.primary },
  tabText:           { fontSize: 11, fontWeight: '600', color: colors.textMuted },
  tabTextActive:     { color: colors.primary },
  scroll:            { flex: 1, paddingHorizontal: spacing.md },
  center:            { flex: 1, alignItems: 'center', justifyContent: 'center', paddingTop: spacing.xl * 2 },
  desc:              { fontSize: 13, color: colors.textMuted, marginBottom: spacing.md, lineHeight: 18 },
  sectionTitle:      { fontSize: 11, fontWeight: '700', color: colors.textMuted, letterSpacing: 1, marginBottom: spacing.sm, marginTop: spacing.md },
  pillRow:           { flexDirection: 'row', marginBottom: spacing.md },
  pill:              { flex: 1, backgroundColor: colors.card, borderRadius: radius.sm, padding: spacing.sm, alignItems: 'center', marginRight: spacing.xs },
  pillValue:         { fontSize: 20, fontWeight: '700' },
  pillLabel:         { fontSize: 10, color: colors.textMuted, marginTop: 2 },
  btn:               { backgroundColor: colors.primary, borderRadius: radius.md, padding: spacing.md, alignItems: 'center', marginBottom: spacing.md },
  btnText:           { color: colors.background, fontWeight: '700', fontSize: 14 },
  btnSecondary:      { borderWidth: 1, borderColor: colors.primary, borderRadius: radius.md, padding: spacing.md, alignItems: 'center', marginBottom: spacing.md },
  btnSecondaryText:  { color: colors.primary, fontWeight: '700', fontSize: 14 },
  btnDanger:         { backgroundColor: '#2d0a14', borderRadius: radius.md, padding: spacing.md, alignItems: 'center' },
  btnDangerText:     { color: colors.critical, fontWeight: '700', fontSize: 14 },
  buttonRow:         { flexDirection: 'row', marginBottom: spacing.sm },
  error:             { color: colors.critical, fontSize: 13, marginBottom: spacing.sm },
  clean:             { color: colors.success, fontSize: 14, textAlign: 'center', paddingVertical: spacing.lg },
  empty:             { color: colors.textMuted, fontSize: 13, textAlign: 'center', paddingVertical: spacing.md },
  lastScan:          { fontSize: 11, color: colors.textMuted, textAlign: 'center', marginBottom: spacing.md },
  card:              { backgroundColor: colors.card, borderRadius: radius.md, padding: spacing.md, marginBottom: spacing.sm },
  threatCard:        { borderWidth: 1, borderColor: colors.critical + '44' },
  suspCard:          { borderWidth: 1, borderColor: colors.warning + '44' },
  cardRow:           { flexDirection: 'row', alignItems: 'center', marginBottom: 4 },
  dot:               { width: 8, height: 8, borderRadius: 4, marginRight: spacing.sm },
  riskBadge:         { paddingHorizontal: 7, paddingVertical: 2, borderRadius: 4, marginRight: spacing.sm },
  riskText:          { fontSize: 9, fontWeight: '700', color: '#fff' },
  procName:          { fontSize: 13, fontWeight: '600', color: colors.textPrimary },
  procPid:           { fontSize: 11, color: colors.textMuted, marginLeft: spacing.sm },
  reason:            { fontSize: 12, color: colors.textSecondary, marginTop: 2 },
  metaText:          { fontSize: 11, color: colors.textMuted, marginTop: 2 },
  suspDot:           { fontSize: 14, marginRight: 4 },
  killBtn:           { marginTop: spacing.sm, backgroundColor: '#2d0a14', borderRadius: radius.sm, paddingVertical: 6, alignItems: 'center' },
  killBtnText:       { color: colors.critical, fontWeight: '700', fontSize: 12 },
  killSmall:         { color: colors.critical, fontSize: 11, fontWeight: '700' },
  approveBtn:        { marginTop: spacing.sm, borderWidth: 1, borderColor: colors.success, borderRadius: radius.sm, paddingVertical: 6, alignItems: 'center' },
  approveBtnText:    { color: colors.success, fontWeight: '700', fontSize: 12 },
  trustBtn:          { borderWidth: 1, borderColor: colors.border, borderRadius: 6, paddingHorizontal: 10, paddingVertical: 4 },
  trustBtnActive:    { borderColor: colors.success, backgroundColor: colors.success + '22' },
  trustBtnText:      { fontSize: 11, fontWeight: '600', color: colors.textMuted },
  trustBtnTextActive:{ color: colors.success },
  showMore:          { alignItems: 'center', paddingVertical: spacing.md },
  showMoreText:      { color: colors.primary, fontSize: 13 },
  toggleBtn:         { borderWidth: 1, borderColor: colors.border, borderRadius: 6, paddingHorizontal: 12, paddingVertical: 5 },
  toggleBtnOn:       { borderColor: colors.success, backgroundColor: colors.success + '22' },
  toggleBtnText:     { fontSize: 11, fontWeight: '700', color: colors.textMuted },
  toggleBtnTextOn:   { color: colors.success },
});
