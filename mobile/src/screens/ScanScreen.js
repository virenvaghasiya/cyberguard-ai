import React, { useState } from 'react';
import {
  View, Text, ScrollView, StyleSheet, TouchableOpacity,
  TextInput, ActivityIndicator, KeyboardAvoidingView, Platform,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { colors, spacing, radius, typography } from '../theme';
import FindingCard from '../components/FindingCard';
import { scanLog, scanVulnerability, scanDemoEmails, scanSignature, scanFile } from '../services/api';

const TABS = ['Email', 'Log', 'Vuln', 'Sig', 'File'];

export default function ScanScreen() {
  const [tab, setTab] = useState('Email');

  return (
    <SafeAreaView style={styles.safe}>
      <Text style={[typography.h2, styles.title]}>Scanner</Text>

      {/* Tab bar */}
      <View style={styles.tabBar}>
        {TABS.map(t => (
          <TouchableOpacity key={t} style={[styles.tab, tab === t && styles.tabActive]} onPress={() => setTab(t)}>
            <Text style={[styles.tabText, tab === t && styles.tabTextActive]}>{t}</Text>
          </TouchableOpacity>
        ))}
      </View>

      {tab === 'Email' && <EmailTab />}
      {tab === 'Log'   && <LogTab />}
      {tab === 'Vuln'  && <VulnTab />}
      {tab === 'Sig'   && <SigTab />}
      {tab === 'File'  && <FileTab />}
    </SafeAreaView>
  );
}

// ---------------------------------------------------------------------------
// Email scanner tab
// ---------------------------------------------------------------------------
function EmailTab() {
  const [running, setRunning] = useState(false);
  const [result, setResult]   = useState(null);
  const [error, setError]     = useState(null);

  const runDemo = async () => {
    setRunning(true); setError(null); setResult(null);
    try {
      const r = await scanDemoEmails();
      setResult(r);
    } catch { setError('Failed to scan emails.'); }
    finally  { setRunning(false); }
  };

  const VERDICT_COLOR = { safe: colors.success, caution: colors.warning, warning: colors.warning, danger: colors.critical };

  return (
    <KeyboardAvoidingView style={styles.flex} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
      <ScrollView style={styles.scroll}>
        <Text style={styles.desc}>Scan emails for phishing indicators using AI-powered detection.</Text>

        <TouchableOpacity style={styles.btn} onPress={runDemo} disabled={running}>
          {running ? <ActivityIndicator color={colors.background} /> : <Text style={styles.btnText}>📧  Scan Demo Emails</Text>}
        </TouchableOpacity>

        {error && <Text style={styles.error}>{error}</Text>}

        {result && (
          <>
            <View style={styles.summaryRow}>
              <SummaryPill label="Total"      value={result.total_scanned}    color={colors.primary} />
              <SummaryPill label="Safe"       value={result.safe_count}       color={colors.success} />
              <SummaryPill label="Suspicious" value={result.suspicious_count} color={colors.warning} />
              <SummaryPill label="Dangerous"  value={result.dangerous_count}  color={colors.critical} />
            </View>

            {(result.results || []).map((r, i) => (
              <View key={i} style={styles.emailCard}>
                <View style={styles.emailHeader}>
                  <Text style={styles.emailSubject} numberOfLines={1}>{r.subject || '(no subject)'}</Text>
                  <Text style={[styles.verdict, { color: VERDICT_COLOR[r.verdict] || colors.textMuted }]}>
                    {r.verdict?.toUpperCase()}
                  </Text>
                </View>
                <Text style={styles.emailFrom}>{r.sender_email || r.sender_name || 'Unknown sender'}</Text>
                <View style={styles.scoreRow}>
                  <Text style={styles.scoreLabel}>Phishing score</Text>
                  <View style={styles.scoreBar}>
                    <View style={[styles.scoreFill, {
                      width: `${Math.min(100, (r.phishing_score || 0) * 100)}%`,
                      backgroundColor: r.phishing_score > 0.7 ? colors.critical : r.phishing_score > 0.4 ? colors.warning : colors.success,
                    }]} />
                  </View>
                  <Text style={styles.scoreValue}>{Math.round((r.phishing_score || 0) * 100)}%</Text>
                </View>
              </View>
            ))}
          </>
        )}
        <View style={{ height: spacing.xl }} />
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

// ---------------------------------------------------------------------------
// Log analyzer tab
// ---------------------------------------------------------------------------
function LogTab() {
  const [text, setText]       = useState('');
  const [logType, setLogType] = useState('auto');
  const [running, setRunning] = useState(false);
  const [result, setResult]   = useState(null);
  const [error, setError]     = useState(null);

  const LOG_TYPES = ['auto', 'auth', 'web'];

  const run = async () => {
    if (!text.trim()) return;
    setRunning(true); setError(null); setResult(null);
    try {
      const r = await scanLog(text, logType);
      setResult(r);
    } catch { setError('Failed to analyze log.'); }
    finally  { setRunning(false); }
  };

  return (
    <KeyboardAvoidingView style={styles.flex} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
      <ScrollView style={styles.scroll}>
        <Text style={styles.desc}>Paste log content to detect security threats.</Text>

        <View style={styles.typeRow}>
          {LOG_TYPES.map(t => (
            <TouchableOpacity key={t} style={[styles.typePill, logType === t && styles.typePillActive]} onPress={() => setLogType(t)}>
              <Text style={[styles.typePillText, logType === t && styles.typePillTextActive]}>{t.toUpperCase()}</Text>
            </TouchableOpacity>
          ))}
        </View>

        <TextInput
          style={styles.textInput}
          multiline
          numberOfLines={8}
          placeholder="Paste log content here..."
          placeholderTextColor={colors.textMuted}
          value={text}
          onChangeText={setText}
          autoCapitalize="none"
          autoCorrect={false}
        />

        <TouchableOpacity style={[styles.btn, !text.trim() && styles.btnDisabled]} onPress={run} disabled={running || !text.trim()}>
          {running ? <ActivityIndicator color={colors.background} /> : <Text style={styles.btnText}>🔍  Analyze Log</Text>}
        </TouchableOpacity>

        {error && <Text style={styles.error}>{error}</Text>}

        {result && (
          <>
            <View style={styles.summaryRow}>
              <SummaryPill label="Findings"  value={result.total_findings} color={colors.primary} />
              <SummaryPill label="Critical"  value={result.critical}       color={colors.critical} />
              <SummaryPill label="High"      value={result.high}           color={colors.high} />
              <SummaryPill label="Medium"    value={result.medium}         color={colors.warning} />
            </View>
            {result.total_findings === 0 && (
              <Text style={styles.clean}>✅  No threats detected in this log.</Text>
            )}
            {(result.findings || []).map((f, i) => <FindingCard key={i} finding={f} />)}
          </>
        )}
        <View style={{ height: spacing.xl }} />
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

// ---------------------------------------------------------------------------
// Vulnerability scanner tab
// ---------------------------------------------------------------------------
function VulnTab() {
  const [target, setTarget] = useState('');
  const [running, setRunning] = useState(false);
  const [result, setResult]   = useState(null);
  const [error, setError]     = useState(null);

  const run = async () => {
    if (!target.trim()) return;
    setRunning(true); setError(null); setResult(null);
    try {
      const r = await scanVulnerability(target.trim(), null, 1.0);
      setResult(r);
    } catch { setError('Scan failed. Check the target and server connection.'); }
    finally  { setRunning(false); }
  };

  return (
    <KeyboardAvoidingView style={styles.flex} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
      <ScrollView style={styles.scroll}>
        <Text style={styles.desc}>Scan a host or network for open and dangerous ports.</Text>

        <TextInput
          style={styles.input}
          placeholder="IP, hostname, or CIDR (e.g. 192.168.1.1)"
          placeholderTextColor={colors.textMuted}
          value={target}
          onChangeText={setTarget}
          autoCapitalize="none"
          autoCorrect={false}
          keyboardType="default"
        />

        <TouchableOpacity style={[styles.btn, !target.trim() && styles.btnDisabled]} onPress={run} disabled={running || !target.trim()}>
          {running ? <ActivityIndicator color={colors.background} /> : <Text style={styles.btnText}>🛡️  Start Vulnerability Scan</Text>}
        </TouchableOpacity>

        {running && (
          <View style={styles.scanningCard}>
            <ActivityIndicator color={colors.primary} style={{ marginBottom: spacing.sm }} />
            <Text style={styles.scanningText}>Scanning ports on {target}...</Text>
            <Text style={styles.scanningSubtext}>This may take up to 30 seconds</Text>
          </View>
        )}

        {error && <Text style={styles.error}>{error}</Text>}

        {result && (
          <>
            <View style={styles.summaryRow}>
              <SummaryPill label="Findings" value={result.total_findings} color={colors.primary} />
              <SummaryPill label="Critical" value={result.critical}       color={colors.critical} />
              <SummaryPill label="High"     value={result.high}           color={colors.high} />
              <SummaryPill label="Medium"   value={result.medium}         color={colors.warning} />
            </View>
            {result.total_findings === 0 && (
              <Text style={styles.clean}>✅  No vulnerabilities found on {result.target}.</Text>
            )}
            {(result.findings || []).map((f, i) => <FindingCard key={i} finding={f} />)}
          </>
        )}
        <View style={{ height: spacing.xl }} />
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

// ---------------------------------------------------------------------------
// Signature scanner tab
// ---------------------------------------------------------------------------
function SigTab() {
  const [text, setText]       = useState('');
  const [running, setRunning] = useState(false);
  const [result, setResult]   = useState(null);
  const [error, setError]     = useState(null);

  const run = async () => {
    if (!text.trim()) return;
    setRunning(true); setError(null); setResult(null);
    try {
      const r = await scanSignature(text);
      setResult(r);
    } catch { setError('Signature scan failed.'); }
    finally  { setRunning(false); }
  };

  const RISK_COLOR = { critical: '#ff3b30', high: '#ff9500', medium: '#ffcc00', low: '#34c759' };

  return (
    <KeyboardAvoidingView style={styles.flex} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
      <ScrollView style={styles.scroll}>
        <Text style={styles.desc}>Detect SQLi, XSS, RCE, C2, web shells, and 200+ other attack patterns in any text.</Text>

        <TextInput
          style={styles.textInput}
          multiline
          numberOfLines={8}
          placeholder="Paste request payload, log line, or any text..."
          placeholderTextColor={colors.textMuted}
          value={text}
          onChangeText={setText}
          autoCapitalize="none"
          autoCorrect={false}
        />

        <TouchableOpacity style={[styles.btn, !text.trim() && styles.btnDisabled]} onPress={run} disabled={running || !text.trim()}>
          {running ? <ActivityIndicator color={colors.background} /> : <Text style={styles.btnText}>🧬  Run Signature Scan</Text>}
        </TouchableOpacity>

        {error && <Text style={styles.error}>{error}</Text>}

        {result && (
          <>
            <View style={styles.summaryRow}>
              <SummaryPill label="Matches"  value={result.total_matches || result.matches?.length || 0} color={colors.primary} />
              <SummaryPill label="Critical" value={(result.matches || []).filter(m => m.severity === 'critical').length} color={colors.critical} />
              <SummaryPill label="High"     value={(result.matches || []).filter(m => m.severity === 'high').length}     color={colors.high} />
            </View>
            {(result.matches || []).length === 0 && (
              <Text style={styles.clean}>✅  No attack signatures detected.</Text>
            )}
            {(result.matches || []).map((m, i) => (
              <View key={i} style={[styles.sigCard, { borderLeftColor: RISK_COLOR[m.severity] || colors.border }]}>
                <View style={{ flexDirection: 'row', justifyContent: 'space-between' }}>
                  <Text style={{ fontSize: 13, fontWeight: '700', color: colors.textPrimary, flex: 1 }}>{m.rule_name || m.pattern_name}</Text>
                  <Text style={{ fontSize: 11, fontWeight: '700', color: RISK_COLOR[m.severity] || colors.textMuted }}>
                    {m.severity?.toUpperCase()}
                  </Text>
                </View>
                {m.category && <Text style={{ fontSize: 11, color: colors.textMuted, marginTop: 2 }}>Category: {m.category}</Text>}
                {m.match && (
                  <Text style={{ fontSize: 11, color: colors.textSecondary, fontFamily: 'monospace', marginTop: 4 }} numberOfLines={2}>
                    {m.match}
                  </Text>
                )}
              </View>
            ))}
          </>
        )}
        <View style={{ height: spacing.xl }} />
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

// ---------------------------------------------------------------------------
// File scanner tab
// ---------------------------------------------------------------------------
function FileTab() {
  const [path, setPath]       = useState('');
  const [running, setRunning] = useState(false);
  const [result, setResult]   = useState(null);
  const [error, setError]     = useState(null);

  const run = async () => {
    if (!path.trim()) return;
    setRunning(true); setError(null); setResult(null);
    try {
      const r = await scanFile(path.trim());
      setResult(r);
    } catch { setError('File scan failed. Check the path and server connection.'); }
    finally  { setRunning(false); }
  };

  const VERDICT_COLOR = { clean: colors.success, suspicious: colors.warning, malicious: colors.critical };

  return (
    <KeyboardAvoidingView style={styles.flex} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
      <ScrollView style={styles.scroll}>
        <Text style={styles.desc}>Scan a file for malware hash matches, static analysis patterns, and VirusTotal detections.</Text>

        <TextInput
          style={styles.input}
          placeholder="/path/to/file or ~/Downloads/suspicious.sh"
          placeholderTextColor={colors.textMuted}
          value={path}
          onChangeText={setPath}
          autoCapitalize="none"
          autoCorrect={false}
        />

        <TouchableOpacity style={[styles.btn, !path.trim() && styles.btnDisabled]} onPress={run} disabled={running || !path.trim()}>
          {running ? <ActivityIndicator color={colors.background} /> : <Text style={styles.btnText}>📁  Scan File</Text>}
        </TouchableOpacity>

        {error && <Text style={styles.error}>{error}</Text>}

        {result && (
          <>
            <View style={[styles.verdictBanner, { backgroundColor: (VERDICT_COLOR[result.verdict] || colors.info) + '22' }]}>
              <Text style={[styles.verdictLabel, { color: VERDICT_COLOR[result.verdict] || colors.info }]}>
                {result.verdict?.toUpperCase() || 'UNKNOWN'}
              </Text>
              <Text style={styles.verdictPath} numberOfLines={1}>{result.path || path}</Text>
            </View>

            <View style={styles.summaryRow}>
              <SummaryPill label="VT Hits"  value={result.vt_positives ?? '—'}      color={result.vt_positives > 0 ? colors.critical : colors.success} />
              <SummaryPill label="Patterns" value={result.static_matches?.length || 0} color={colors.warning} />
              <SummaryPill label="Hash DB"  value={result.hash_match ? 'HIT' : 'OK'} color={result.hash_match ? colors.critical : colors.success} />
            </View>

            {(result.static_matches || []).map((m, i) => (
              <View key={i} style={styles.sigCard}>
                <Text style={{ fontSize: 13, fontWeight: '600', color: colors.textPrimary }}>{m.pattern}</Text>
                {m.line_number && <Text style={{ fontSize: 11, color: colors.textMuted }}>Line {m.line_number}</Text>}
                {m.context && (
                  <Text style={{ fontSize: 11, fontFamily: 'monospace', color: colors.textSecondary, marginTop: 2 }} numberOfLines={2}>
                    {m.context}
                  </Text>
                )}
              </View>
            ))}

            {result.vt_report && (
              <View style={styles.sigCard}>
                <Text style={{ fontSize: 12, fontWeight: '600', color: colors.textSecondary }}>VirusTotal</Text>
                <Text style={{ fontSize: 11, color: colors.textMuted, marginTop: 2 }}>
                  {result.vt_positives} / {result.vt_total} engines detected
                </Text>
              </View>
            )}
          </>
        )}
        <View style={{ height: spacing.xl }} />
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

// ---------------------------------------------------------------------------
// Shared sub-components
// ---------------------------------------------------------------------------
function SummaryPill({ label, value, color }) {
  return (
    <View style={styles.pill}>
      <Text style={[styles.pillValue, { color }]}>{value}</Text>
      <Text style={styles.pillLabel}>{label}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: colors.background },
  flex: { flex: 1 },
  title: { paddingHorizontal: spacing.md, paddingTop: spacing.lg, paddingBottom: spacing.sm },
  tabBar: { flexDirection: 'row', paddingHorizontal: spacing.md, marginBottom: spacing.md },
  tab: { flex: 1, paddingVertical: 8, alignItems: 'center', borderBottomWidth: 2, borderBottomColor: colors.border },
  tabActive: { borderBottomColor: colors.primary },
  tabText: { fontSize: 13, fontWeight: '600', color: colors.textMuted },
  tabTextActive: { color: colors.primary },
  scroll: { flex: 1, paddingHorizontal: spacing.md },
  desc: { fontSize: 13, color: colors.textMuted, marginBottom: spacing.md, lineHeight: 18 },
  btn: { backgroundColor: colors.primary, borderRadius: radius.md, padding: spacing.md, alignItems: 'center', marginBottom: spacing.md },
  btnDisabled: { opacity: 0.4 },
  btnText: { color: colors.background, fontWeight: '700', fontSize: 14 },
  error: { color: colors.critical, fontSize: 13, marginBottom: spacing.sm },
  clean: { color: colors.success, fontSize: 14, textAlign: 'center', paddingVertical: spacing.lg },
  summaryRow: { flexDirection: 'row', marginBottom: spacing.md },
  pill: { flex: 1, backgroundColor: colors.card, borderRadius: radius.sm, padding: spacing.sm, alignItems: 'center', marginRight: spacing.xs },
  pillValue: { fontSize: 20, fontWeight: '700' },
  pillLabel: { fontSize: 10, color: colors.textMuted, marginTop: 2 },
  textInput: { backgroundColor: colors.card, borderRadius: radius.md, padding: spacing.md, color: colors.textPrimary, fontSize: 12, fontFamily: 'monospace', minHeight: 140, textAlignVertical: 'top', marginBottom: spacing.md, borderWidth: 1, borderColor: colors.border },
  input: { backgroundColor: colors.card, borderRadius: radius.md, padding: spacing.md, color: colors.textPrimary, fontSize: 14, marginBottom: spacing.md, borderWidth: 1, borderColor: colors.border },
  typeRow: { flexDirection: 'row', marginBottom: spacing.sm },
  typePill: { paddingHorizontal: 12, paddingVertical: 5, borderRadius: 20, borderWidth: 1, borderColor: colors.border, marginRight: 6 },
  typePillActive: { backgroundColor: colors.primary, borderColor: colors.primary },
  typePillText: { fontSize: 11, fontWeight: '600', color: colors.textMuted },
  typePillTextActive: { color: colors.background },
  scanningCard: { backgroundColor: colors.card, borderRadius: radius.md, padding: spacing.lg, alignItems: 'center', marginBottom: spacing.md },
  scanningText: { fontSize: 13, color: colors.textSecondary },
  scanningSubtext: { fontSize: 11, color: colors.textMuted, marginTop: 4 },
  emailCard: { backgroundColor: colors.card, borderRadius: radius.md, padding: spacing.md, marginBottom: spacing.sm },
  emailHeader: { flexDirection: 'row', justifyContent: 'space-between', marginBottom: 4 },
  emailSubject: { flex: 1, fontSize: 13, fontWeight: '600', color: colors.textPrimary },
  verdict: { fontSize: 11, fontWeight: '700', marginLeft: spacing.sm },
  emailFrom: { fontSize: 11, color: colors.textMuted, marginBottom: spacing.sm },
  scoreRow: { flexDirection: 'row', alignItems: 'center' },
  scoreLabel: { fontSize: 11, color: colors.textMuted, width: 85 },
  scoreBar: { flex: 1, height: 6, backgroundColor: colors.border, borderRadius: 3, overflow: 'hidden', marginHorizontal: spacing.sm },
  scoreFill: { height: '100%', borderRadius: 3 },
  scoreValue: { fontSize: 11, color: colors.textPrimary, width: 32, textAlign: 'right' },
  sigCard: { backgroundColor: colors.card, borderRadius: radius.md, padding: spacing.md, marginBottom: spacing.sm, borderLeftWidth: 3, borderLeftColor: colors.border },
  verdictBanner: { borderRadius: radius.md, padding: spacing.md, marginBottom: spacing.md, alignItems: 'center' },
  verdictLabel: { fontSize: 22, fontWeight: '800', marginBottom: 4 },
  verdictPath: { fontSize: 11, color: colors.textMuted },
});
