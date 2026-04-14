import React, { useState, useEffect } from 'react';
import {
  View, Text, ScrollView, StyleSheet, TextInput,
  TouchableOpacity, ActivityIndicator, Switch,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { colors, spacing, radius, typography } from '../theme';
import { login, logout, fetchHealth } from '../services/api';

export default function SettingsScreen() {
  const [serverUrl, setServerUrl]   = useState('http://localhost:8000');
  const [username, setUsername]     = useState('admin');
  const [password, setPassword]     = useState('');
  const [token, setToken]           = useState(null);
  const [testing, setTesting]       = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [saving, setSaving]         = useState(false);
  const [loggingIn, setLoggingIn]   = useState(false);

  useEffect(() => {
    AsyncStorage.multiGet(['serverUrl', 'authToken', 'savedUsername']).then(pairs => {
      const map = Object.fromEntries(pairs);
      if (map.serverUrl) setServerUrl(map.serverUrl);
      if (map.authToken) setToken(map.authToken);
      if (map.savedUsername) setUsername(map.savedUsername);
    });
  }, []);

  const saveUrl = async () => {
    setSaving(true);
    await AsyncStorage.setItem('serverUrl', serverUrl.trim());
    setSaving(false);
    setTestResult({ ok: null, msg: 'Server URL saved.' });
  };

  const testConnection = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const h = await fetchHealth();
      setTestResult({ ok: true, msg: `Connected ✓  — ${h.detectors.length} detectors, ${h.websocket_clients} WS clients` });
    } catch (e) {
      setTestResult({ ok: false, msg: `Failed: ${e.message}` });
    } finally {
      setTesting(false);
    }
  };

  const handleLogin = async () => {
    setLoggingIn(true);
    setTestResult(null);
    try {
      await login(username, password);
      const t = await AsyncStorage.getItem('authToken');
      setToken(t);
      await AsyncStorage.setItem('savedUsername', username);
      setPassword('');
      setTestResult({ ok: true, msg: 'Logged in successfully.' });
    } catch {
      setTestResult({ ok: false, msg: 'Login failed. Check credentials.' });
    } finally {
      setLoggingIn(false);
    }
  };

  const handleLogout = async () => {
    await logout();
    setToken(null);
    setTestResult({ ok: null, msg: 'Logged out.' });
  };

  return (
    <SafeAreaView style={styles.safe}>
      <ScrollView style={styles.scroll}>
        <Text style={[typography.h2, styles.title]}>Settings</Text>

        {/* Server config */}
        <Text style={styles.section}>SERVER</Text>
        <View style={styles.card}>
          <Text style={styles.label}>Backend URL</Text>
          <TextInput
            style={styles.input}
            value={serverUrl}
            onChangeText={setServerUrl}
            placeholder="http://localhost:8000"
            placeholderTextColor={colors.textMuted}
            autoCapitalize="none"
            autoCorrect={false}
            keyboardType="url"
          />
          <Text style={styles.hint}>
            On your iPhone, use your Mac's local IP instead of localhost.{'\n'}
            Find it: System Settings → Wi-Fi → your network → IP Address
          </Text>
          <View style={styles.btnRow}>
            <TouchableOpacity style={[styles.btn, styles.btnSecondary, { flex: 1, marginRight: spacing.sm }]} onPress={saveUrl} disabled={saving}>
              <Text style={styles.btnSecondaryText}>{saving ? 'Saving…' : 'Save URL'}</Text>
            </TouchableOpacity>
            <TouchableOpacity style={[styles.btn, { flex: 1 }]} onPress={testConnection} disabled={testing}>
              {testing ? <ActivityIndicator color={colors.background} size="small" /> : <Text style={styles.btnText}>Test Connection</Text>}
            </TouchableOpacity>
          </View>
        </View>

        {/* Auth */}
        <Text style={styles.section}>AUTHENTICATION</Text>
        <View style={styles.card}>
          {token ? (
            <>
              <View style={styles.loggedInRow}>
                <View style={[styles.dot, { backgroundColor: colors.success }]} />
                <Text style={styles.loggedInText}>Logged in as {username}</Text>
              </View>
              <TouchableOpacity style={[styles.btn, styles.btnDanger, { marginTop: spacing.sm }]} onPress={handleLogout}>
                <Text style={styles.btnText}>Log Out</Text>
              </TouchableOpacity>
            </>
          ) : (
            <>
              <Text style={styles.label}>Username</Text>
              <TextInput style={styles.input} value={username} onChangeText={setUsername} autoCapitalize="none" placeholderTextColor={colors.textMuted} />
              <Text style={[styles.label, { marginTop: spacing.sm }]}>Password</Text>
              <TextInput style={styles.input} value={password} onChangeText={setPassword} secureTextEntry placeholder="••••••••" placeholderTextColor={colors.textMuted} />
              <TouchableOpacity style={[styles.btn, { marginTop: spacing.sm }]} onPress={handleLogin} disabled={loggingIn || !password}>
                {loggingIn ? <ActivityIndicator color={colors.background} size="small" /> : <Text style={styles.btnText}>Log In</Text>}
              </TouchableOpacity>
              <Text style={styles.hint}>Default: admin / cyberguard  (set via CYBERGUARD_USER / CYBERGUARD_PASSWORD env vars on your Mac)</Text>
            </>
          )}
        </View>

        {/* Connection result */}
        {testResult && (
          <View style={[styles.resultBanner, {
            backgroundColor: testResult.ok === true ? '#0a2d12' : testResult.ok === false ? '#2d0a14' : colors.card,
          }]}>
            <Text style={[styles.resultText, {
              color: testResult.ok === true ? colors.success : testResult.ok === false ? colors.critical : colors.textSecondary,
            }]}>
              {testResult.msg}
            </Text>
          </View>
        )}

        {/* About */}
        <Text style={styles.section}>ABOUT</Text>
        <View style={styles.card}>
          <Row label="App" value="CyberGuard AI" />
          <Row label="Version" value="0.1.0" />
          <Row label="Backend" value="FastAPI + Python" />
          <Row label="Transport" value="REST + WebSocket" />
        </View>

        <View style={{ height: spacing.xl }} />
      </ScrollView>
    </SafeAreaView>
  );
}

function Row({ label, value }) {
  return (
    <View style={styles.row}>
      <Text style={styles.rowLabel}>{label}</Text>
      <Text style={styles.rowValue}>{value}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: colors.background },
  scroll: { flex: 1, paddingHorizontal: spacing.md },
  title: { paddingTop: spacing.lg, paddingBottom: spacing.sm },
  section: { fontSize: 11, fontWeight: '700', color: colors.textMuted, letterSpacing: 1, marginBottom: spacing.sm, marginTop: spacing.md },
  card: { backgroundColor: colors.card, borderRadius: radius.md, padding: spacing.md, marginBottom: spacing.sm },
  label: { fontSize: 12, color: colors.textSecondary, marginBottom: 6 },
  hint: { fontSize: 11, color: colors.textMuted, lineHeight: 16, marginTop: spacing.sm },
  input: { backgroundColor: colors.background, borderRadius: radius.sm, borderWidth: 1, borderColor: colors.border, padding: spacing.sm, color: colors.textPrimary, fontSize: 14 },
  btnRow: { flexDirection: 'row', marginTop: spacing.md },
  btn: { backgroundColor: colors.primary, borderRadius: radius.sm, padding: spacing.sm + 2, alignItems: 'center' },
  btnSecondary: { backgroundColor: 'transparent', borderWidth: 1, borderColor: colors.primary },
  btnSecondaryText: { color: colors.primary, fontWeight: '600', fontSize: 13 },
  btnDanger: { backgroundColor: colors.danger },
  btnText: { color: colors.background, fontWeight: '700', fontSize: 13 },
  loggedInRow: { flexDirection: 'row', alignItems: 'center' },
  dot: { width: 8, height: 8, borderRadius: 4, marginRight: spacing.sm },
  loggedInText: { fontSize: 14, color: colors.textPrimary },
  resultBanner: { borderRadius: radius.sm, padding: spacing.md, marginBottom: spacing.sm },
  resultText: { fontSize: 13 },
  row: { flexDirection: 'row', justifyContent: 'space-between', paddingVertical: 5 },
  rowLabel: { fontSize: 13, color: colors.textMuted },
  rowValue: { fontSize: 13, color: colors.textPrimary },
});
