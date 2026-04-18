// CyberGuard AI — API service layer
// All HTTP calls to the backend go through here.

import axios from 'axios';
import AsyncStorage from '@react-native-async-storage/async-storage';

// ---------------------------------------------------------------------------
// Base URL — reads from AsyncStorage so the user can change it in Settings
// ---------------------------------------------------------------------------

const DEFAULT_BASE_URL = 'http://localhost:8000';

export async function getBaseUrl() {
  const stored = await AsyncStorage.getItem('serverUrl');
  return stored || DEFAULT_BASE_URL;
}

async function client() {
  const baseURL = await getBaseUrl();
  const token = await AsyncStorage.getItem('authToken');
  return axios.create({
    baseURL,
    timeout: 15000,
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export async function login(username, password) {
  const baseURL = await getBaseUrl();
  const form = new URLSearchParams();
  form.append('username', username);
  form.append('password', password);
  const res = await axios.post(`${baseURL}/auth/token`, form.toString(), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    timeout: 10000,
  });
  await AsyncStorage.setItem('authToken', res.data.access_token);
  return res.data;
}

export async function logout() {
  await AsyncStorage.removeItem('authToken');
}

// ---------------------------------------------------------------------------
// Health / Status
// ---------------------------------------------------------------------------

export async function fetchHealth() {
  const c = await client();
  const res = await c.get('/health');
  return res.data;
}

export async function fetchDetectors() {
  const c = await client();
  const res = await c.get('/detectors');
  return res.data;
}

export async function fetchEvents(limit = 50) {
  const c = await client();
  const res = await c.get(`/events?limit=${limit}`);
  return res.data;
}

// ---------------------------------------------------------------------------
// Dashboard stats
// ---------------------------------------------------------------------------

export async function fetchStatsSummary() {
  const c = await client();
  const res = await c.get('/stats/summary');
  return res.data;
}

export async function fetchStatsTimeline(hours = 24) {
  const c = await client();
  const res = await c.get(`/stats/timeline?hours=${hours}`);
  return res.data;
}

// ---------------------------------------------------------------------------
// Network monitor
// ---------------------------------------------------------------------------

export async function fetchNetworkStatus() {
  const c = await client();
  const res = await c.get('/network/status');
  return res.data;
}

export async function runDemoAnalysis() {
  const c = await client();
  const res = await c.post('/analyze/demo');
  return res.data;
}

// ---------------------------------------------------------------------------
// Email scanner
// ---------------------------------------------------------------------------

export async function scanEmails(emails) {
  const c = await client();
  const res = await c.post('/scan/emails', { emails });
  return res.data;
}

export async function scanDemoEmails() {
  const c = await client();
  const res = await c.post('/scan/demo-emails');
  return res.data;
}

// ---------------------------------------------------------------------------
// Log analyzer
// ---------------------------------------------------------------------------

export async function scanLog(content, logType = 'auto') {
  const c = await client();
  const res = await c.post('/scan/log', { content, log_type: logType });
  return res.data;
}

// ---------------------------------------------------------------------------
// Vulnerability scanner
// ---------------------------------------------------------------------------

export async function scanVulnerability(target, ports = null, timeout = 1.0) {
  const c = await client();
  const body = { target, timeout };
  if (ports) body.ports = ports;
  const res = await c.post('/scan/vulnerability', body);
  return res.data;
}

// ---------------------------------------------------------------------------
// Signature scanner (Phase 5b)
// ---------------------------------------------------------------------------

export async function scanSignature(text) {
  const c = await client();
  const res = await c.post('/signatures/scan', { text });
  return res.data;
}

// ---------------------------------------------------------------------------
// Process monitor (Phase 7a)
// GET /processes/all       → all processes sorted by CPU
// GET /processes/suspicious → deep scan, flagged processes only
// POST /processes/kill/{pid}
// ---------------------------------------------------------------------------

export async function fetchProcesses() {
  const c = await client();
  const res = await c.get('/processes/all');
  return res.data;  // { count, processes }
}

export async function analyzeProcesses() {
  const c = await client();
  const res = await c.get('/processes/suspicious');
  return res.data;  // { count, critical, high, medium, findings }
}

export async function killProcess(pid) {
  const c = await client();
  const res = await c.post(`/processes/kill/${pid}`);
  return res.data;
}

// ---------------------------------------------------------------------------
// Persistence monitor (Phase 7b)
// GET  /persistence/status  → scan + changes list
// POST /persistence/baseline
// POST /persistence/approve?path=...
// ---------------------------------------------------------------------------

export async function analyzePersistence() {
  const c = await client();
  const res = await c.get('/persistence/status');
  // normalize: backend returns { has_baseline, files_watched, changes_detected, changes }
  const d = res.data;
  return { findings: d.changes || [], has_baseline: d.has_baseline, files_watched: d.files_watched };
}

export async function takePersistenceBaseline() {
  const c = await client();
  const res = await c.post('/persistence/baseline');
  return res.data;
}

export async function approvePersistenceChange(path) {
  const c = await client();
  // backend expects path as query param, not body
  const res = await c.post(`/persistence/approve?path=${encodeURIComponent(path)}`);
  return res.data;
}

// ---------------------------------------------------------------------------
// USB monitor (Phase 7c)
// GET  /usb/devices     → all devices with trust status
// GET  /usb/suspicious  → untrusted / risky devices
// POST /usb/trust?device_id=...  → trust a device
// (no untrust endpoint — toggle by re-trusting; handled in UI)
// ---------------------------------------------------------------------------

export async function fetchUSBDevices() {
  const c = await client();
  const res = await c.get('/usb/devices');
  return res.data;  // { count, devices }
}

export async function analyzeUSB() {
  const c = await client();
  const res = await c.get('/usb/suspicious');
  // normalize: backend returns { count, devices }
  return { findings: res.data.devices || [] };
}

export async function trustUSBDevice(deviceId) {
  const c = await client();
  // backend expects device_id as query param
  const res = await c.post(`/usb/trust?device_id=${encodeURIComponent(deviceId)}`);
  return res.data;
}

// ---------------------------------------------------------------------------
// File scanner / FIM (Phase 8)
// POST /files/scan        → { path }
// GET  /files/fim/status  → FIM changes
// POST /files/fim/baseline
// POST /files/fim/approve?path=...
// ---------------------------------------------------------------------------

export async function scanFile(path) {
  const c = await client();
  const res = await c.post('/files/scan', { path });
  return res.data;
}

export async function analyzeFIM() {
  const c = await client();
  const res = await c.get('/files/fim/status');
  const d = res.data;
  return { findings: d.changes || [], has_baseline: d.has_baseline };
}

export async function takeFIMBaseline() {
  const c = await client();
  const res = await c.post('/files/fim/baseline');
  return res.data;
}

export async function approveFIMChange(path) {
  const c = await client();
  const res = await c.post(`/files/fim/approve?path=${encodeURIComponent(path)}`);
  return res.data;
}

// ---------------------------------------------------------------------------
// Response / Rules Engine (Phase 9)
// GET   /response/rules
// PATCH /response/rules/{name}/enable   (no body)
// PATCH /response/rules/{name}/disable  (no body)
// GET   /response/pending
// POST  /response/pending/{id}/confirm
// POST  /response/pending/{id}/dismiss
// ---------------------------------------------------------------------------

export async function fetchRules() {
  const c = await client();
  const res = await c.get('/response/rules');
  return res.data;
}

export async function setRuleEnabled(ruleId, enabled) {
  const c = await client();
  const action = enabled ? 'enable' : 'disable';
  const res = await c.patch(`/response/rules/${ruleId}/${action}`);
  return res.data;
}

export async function fetchPendingActions() {
  const c = await client();
  const res = await c.get('/response/pending');
  return res.data;
}

export async function confirmPendingAction(actionId) {
  const c = await client();
  const res = await c.post(`/response/pending/${actionId}/confirm`);
  return res.data;
}

export async function dismissPendingAction(actionId) {
  const c = await client();
  const res = await c.post(`/response/pending/${actionId}/dismiss`);
  return res.data;
}
