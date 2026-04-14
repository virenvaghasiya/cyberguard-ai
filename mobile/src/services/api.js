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
