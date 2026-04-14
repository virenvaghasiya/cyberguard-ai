// CyberGuard AI — WebSocket service for live alerts
import AsyncStorage from '@react-native-async-storage/async-storage';

const DEFAULT_BASE_URL = 'http://localhost:8000';

function toWsUrl(httpUrl) {
  return httpUrl.replace(/^http/, 'ws') + '/ws/alerts';
}

class AlertWebSocket {
  constructor() {
    this._ws = null;
    this._listeners = [];
    this._reconnectTimer = null;
    this._shouldReconnect = false;
  }

  async connect() {
    this._shouldReconnect = true;
    const stored = await AsyncStorage.getItem('serverUrl');
    const url = toWsUrl(stored || DEFAULT_BASE_URL);
    this._open(url);
  }

  _open(url) {
    this._ws = new WebSocket(url);

    this._ws.onopen = () => {
      this._emit('status', { connected: true });
    };

    this._ws.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        this._emit('alert', data);
      } catch (_) {}
    };

    this._ws.onerror = () => {
      this._emit('status', { connected: false, error: true });
    };

    this._ws.onclose = () => {
      this._emit('status', { connected: false });
      if (this._shouldReconnect) {
        this._reconnectTimer = setTimeout(() => this._open(url), 3000);
      }
    };
  }

  disconnect() {
    this._shouldReconnect = false;
    if (this._reconnectTimer) clearTimeout(this._reconnectTimer);
    if (this._ws) this._ws.close();
    this._ws = null;
  }

  addListener(fn) {
    this._listeners.push(fn);
    return () => {
      this._listeners = this._listeners.filter(l => l !== fn);
    };
  }

  _emit(type, data) {
    this._listeners.forEach(fn => fn(type, data));
  }
}

export const alertWS = new AlertWebSocket();
