"""
WebSocket connection manager for CyberGuard AI live alerts.

Maintains a registry of connected WebSocket clients and broadcasts
every event from the event bus to all of them in real time.

Usage:
    1. Include `ws_manager` in the FastAPI lifespan and subscribe it to the event bus.
    2. Mount the /ws/alerts endpoint from server.py.
    3. Mobile app connects to ws://host:8000/ws/alerts and receives JSON events.

Message format sent to clients:
    {
        "event_id":   "uuid",
        "event_type": "anomaly.detected",
        "source":     "log_analyzer",
        "severity":   "high",
        "timestamp":  "2026-04-14T10:00:00+00:00",
        "data":       { ... detector-specific payload ... }
    }
"""

from __future__ import annotations

import asyncio
import json

import structlog
from fastapi import WebSocket, WebSocketDisconnect

from src.core.events import Event

logger = structlog.get_logger()


class WebSocketManager:
    """
    Manages all active WebSocket connections and broadcasts events to them.

    Thread-safe: uses asyncio locks so concurrent connects/disconnects
    don't cause race conditions during broadcast.
    """

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    async def connect(self, websocket: WebSocket) -> None:
        """Accept and register a new WebSocket client."""
        await websocket.accept()
        async with self._lock:
            self._connections.append(websocket)
        logger.info("ws_client_connected", total=len(self._connections))

    async def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket client."""
        async with self._lock:
            if websocket in self._connections:
                self._connections.remove(websocket)
        logger.info("ws_client_disconnected", total=len(self._connections))

    async def broadcast(self, message: dict) -> None:
        """
        Send a JSON message to all connected clients.
        Silently drops clients that have disconnected mid-broadcast.
        """
        if not self._connections:
            return

        payload = json.dumps(message, default=str)
        dead: list[WebSocket] = []

        async with self._lock:
            clients = list(self._connections)

        for ws in clients:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)

        # Clean up disconnected clients
        if dead:
            async with self._lock:
                for ws in dead:
                    if ws in self._connections:
                        self._connections.remove(ws)
            logger.debug("ws_dead_clients_removed", count=len(dead))

    async def handle_connection(self, websocket: WebSocket) -> None:
        """
        Full lifecycle handler for a single WebSocket connection.

        Mount this as the endpoint handler:
            @app.websocket("/ws/alerts")
            async def alerts_ws(ws: WebSocket):
                await ws_manager.handle_connection(ws)
        """
        await self.connect(websocket)
        try:
            # Send a welcome message so the client knows it's connected
            await websocket.send_json({
                "type": "connected",
                "message": "CyberGuard AI live alerts connected",
                "active_connections": self.connection_count,
            })
            # Keep the connection alive — wait for client to disconnect
            while True:
                # We don't process incoming messages, just keep the socket open.
                # recv_text() will raise WebSocketDisconnect when client leaves.
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            await self.disconnect(websocket)


# ---------------------------------------------------------------------------
# Singleton used by server.py and hooked into the event bus
# ---------------------------------------------------------------------------

ws_manager = WebSocketManager()


async def broadcast_event(event: Event) -> None:
    """
    Event bus handler — receives every published event and broadcasts it
    to all connected WebSocket clients.

    Subscribe this to the event bus during app startup:
        for event_type in EventType:
            pipeline.event_bus.subscribe(event_type, broadcast_event)
    """
    await ws_manager.broadcast(event.to_dict())
