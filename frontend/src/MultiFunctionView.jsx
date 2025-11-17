/**
 * Multi-Function Tracer View
 * Hiển thị realtime traces từ multi-function tracer
 * Tương tự RealtimeView nhưng cho multi-function mode
 */

import React, { useState, useEffect, useRef } from 'react';
import io from 'socket.io-client';
import './MultiFunctionView.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:5000';

const MultiFunctionView = () => {
    const [connected, setConnected] = useState(false);
    const [running, setRunning] = useState(false);
    const [events, setEvents] = useState([]);
    const [stats, setStats] = useState(null);
    const [config, setConfig] = useState({ max_functions: 50 });
    const [availableConfigs, setAvailableConfigs] = useState([]);
    const [selectedConfig, setSelectedConfig] = useState('trace_config.json');

    const socketRef = useRef(null);
    const eventsEndRef = useRef(null);
    const maxEvents = 200; // Keep last 200 events

    // Initialize Socket.IO connection
    useEffect(() => {
        socketRef.current = io(BACKEND_URL, {
            transports: ['websocket', 'polling']
        });

        socketRef.current.on('connect', () => {
            console.log('[MultiFunction] Connected to backend');
            setConnected(true);
            fetchStatus();
            fetchConfigs();
        });

        socketRef.current.on('disconnect', () => {
            console.log('[MultiFunction] Disconnected from backend');
            setConnected(false);
        });

        // Listen for multi-function events
        socketRef.current.on('multi_function_event', (event) => {
            setEvents(prev => {
                const updated = [...prev, event];
                return updated.slice(-maxEvents); // Keep only last N events
            });
        });

        // Listen for stats updates
        socketRef.current.on('multi_function_stats', (statsData) => {
            setStats(statsData);
        });

        // Listen for status updates
        socketRef.current.on('multi_function_status', (status) => {
            setRunning(status.running);
        });

        return () => {
            if (socketRef.current) {
                socketRef.current.disconnect();
            }
        };
    }, []);

    // Auto-scroll to bottom
    useEffect(() => {
        eventsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [events]);

    const fetchStatus = async () => {
        try {
            const response = await fetch(`${BACKEND_URL}/api/multi-function/status`);
            const data = await response.json();
            setRunning(data.running);
            if (data.stats) {
                setStats(data.stats);
            }
        } catch (error) {
            console.error('[MultiFunction] Error fetching status:', error);
        }
    };

    const fetchConfigs = async () => {
        try {
            const response = await fetch(`${BACKEND_URL}/api/multi-function/config`);
            const data = await response.json();
            setAvailableConfigs(data.configs || []);
            if (data.default) {
                setSelectedConfig(data.default);
            }
        } catch (error) {
            console.error('[MultiFunction] Error fetching configs:', error);
        }
    };

    const handleStart = async () => {
        try {
            const response = await fetch(`${BACKEND_URL}/api/multi-function/start`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    config: selectedConfig,
                    max_functions: config.max_functions
                })
            });

            if (response.ok) {
                const data = await response.json();
                setRunning(true);
                setEvents([]);
                console.log('[MultiFunction] Started:', data);
            } else {
                const error = await response.json();
                alert(`Error starting tracer: ${error.error}`);
            }
        } catch (error) {
            console.error('[MultiFunction] Error starting:', error);
            alert(`Error: ${error.message}`);
        }
    };

    const handleStop = async () => {
        try {
            const response = await fetch(`${BACKEND_URL}/api/multi-function/stop`, {
                method: 'POST'
            });

            if (response.ok) {
                const data = await response.json();
                setRunning(false);
                console.log('[MultiFunction] Stopped:', data);
                if (data.final_stats) {
                    setStats(data.final_stats);
                }
            }
        } catch (error) {
            console.error('[MultiFunction] Error stopping:', error);
        }
    };

    const handleDiscover = async () => {
        if (!window.confirm('Run function discovery? This may take 30-60 seconds.')) {
            return;
        }

        try {
            const response = await fetch(`${BACKEND_URL}/api/multi-function/discover`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    max_trace: config.max_functions,
                    priority: 2
                })
            });

            if (response.ok) {
                const data = await response.json();
                alert(`Discovery complete! Found ${data.functions_discovered} functions`);
                fetchConfigs();
            } else {
                const error = await response.json();
                alert(`Discovery failed: ${error.error}`);
            }
        } catch (error) {
            console.error('[MultiFunction] Error discovering:', error);
            alert(`Error: ${error.message}`);
        }
    };

    const clearEvents = () => {
        setEvents([]);
    };

    const getEventTypeLabel = (type) => {
        const labels = ['FUNC', 'NFT_CHAIN', 'NFT_RULE', 'NF_HOOK'];
        return labels[type] || 'UNKNOWN';
    };

    const getEventTypeClass = (type) => {
        const classes = ['event-func', 'event-nft-chain', 'event-nft-rule', 'event-nf-hook'];
        return classes[type] || 'event-unknown';
    };

    const formatFlow = (event) => {
        return `${event.src_ip}:${event.src_port} → ${event.dst_ip}:${event.dst_port}`;
    };

    return (
        <div className="multi-function-view">
            <div className="header">
                <h2>🔬 Multi-Function Packet Tracer</h2>
                <div className="status-indicator">
                    <span className={`status-dot ${connected ? 'connected' : 'disconnected'}`}></span>
                    {connected ? 'Connected' : 'Disconnected'}
                </div>
            </div>

            {/* Controls */}
            <div className="controls">
                <div className="control-group">
                    <label>Configuration:</label>
                    <select
                        value={selectedConfig}
                        onChange={(e) => setSelectedConfig(e.target.value)}
                        disabled={running}
                    >
                        {availableConfigs.map((cfg) => (
                            <option key={cfg.file} value={cfg.file}>
                                {cfg.file} ({cfg.total_functions} functions)
                            </option>
                        ))}
                    </select>
                </div>

                <div className="control-group">
                    <label>Max Functions:</label>
                    <input
                        type="number"
                        value={config.max_functions}
                        onChange={(e) => setConfig({...config, max_functions: parseInt(e.target.value)})}
                        min="10"
                        max="200"
                        disabled={running}
                    />
                </div>

                <div className="control-buttons">
                    {!running ? (
                        <>
                            <button onClick={handleStart} className="btn-start">
                                ▶ Start Tracing
                            </button>
                            <button onClick={handleDiscover} className="btn-discover">
                                🔍 Discover Functions
                            </button>
                        </>
                    ) : (
                        <button onClick={handleStop} className="btn-stop">
                            ⏹ Stop Tracing
                        </button>
                    )}
                    <button onClick={clearEvents} className="btn-clear">
                        🗑️ Clear Events
                    </button>
                </div>
            </div>

            {/* Statistics */}
            {stats && (
                <div className="stats-panel">
                    <div className="stat-card">
                        <div className="stat-value">{stats.total_events?.toLocaleString() || 0}</div>
                        <div className="stat-label">Total Events</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-value">{stats.packets_seen?.toLocaleString() || 0}</div>
                        <div className="stat-label">Packets</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-value">{stats.functions_hit || 0}</div>
                        <div className="stat-label">Functions Hit</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-value">{stats.nft_chains || 0}</div>
                        <div className="stat-label">NFT Chains</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-value">{stats.nft_rules || 0}</div>
                        <div className="stat-label">NFT Rules</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-value">{Math.round(stats.events_per_second) || 0}</div>
                        <div className="stat-label">Events/sec</div>
                    </div>
                </div>
            )}

            {/* Layer Distribution */}
            {stats && stats.by_layer && Object.keys(stats.by_layer).length > 0 && (
                <div className="layer-distribution">
                    <h3>Events by Layer</h3>
                    <div className="layer-bars">
                        {Object.entries(stats.by_layer)
                            .sort(([,a], [,b]) => b - a)
                            .map(([layer, count]) => (
                                <div key={layer} className="layer-bar">
                                    <span className="layer-name">{layer}</span>
                                    <div className="bar-container">
                                        <div
                                            className="bar-fill"
                                            style={{width: `${(count / stats.total_events) * 100}%`}}
                                        ></div>
                                    </div>
                                    <span className="layer-count">{count}</span>
                                </div>
                            ))
                        }
                    </div>
                </div>
            )}

            {/* Events List */}
            <div className="events-container">
                <div className="events-header">
                    <h3>Trace Events ({events.length}/{maxEvents})</h3>
                    {running && <span className="recording-indicator">🔴 Recording...</span>}
                </div>

                <div className="events-list">
                    {events.length === 0 ? (
                        <div className="no-events">
                            {running ? 'Waiting for events...' : 'No events captured. Click "Start Tracing" to begin.'}
                        </div>
                    ) : (
                        events.map((event, index) => (
                            <div key={index} className={`event-row ${getEventTypeClass(event.event_type)}`}>
                                <span className="event-index">[{index + 1}]</span>
                                <span className="event-type">{getEventTypeLabel(event.event_type)}</span>
                                <span className="event-layer">{event.layer}</span>
                                <span className="event-function">{event.func_name}</span>
                                <span className="event-flow">{formatFlow(event)}</span>
                                {event.verdict_name && (
                                    <span className="event-verdict">[{event.verdict_name}]</span>
                                )}
                            </div>
                        ))
                    )}
                    <div ref={eventsEndRef} />
                </div>
            </div>
        </div>
    );
};

export default MultiFunctionView;
