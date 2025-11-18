import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import io from 'socket.io-client';
import './Realtime.css';

const API_BASE = process.env.REACT_APP_API_BASE || 'http://localhost:5000/api';
const SOCKET_URL = process.env.REACT_APP_SOCKET_URL || 'http://localhost:5000';

// Hook order for pipeline (OLD - kept for backward compatibility)
const HOOK_ORDER = ['PRE_ROUTING', 'LOCAL_IN', 'FORWARD', 'LOCAL_OUT', 'POST_ROUTING'];
const LAYER_ORDER = ['Ingress', 'L2', 'IP', 'Firewall', 'Socket', 'Egress'];

// Hook icons
const HOOK_ICONS = {
  'PRE_ROUTING': '⚙️',
  'LOCAL_IN': '📥',
  'FORWARD': '↔️',
  'LOCAL_OUT': '📤',
  'POST_ROUTING': '⚙️'
};

// NEW: Pipeline structure definitions for Inbound/Outbound flows
const PIPELINE_DEFINITIONS = {
  Inbound: {
    mainFlow: [
      { name: 'NIC', icon: '📡', color: '#2196f3' },
      { name: 'Driver (NAPI)', icon: '🚗', color: '#1976d2' },
      { name: 'GRO', icon: '🔄', color: '#0d47a1' },
      { name: 'TC Ingress', icon: '🚦', color: '#01579b' },
      { name: 'Netfilter PREROUTING', icon: '🔧', color: '#006064' },
      { name: 'Conntrack', icon: '🔗', color: '#00838f' },
      { name: 'NAT PREROUTING', icon: '🔀', color: '#0097a7' },
      { name: 'Routing Decision', icon: '🗺️', color: '#00acc1' },
    ],
    branches: {
      'Local Delivery': [
        { name: 'Netfilter INPUT', icon: '🛡️', color: '#4dd0e1' },
        { name: 'TCP/UDP', icon: '📦', color: '#80deea' },
        { name: 'Socket', icon: '🔌', color: '#b2ebf2' },
      ],
      'Forward': [
        { name: 'Netfilter FORWARD', icon: '🔀', color: '#fb8c00' },
        { name: 'Netfilter POSTROUTING', icon: '⚙️', color: '#f57c00' },
        { name: 'NIC TX', icon: '📤', color: '#ef6c00' },
      ]
    }
  },
  Outbound: [
    { name: 'Application', icon: '💻', color: '#4caf50' },
    { name: 'TCP/UDP Output', icon: '📤', color: '#43a047' },
    { name: 'Netfilter OUTPUT', icon: '🛡️', color: '#388e3c' },
    { name: 'Routing Lookup', icon: '🗺️', color: '#2e7d32' },
    { name: 'NAT POSTROUTING', icon: '⚙️', color: '#558b2f' },
    { name: 'TC Egress', icon: '🚦', color: '#689f38' },
    { name: 'Driver TX', icon: '🚗', color: '#7cb342' },
    { name: 'NIC', icon: '📡', color: '#8bc34a' },
  ]
};

// Enhanced Pipeline Node Component
function PipelineNode({ stageDef, nodeData, maxCount, isActive }) {
  const count = nodeData?.count || 0;
  const percentage = maxCount > 0 ? (count / maxCount) * 100 : 0;

  // Create gradient background based on stage color
  const gradientBg = isActive
    ? `linear-gradient(135deg, ${stageDef.color} 0%, ${stageDef.color}dd 100%)`
    : 'linear-gradient(135deg, #e0e0e0 0%, #c0c0c0 100%)';

  // Verdict data for Netfilter nodes (percentages from summary)
  const verdictData = nodeData?.verdict || null;
  const isNetfilterNode = stageDef.name.includes('Netfilter');

  // Convert top_functions from object {func: pct} to array for display
  const topFunctionsArray = nodeData?.top_functions
    ? Object.entries(nodeData.top_functions).map(([name, pct]) => ({ name, pct }))
    : [];

  return (
    <div className="pipeline-node-wrapper">
      <div
        className={`pipeline-node ${isActive ? 'active' : 'inactive'}`}
        style={{
          background: gradientBg,
          boxShadow: isActive
            ? `0 4px 12px ${stageDef.color}60, 0 2px 4px ${stageDef.color}40`
            : '0 2px 6px rgba(0,0,0,0.1)',
          border: `2px solid ${isActive ? stageDef.color : '#bbb'}`,
        }}
      >
        {/* Icon */}
        <div className="node-icon">{stageDef.icon}</div>

        {/* Name */}
        <div className="node-name">{stageDef.name}</div>

        {/* Count */}
        {isActive && (
          <div className="node-count">{count.toLocaleString()}</div>
        )}

        {/* Top Functions */}
        {isActive && topFunctionsArray.length > 0 && (
          <div className="node-functions">
            {topFunctionsArray.slice(0, 2).map((func, idx) => (
              <div key={idx} className="func-line">
                <span className="func-name">{func.name}</span>
                <span className="func-pct">{func.pct}%</span>
              </div>
            ))}
          </div>
        )}

        {/* Latency (from latency_ns.p50 in nanoseconds) */}
        {isActive && nodeData?.latency_ns && nodeData.latency_ns.p50 > 0 && (
          <div className="node-latency">
            ⏱️ p50: {(nodeData.latency_ns.p50 / 1000).toFixed(1)}µs
          </div>
        )}

        {/* Verdict for Netfilter nodes (already percentages) */}
        {isActive && isNetfilterNode && verdictData && (
          <div className="node-verdict">
            {Object.entries(verdictData).map(([verdict, pct]) => {
              return pct > 0 ? (
                <div key={verdict} className={`verdict-badge verdict-${verdict.toLowerCase()}`}>
                  {verdict}: {pct}%
                </div>
              ) : null;
            })}
          </div>
        )}

        {/* Tooltip (shows on hover) */}
        {isActive && (
          <div className="node-tooltip">
            <div className="tooltip-header">{stageDef.name}</div>
            <div className="tooltip-stat">Events: {count.toLocaleString()}</div>
            {nodeData?.latency_ns && nodeData.latency_ns.p50 > 0 && (
              <div className="tooltip-section">
                <div className="tooltip-label">Latency:</div>
                <div className="tooltip-stat">p50: {(nodeData.latency_ns.p50 / 1000).toFixed(1)}µs</div>
              </div>
            )}
            {topFunctionsArray.length > 0 && (
              <div className="tooltip-section">
                <div className="tooltip-label">Top Functions:</div>
                {topFunctionsArray.map((func, idx) => (
                  <div key={idx} className="tooltip-stat">
                    {idx + 1}. {func.name} – {func.pct}%
                  </div>
                ))}
              </div>
            )}
            {verdictData && (
              <div className="tooltip-section">
                <div className="tooltip-label">Verdicts:</div>
                {Object.entries(verdictData).map(([verdict, pct]) => (
                  <div key={verdict} className="tooltip-stat">
                    {verdict}: {pct}%
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// Color based on drop rate
function getDropRateColor(dropRate) {
  if (dropRate <= 1) {
    return { bg: 'rgba(40, 167, 69, 0.1)', border: '#28a745', text: '#28a745' }; // Green
  } else if (dropRate <= 3) {
    return { bg: 'rgba(255, 193, 7, 0.1)', border: '#ffc107', text: '#f0ad4e' }; // Yellow
  } else {
    return { bg: 'rgba(220, 53, 69, 0.1)', border: '#dc3545', text: '#dc3545' }; // Red
  }
}

// Format timestamp
function formatTimestamp(ts) {
  const date = new Date(ts * 1000);
  return date.toLocaleTimeString('en-US', { hour12: false });
}

function RealtimeView() {
  const [enabled, setEnabled] = useState(false);
  const [connected, setConnected] = useState(false);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [expandedHooks, setExpandedHooks] = useState(new Set()); // Track multiple expanded hooks
  
  const socketRef = useRef(null);

  // Initialize Socket.IO connection
  useEffect(() => {
    const socket = io(SOCKET_URL, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionAttempts: 5
    });

    socket.on('connect', () => {
      console.log('[Realtime] Connected to WebSocket');
      setConnected(true);
      loadStats();
    });

    socket.on('disconnect', () => {
      console.log('[Realtime] Disconnected from WebSocket');
      setConnected(false);
    });

    // Removed packet_event listener - only use stats_update now
    // We now rely on stats_update every 1s for visualization

    socket.on('stats_update', (stats) => {
      console.log('[Realtime] Received stats_update:', stats);
      setStats(stats);
    });

    socket.on('status', (status) => {
      setEnabled(status.enabled);
    });

    socketRef.current = socket;

    return () => {
      socket.disconnect();
    };
  }, []);

  // Load stats periodically - every 1 second to match backend emission
  useEffect(() => {
    if (enabled && connected) {
      const interval = setInterval(loadStats, 1000);
      return () => clearInterval(interval);
    }
  }, [enabled, connected]);

  const loadStats = async () => {
    try {
      const res = await axios.get(`${API_BASE}/realtime/stats`);
      setStats(res.data);
      setEnabled(res.data.enabled);
    } catch (err) {
      console.error('[Realtime] Failed to load stats:', err);
    }
  };

  const toggleRealtime = async () => {
    setLoading(true);
    setError(null);
    
    try {
      if (enabled) {
        await axios.post(`${API_BASE}/realtime/disable`);
        setEnabled(false);
        setExpandedHooks(new Set()); // Clear all expanded hooks
      } else {
        await axios.post(`${API_BASE}/realtime/enable`);
        setEnabled(true);
      }
      await loadStats();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to toggle realtime');
    } finally {
      setLoading(false);
    }
  };

  const resetStats = async () => {
    setLoading(true);
    try {
      await axios.post(`${API_BASE}/realtime/reset`);
      setExpandedHooks(new Set()); // Clear all expanded hooks
      await loadStats();
    } catch (err) {
      setError('Failed to reset stats');
    } finally {
      setLoading(false);
    }
  };

  const toggleHookExpansion = (hookName) => {
    setExpandedHooks(prev => {
      const newSet = new Set(prev);
      if (newSet.has(hookName)) {
        newSet.delete(hookName); // Collapse if already expanded
      } else {
        newSet.add(hookName); // Expand if not expanded
      }
      return newSet;
    });
  };

  return (
    <div className="realtime-container">
      {/* Header */}
      <div className="realtime-header">
        <div className="realtime-header-left">
          <h2>🔄 Realtime Packet Tracer</h2>
          <div className="connection-status">
            <div className={`status-dot ${connected ? 'connected' : 'disconnected'}`}></div>
            <span>{connected ? 'Connected' : 'Disconnected'}</span>
          </div>
        </div>
        <div className="realtime-header-right">
          <button
            className={`realtime-btn ${enabled ? 'danger' : 'primary'}`}
            onClick={toggleRealtime}
            disabled={loading}
          >
            {loading ? '⏳' : enabled ? '⏸️ Disable' : '▶️ Enable'}
          </button>
          <button
            className="realtime-btn secondary"
            onClick={resetStats}
            disabled={loading || !enabled}
          >
            🔄 Reset
          </button>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="realtime-error">
          <span>{error}</span>
          <button onClick={() => setError(null)}>×</button>
        </div>
      )}

      {/* Disabled Notice */}
      {!enabled ? (
        <div className="realtime-disabled-notice">
          <h3>⚙️ Realtime Tracing Disabled</h3>
          <p>Click "Enable" to start tracing packets in real-time</p>
          <p className="hint">🚀 Monitor packet flow through all netfilter hooks</p>
        </div>
      ) : (
        <>
          {/* Stats Cards */}
          <div className="realtime-stats-grid">
            <div className="realtime-stat-card primary">
              <div className="stat-icon">📊</div>
              <div className="stat-content">
                <div className="stat-value">{stats?.total_packets || 0}</div>
                <div className="stat-label">Total Packets</div>
              </div>
            </div>

            <div className="realtime-stat-card success">
              <div className="stat-icon">⚡</div>
              <div className="stat-content">
                <div className="stat-value">{stats?.packets_per_second?.toFixed(1) || 0}</div>
                <div className="stat-label">Packets/Second</div>
              </div>
            </div>

            <div className="realtime-stat-card warning">
              <div className="stat-icon">⏱️</div>
              <div className="stat-content">
                <div className="stat-value">{stats?.uptime_seconds?.toFixed(0) || 0}s</div>
                <div className="stat-label">Uptime</div>
              </div>
            </div>

            <div className="realtime-stat-card info">
              <div className="stat-icon">🪝</div>
              <div className="stat-content">
                <div className="stat-value">{Object.keys(stats?.hooks || {}).length}</div>
                <div className="stat-label">Active Hooks</div>
              </div>
            </div>
          </div>

          {/* ENHANCED: Pipeline Flow Visualization with Detailed Metrics */}
          {stats && stats.summary && Object.keys(stats.summary).length > 0 && (
            <div className="realtime-panel full-width">
              <h3>🔄 Enhanced Packet Pipeline Flow</h3>

              <div className="pipeline-flow-container">
                {/* Inbound Pipeline */}
                {(() => {
                  const inboundNodes = PIPELINE_DEFINITIONS.Inbound.mainFlow.concat(
                    ...Object.values(PIPELINE_DEFINITIONS.Inbound.branches)
                  );
                  const inboundCounts = inboundNodes.map(s => stats.summary[s.name]?.count || 0);
                  const hasInbound = inboundCounts.some(c => c > 0);

                  if (!hasInbound) return null;

                  const maxCount = Math.max(...inboundCounts);

                  return (
                    <div className="pipeline-direction">
                      <div className="pipeline-direction-header">
                        <span className="pipeline-direction-icon">📥</span>
                        <h4>Inbound Traffic</h4>
                        <span className="pipeline-event-count">
                          {inboundCounts.reduce((sum, val) => sum + val, 0).toLocaleString()} events
                        </span>
                      </div>

                      {/* Main Pipeline Flow */}
                      <div className="pipeline-main-flow">
                        <div className="pipeline-stages">
                          {PIPELINE_DEFINITIONS.Inbound.mainFlow.map((stageDef, index, arr) => {
                            const nodeData = stats.summary[stageDef.name];
                            const isActive = nodeData && nodeData.count > 0;

                            return (
                              <React.Fragment key={stageDef.name}>
                                <PipelineNode
                                  stageDef={stageDef}
                                  nodeData={nodeData}
                                  maxCount={maxCount}
                                  isActive={isActive}
                                />
                                {index < arr.length - 1 && (
                                  <div className="stage-arrow" style={{
                                    color: isActive ? stageDef.color : '#999'
                                  }}>→</div>
                                )}
                              </React.Fragment>
                            );
                          })}
                        </div>
                      </div>

                      {/* Branching Point */}
                      <div className="pipeline-branches">
                        {/* Local Delivery Branch */}
                        <div className="pipeline-branch local">
                          <div className="branch-header">
                            <span className="branch-arrow">⤷</span>
                            <span className="branch-label">Local Delivery</span>
                          </div>
                          <div className="pipeline-stages">
                            {PIPELINE_DEFINITIONS.Inbound.branches['Local Delivery'].map((stageDef, index, arr) => {
                              const nodeData = stats.summary[stageDef.name];
                              const isActive = nodeData && nodeData.count > 0;

                              return (
                                <React.Fragment key={stageDef.name}>
                                  <PipelineNode
                                    stageDef={stageDef}
                                    nodeData={nodeData}
                                    maxCount={maxCount}
                                    isActive={isActive}
                                  />
                                  {index < arr.length - 1 && (
                                    <div className="stage-arrow" style={{
                                      color: isActive ? stageDef.color : '#999'
                                    }}>→</div>
                                  )}
                                </React.Fragment>
                              );
                            })}
                          </div>
                        </div>

                        {/* Forward Branch */}
                        <div className="pipeline-branch forward">
                          <div className="branch-header">
                            <span className="branch-arrow">⤷</span>
                            <span className="branch-label">Forward</span>
                          </div>
                          <div className="pipeline-stages">
                            {PIPELINE_DEFINITIONS.Inbound.branches['Forward'].map((stageDef, index, arr) => {
                              const nodeData = stats.summary[stageDef.name];
                              const isActive = nodeData && nodeData.count > 0;

                              return (
                                <React.Fragment key={stageDef.name}>
                                  <PipelineNode
                                    stageDef={stageDef}
                                    nodeData={nodeData}
                                    maxCount={maxCount}
                                    isActive={isActive}
                                  />
                                  {index < arr.length - 1 && (
                                    <div className="stage-arrow" style={{
                                      color: isActive ? stageDef.color : '#999'
                                    }}>→</div>
                                  )}
                                </React.Fragment>
                              );
                            })}
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })()}

                {/* Outbound Pipeline */}
                {(() => {
                  const outboundCounts = PIPELINE_DEFINITIONS.Outbound.map(s => stats.summary[s.name]?.count || 0);
                  const hasOutbound = outboundCounts.some(c => c > 0);

                  if (!hasOutbound) return null;

                  const maxCount = Math.max(...outboundCounts);

                  return (
                    <div className="pipeline-direction">
                      <div className="pipeline-direction-header">
                        <span className="pipeline-direction-icon">📤</span>
                        <h4>Outbound Traffic</h4>
                        <span className="pipeline-event-count">
                          {outboundCounts.reduce((sum, val) => sum + val, 0).toLocaleString()} events
                        </span>
                      </div>

                      <div className="pipeline-stages">
                        {PIPELINE_DEFINITIONS.Outbound.map((stageDef, index, arr) => {
                          const nodeData = stats.summary[stageDef.name];
                          const isActive = nodeData && nodeData.count > 0;

                          return (
                            <React.Fragment key={stageDef.name}>
                              <PipelineNode
                                stageDef={stageDef}
                                nodeData={nodeData}
                                maxCount={maxCount}
                                isActive={isActive}
                              />
                              {index < arr.length - 1 && (
                                <div className="stage-arrow" style={{
                                  color: isActive ? stageDef.color : '#999'
                                }}>→</div>
                              )}
                            </React.Fragment>
                          );
                        })}
                      </div>
                    </div>
                  );
                })()}
              </div>
            </div>
          )}

          {/* Hook Distribution */}
          {stats && stats.hooks && Object.keys(stats.hooks).length > 0 && (
            <div className="realtime-panel">
              <h3>🪝 Hook Distribution</h3>
              <div className="hook-bars">
                {Object.entries(stats.hooks).map(([hook, hookData]) => {
                  const maxCount = Math.max(...Object.values(stats.hooks).map(h => h.packets_total || 0));
                  const percentage = maxCount > 0 ? ((hookData.packets_total || 0) / maxCount) * 100 : 0;
                  const colors = getDropRateColor(
                    Object.values(hookData.layers || {}).length > 0
                      ? Object.values(hookData.layers).reduce((sum, l) => sum + (l.drop_rate || 0), 0) / Object.values(hookData.layers).length
                      : 0
                  );

                  return (
                    <div key={hook} className="hook-bar-item">
                      <div className="hook-bar-label">
                        <span>{HOOK_ICONS[hook]} {hook}</span>
                        <span className="hook-bar-count">{hookData.packets_total || 0}</span>
                      </div>
                      <div className="hook-bar">
                        <div 
                          className="hook-bar-fill" 
                          style={{ 
                            width: `${percentage}%`,
                            background: colors.border
                          }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

        </>
      )}
    </div>
  );
}

export default RealtimeView;