import React, { useState, useEffect, useRef } from 'react';
import io from 'socket.io-client';
import './Realtime.css';

const SOCKET_URL = process.env.REACT_APP_SOCKET_URL || 'http://localhost:5000';

// Hook order for pipeline
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

// Color based on drop rate
function getDropRateColor(dropRate) {
  if (dropRate <= 1) {
    return { bg: 'rgba(40, 167, 69, 0.1)', border: '#28a745', text: '#28a745' };
  } else if (dropRate <= 3) {
    return { bg: 'rgba(255, 193, 7, 0.1)', border: '#ffc107', text: '#f0ad4e' };
  } else {
    return { bg: 'rgba(220, 53, 69, 0.1)', border: '#dc3545', text: '#dc3545' };
  }
}

/**
 * SessionRealtimeStats - Realtime visualization cho 1 session cụ thể
 * Subscribe to WebSocket room: session_{sessionId}
 */
function SessionRealtimeStats({ sessionId }) {
  const [connected, setConnected] = useState(false);
  const [stats, setStats] = useState(null);
  const [expandedHooks, setExpandedHooks] = useState(new Set());
  
  const socketRef = useRef(null);

  // Initialize Socket.IO connection
  useEffect(() => {
    console.log(`[SessionRealtime] Connecting for session: ${sessionId}`);
    
    const socket = io(SOCKET_URL, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionAttempts: 5
    });

    socket.on('connect', () => {
      console.log(`[SessionRealtime] Connected, joining room: session_${sessionId}`);
      setConnected(true);
      
      // Join session-specific room
      socket.emit('join_session', { session_id: sessionId });
    });

    socket.on('disconnect', () => {
      console.log('[SessionRealtime] Disconnected from WebSocket');
      setConnected(false);
    });

    socket.on('joined_session', (data) => {
      console.log('[SessionRealtime] Joined session room:', data);
    });

    // Listen for session-specific stats updates
    socket.on('session_stats_update', (data) => {
      if (data.session_id === sessionId) {
        console.log('[SessionRealtime] Received stats for session:', data.stats);
        setStats(data.stats);
      }
    });

    socketRef.current = socket;

    return () => {
      console.log(`[SessionRealtime] Leaving room: session_${sessionId}`);
      socket.emit('leave_session', { session_id: sessionId });
      socket.disconnect();
    };
  }, [sessionId]);

  const toggleHookExpansion = (hookName) => {
    setExpandedHooks(prev => {
      const newSet = new Set(prev);
      if (newSet.has(hookName)) {
        newSet.delete(hookName);
      } else {
        newSet.add(hookName);
      }
      return newSet;
    });
  };

  // Loading state
  if (!stats) {
    return (
      <div className="realtime-container">
        <div className="realtime-disabled-notice">
          <h3>⏳ Đang tải realtime stats...</h3>
          <p>Kết nối WebSocket và đợi dữ liệu đầu tiên</p>
          <div className="connection-status">
            <div className={`status-dot ${connected ? 'connected' : 'disconnected'}`}></div>
            <span>{connected ? 'Connected' : 'Connecting...'}</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="realtime-container">
      {/* Connection Status */}
      <div className="realtime-header">
        <div className="realtime-header-left">
          <h2>📊 Realtime Statistics - {sessionId}</h2>
          <div className="connection-status">
            <div className={`status-dot ${connected ? 'connected' : 'disconnected'}`}></div>
            <span>{connected ? 'Live Updates' : 'Disconnected'}</span>
          </div>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="realtime-stats-grid">
        <div className="realtime-stat-card primary">
          <div className="stat-icon">📦</div>
          <div className="stat-content">
            <div className="stat-value">{stats.total_packets?.toLocaleString() || 0}</div>
            <div className="stat-label">Total Packets</div>
          </div>
        </div>

        <div className="realtime-stat-card success">
          <div className="stat-icon">⚡</div>
          <div className="stat-content">
            <div className="stat-value">{stats.packets_per_second?.toFixed(1) || 0}</div>
            <div className="stat-label">Packets/Sec</div>
          </div>
        </div>

        <div className="realtime-stat-card warning">
          <div className="stat-icon">⏱️</div>
          <div className="stat-content">
            <div className="stat-value">{stats.uptime_seconds?.toFixed(0) || 0}s</div>
            <div className="stat-label">Uptime</div>
          </div>
        </div>

        <div className="realtime-stat-card info">
          <div className="stat-icon">🎯</div>
          <div className="stat-content">
            <div className="stat-value">{stats.mode?.toUpperCase() || 'N/A'}</div>
            <div className="stat-label">Mode</div>
          </div>
        </div>
      </div>

      {/* Multifunction Stats Visualization */}
      {stats.mode === 'multifunction' && (stats.stats_by_layer || stats.stats_by_hook || stats.stats_by_verdict) && (
        <div className="multifunction-stats-container">
          {/* Layer Statistics */}
          {stats.stats_by_layer && Object.keys(stats.stats_by_layer).length > 0 && (
            <div className="realtime-panel">
              <h3>📊 Network Stack Layers</h3>
              <div className="bar-chart">
                {Object.entries(stats.stats_by_layer)
                  .sort((a, b) => b[1] - a[1])
                  .map(([layer, count]) => {
                    const maxCount = Math.max(...Object.values(stats.stats_by_layer));
                    const percentage = (count / maxCount) * 100;
                    return (
                      <div key={layer} className="bar-item">
                        <div className="bar-label">{layer}</div>
                        <div className="bar-visual">
                          <div
                            className="bar-fill"
                            style={{
                              width: `${percentage}%`,
                              backgroundColor: '#1a73e8'
                            }}
                          >
                            <span className="bar-value">{count.toLocaleString()}</span>
                          </div>
                        </div>
                      </div>
                    );
                  })}
              </div>
            </div>
          )}

          {/* Hook Statistics */}
          {stats.stats_by_hook && Object.keys(stats.stats_by_hook).length > 0 && (
            <div className="realtime-panel">
              <h3>🔄 Netfilter Hooks</h3>
              <div className="bar-chart">
                {Object.entries(stats.stats_by_hook)
                  .sort((a, b) => {
                    const hookOrder = ['PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING'];
                    return hookOrder.indexOf(a[0]) - hookOrder.indexOf(b[0]);
                  })
                  .map(([hook, count]) => {
                    const maxCount = Math.max(...Object.values(stats.stats_by_hook));
                    const percentage = (count / maxCount) * 100;
                    const hookIcons = {
                      'PREROUTING': '⚙️',
                      'INPUT': '📥',
                      'FORWARD': '↔️',
                      'OUTPUT': '📤',
                      'POSTROUTING': '⚙️'
                    };
                    return (
                      <div key={hook} className="bar-item">
                        <div className="bar-label">{hookIcons[hook] || ''} {hook}</div>
                        <div className="bar-visual">
                          <div
                            className="bar-fill"
                            style={{
                              width: `${percentage}%`,
                              backgroundColor: '#28a745'
                            }}
                          >
                            <span className="bar-value">{count.toLocaleString()}</span>
                          </div>
                        </div>
                      </div>
                    );
                  })}
              </div>
            </div>
          )}

          {/* Verdict Statistics */}
          {stats.stats_by_verdict && Object.keys(stats.stats_by_verdict).length > 0 && (
            <div className="realtime-panel">
              <h3>⚖️ NFT Verdicts</h3>
              <div className="bar-chart">
                {Object.entries(stats.stats_by_verdict)
                  .sort((a, b) => b[1] - a[1])
                  .map(([verdict, count]) => {
                    const maxCount = Math.max(...Object.values(stats.stats_by_verdict));
                    const percentage = (count / maxCount) * 100;
                    const verdictColors = {
                      'ACCEPT': '#28a745',
                      'DROP': '#dc3545',
                      'STOLEN': '#ffc107',
                      'QUEUE': '#17a2b8',
                      'REPEAT': '#6c757d',
                      'STOP': '#fd7e14'
                    };
                    return (
                      <div key={verdict} className="bar-item">
                        <div className="bar-label">{verdict}</div>
                        <div className="bar-visual">
                          <div
                            className="bar-fill"
                            style={{
                              width: `${percentage}%`,
                              backgroundColor: verdictColors[verdict] || '#6c757d'
                            }}
                          >
                            <span className="bar-value">{count.toLocaleString()}</span>
                          </div>
                        </div>
                      </div>
                    );
                  })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Hook Pipeline Graph */}
      {stats.hooks && Object.keys(stats.hooks).length > 0 ? (
        <div className="realtime-panel full-width">
          <h3>🔄 Packet Flow Pipeline</h3>
          {stats.mode === 'multifunction' && (
            <div className="multifunction-note">
              ℹ️ Multi-Function Mode: Layers are auto-detected from traced kernel functions
            </div>
          )}
          <div className="hook-pipeline">
            {HOOK_ORDER.map((hookName, index) => {
              const hookData = stats.hooks[hookName];
              const isExpanded = expandedHooks.has(hookName);

              // Hook not active
              if (!hookData || !hookData.packets_total || hookData.packets_total === 0) {
                return (
                  <div key={hookName} className="hook-pipeline-item">
                    <div className="hook-node inactive">
                      <div className="hook-icon">{HOOK_ICONS[hookName]}</div>
                      <div className="hook-name">{hookName}</div>
                      <div className="hook-stats">
                        <div className="hook-stat">
                          <span className="value">No data</span>
                        </div>
                      </div>
                    </div>
                    {index < HOOK_ORDER.length - 1 && (
                      <div className="hook-arrow inactive">→</div>
                    )}
                  </div>
                );
              }

              const totalPackets = hookData.packets_total || 0;
              const layersData = hookData.layers || {};
              const avgDropRate = Object.values(layersData).length > 0
                ? Object.values(layersData).reduce((sum, l) => sum + (l.drop_rate || 0), 0) / Object.values(layersData).length
                : 0;
              const avgLatency = Object.values(layersData).length > 0
                ? Object.values(layersData).reduce((sum, l) => sum + (l.avg_latency_ms || 0), 0) / Object.values(layersData).length
                : 0;

              const colors = getDropRateColor(avgDropRate);

              return (
                <div key={hookName} className="hook-pipeline-item">
                  <div 
                    className={`hook-node active ${isExpanded ? 'expanded' : ''}`}
                    style={{
                      backgroundColor: colors.bg,
                      borderColor: colors.border,
                      boxShadow: `0 0 15px ${colors.border}40`
                    }}
                    onClick={() => toggleHookExpansion(hookName)}
                  >
                    <div className="hook-icon">{HOOK_ICONS[hookName]}</div>
                    <div className="hook-name">{hookName}</div>
                    <div className="hook-stats">
                      <div className="hook-stat">
                        <span className="label">📦</span>
                        <span className="value">{totalPackets.toLocaleString()} pkts</span>
                      </div>
                      <div className="hook-stat">
                        <span className="label">🚫</span>
                        <span className="value" style={{ color: colors.text }}>
                          {avgDropRate.toFixed(1)}%
                        </span>
                      </div>
                      <div className="hook-stat">
                        <span className="label">⏱️</span>
                        <span className="value">{avgLatency.toFixed(2)} ms</span>
                      </div>
                    </div>
                    <div className="hook-expand-hint">
                      {isExpanded ? '▼ Click to collapse' : '▶ Click to expand layers'}
                    </div>
                  </div>

                  {index < HOOK_ORDER.length - 1 && (
                    <div className="hook-arrow active">→</div>
                  )}

                  {/* Expanded Layers */}
                  {isExpanded && (
                    <div className="layers-container">
                      {Object.keys(layersData).length === 0 ? (
                        <div className="no-layers-message">
                          <p>ℹ️ No layer data available for this hook</p>
                          <p className="hint">Layers will appear as packets flow through</p>
                        </div>
                      ) : (
                        LAYER_ORDER.map(layerName => {
                          const layerData = layersData[layerName];
                          if (!layerData) return null;

                          const layerColors = getDropRateColor(layerData.drop_rate || 0);
                          const verdictText = Object.entries(layerData.verdict_breakdown || {})
                            .map(([v, c]) => `${v}: ${((c / layerData.packets_in) * 100).toFixed(0)}%`)
                            .join(', ');

                          return (
                            <div 
                              key={layerName} 
                              className="layer-node"
                              style={{
                                backgroundColor: layerColors.bg,
                                borderColor: layerColors.border
                              }}
                            >
                              <div className="layer-header">
                                <span className="layer-icon">🧱</span>
                                <span className="layer-name">{layerName}</span>
                              </div>
                              <div className="layer-details">
                                <div className="layer-stat">
                                  <span className="label">Packets:</span>
                                  <span className="value">{layerData.packets_in}</span>
                                </div>
                                <div className="layer-stat">
                                  <span className="label">Drop:</span>
                                  <span className="value" style={{ color: layerColors.text }}>
                                    {(layerData.drop_rate || 0).toFixed(1)}%
                                  </span>
                                </div>
                                {layerData.avg_latency_ms > 0 && (
                                  <div className="layer-stat">
                                    <span className="label">Latency:</span>
                                    <span className="value">{layerData.avg_latency_ms.toFixed(2)} ms</span>
                                  </div>
                                )}
                                {verdictText && (
                                  <div className="layer-stat">
                                    <span className="label">Verdicts:</span>
                                    <span className="value small">{verdictText}</span>
                                  </div>
                                )}
                                {layerData.top_function && (
                                  <div className="layer-stat">
                                    <span className="label">Top Func:</span>
                                    <span className="value small mono">
                                      {layerData.top_function} ({layerData.top_function_calls})
                                    </span>
                                  </div>
                                )}
                              </div>
                            </div>
                          );
                        })
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      ) : (
        <div className="realtime-panel full-width">
          <div className="empty-events">
            <p>📊 Đang chờ dữ liệu packet flow...</p>
            <p className="hint">Generate network traffic để xem packet flow qua hooks</p>
          </div>
        </div>
      )}

      {/* Hook Distribution */}
      {stats.hooks && Object.keys(stats.hooks).length > 0 && (
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

      {/* Recent Events Table */}
      {stats.recent_events && stats.recent_events.length > 0 && (
        <div className="realtime-panel full-width">
          <h3>📝 Recent Events (Last 10)</h3>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.9rem' }}>
              <thead>
                <tr style={{ background: '#f8f9fa', borderBottom: '2px solid #dee2e6' }}>
                  <th style={{ padding: '0.75rem', textAlign: 'left', color: '#666', fontWeight: '600' }}>Type</th>
                  <th style={{ padding: '0.75rem', textAlign: 'left', color: '#666', fontWeight: '600' }}>Function/Hook</th>
                  <th style={{ padding: '0.75rem', textAlign: 'left', color: '#666', fontWeight: '600' }}>Verdict</th>
                  <th style={{ padding: '0.75rem', textAlign: 'left', color: '#666', fontWeight: '600' }}>Protocol</th>
                  <th style={{ padding: '0.75rem', textAlign: 'left', color: '#666', fontWeight: '600' }}>Flow</th>
                </tr>
              </thead>
              <tbody>
                {stats.recent_events.slice(-10).reverse().map((evt, idx) => (
                  <tr key={idx} style={{ borderBottom: '1px solid #e9ecef' }}>
                    <td style={{ padding: '0.75rem' }}>
                      <span style={{
                        padding: '0.25rem 0.5rem',
                        borderRadius: '4px',
                        fontSize: '0.75rem',
                        fontWeight: '600',
                        background: evt.type === 'nft' ? '#e8d5f5' : '#d5e8f5',
                        color: evt.type === 'nft' ? '#6f42c1' : '#0066cc'
                      }}>
                        {evt.type || '-'}
                      </span>
                    </td>
                    <td style={{ padding: '0.75rem', fontFamily: 'monospace', fontSize: '0.85rem' }}>
                      {evt.func_name || evt.hook_name || '-'}
                    </td>
                    <td style={{ padding: '0.75rem' }}>
                      <span style={{
                        padding: '0.25rem 0.5rem',
                        borderRadius: '4px',
                        fontSize: '0.75rem',
                        fontWeight: '600',
                        background: evt.verdict_name === 'ACCEPT' ? '#d4edda' : 
                                   evt.verdict_name === 'DROP' ? '#f8d7da' : '#e9ecef',
                        color: evt.verdict_name === 'ACCEPT' ? '#155724' : 
                               evt.verdict_name === 'DROP' ? '#721c24' : '#666'
                      }}>
                        {evt.verdict_name || '-'}
                      </span>
                    </td>
                    <td style={{ padding: '0.75rem', fontSize: '0.85rem', color: '#666' }}>
                      {evt.protocol || '-'}
                    </td>
                    <td style={{ padding: '0.75rem', fontFamily: 'monospace', fontSize: '0.8rem', color: '#495057' }}>
                      {evt.src_ip && evt.dst_ip ? `${evt.src_ip} → ${evt.dst_ip}` : '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Info Footer */}
      <div className="realtime-panel full-width">
        <div className="empty-events">
          <p>📈 Stats update mỗi 1 giây qua WebSocket</p>
          <p className="hint">✨ Không cần refresh - tất cả realtime!</p>
        </div>
      </div>
    </div>
  );
}

export default SessionRealtimeStats;