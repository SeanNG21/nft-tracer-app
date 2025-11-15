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
  const [expandedEvents, setExpandedEvents] = useState(new Set());

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

  const toggleEventExpansion = (eventIndex) => {
    setExpandedEvents(prev => {
      const newSet = new Set(prev);
      if (newSet.has(eventIndex)) {
        newSet.delete(eventIndex);
      } else {
        newSet.add(eventIndex);
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

      {/* Hook Pipeline Graph */}
      {stats.hooks && Object.keys(stats.hooks).length > 0 ? (
        <div className="realtime-panel full-width">
          <h3>🔄 Packet Flow Pipeline</h3>
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

      {/* Recent Events Table - Expanded Details */}
      {stats.recent_events && stats.recent_events.length > 0 && (
        <div className="realtime-panel full-width">
          <h3>📝 All Events - Packet Trace Details (Last 50)</h3>
          <p style={{ fontSize: '0.9rem', color: '#666', marginBottom: '1rem' }}>
            Click on any event to expand and view complete details including chain info, rules, function flow, and packet data.
          </p>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
              <thead>
                <tr style={{ background: '#f8f9fa', borderBottom: '2px solid #dee2e6' }}>
                  <th style={{ padding: '0.75rem', textAlign: 'left', color: '#666', fontWeight: '600', width: '30px' }}></th>
                  <th style={{ padding: '0.75rem', textAlign: 'left', color: '#666', fontWeight: '600' }}>Timestamp</th>
                  <th style={{ padding: '0.75rem', textAlign: 'left', color: '#666', fontWeight: '600' }}>Type</th>
                  <th style={{ padding: '0.75rem', textAlign: 'left', color: '#666', fontWeight: '600' }}>Function/Hook</th>
                  <th style={{ padding: '0.75rem', textAlign: 'left', color: '#666', fontWeight: '600' }}>Layer</th>
                  <th style={{ padding: '0.75rem', textAlign: 'left', color: '#666', fontWeight: '600' }}>Verdict</th>
                  <th style={{ padding: '0.75rem', textAlign: 'left', color: '#666', fontWeight: '600' }}>Protocol</th>
                  <th style={{ padding: '0.75rem', textAlign: 'left', color: '#666', fontWeight: '600' }}>Flow</th>
                </tr>
              </thead>
              <tbody>
                {stats.recent_events.slice(-50).reverse().map((evt, idx) => {
                  const isExpanded = expandedEvents.has(idx);
                  const eventTime = new Date(evt.timestamp * 1000).toLocaleTimeString('en-US', { hour12: false, fractionalSecondDigits: 3 });

                  return (
                    <React.Fragment key={idx}>
                      {/* Summary Row - Clickable */}
                      <tr
                        onClick={() => toggleEventExpansion(idx)}
                        style={{
                          borderBottom: isExpanded ? 'none' : '1px solid #e9ecef',
                          cursor: 'pointer',
                          background: isExpanded ? '#f8f9fa' : 'transparent',
                          transition: 'background 0.2s'
                        }}
                        onMouseEnter={(e) => e.currentTarget.style.background = '#f8f9fa'}
                        onMouseLeave={(e) => e.currentTarget.style.background = isExpanded ? '#f8f9fa' : 'transparent'}
                      >
                        <td style={{ padding: '0.75rem', textAlign: 'center' }}>
                          <span style={{ fontSize: '0.8rem', color: '#666' }}>
                            {isExpanded ? '▼' : '▶'}
                          </span>
                        </td>
                        <td style={{ padding: '0.75rem', fontFamily: 'monospace', fontSize: '0.75rem', color: '#495057' }}>
                          {eventTime}
                        </td>
                        <td style={{ padding: '0.75rem' }}>
                          <span style={{
                            padding: '0.25rem 0.5rem',
                            borderRadius: '4px',
                            fontSize: '0.7rem',
                            fontWeight: '600',
                            background: evt.event_type === 2 ? '#e8d5f5' : '#d5e8f5',
                            color: evt.event_type === 2 ? '#6f42c1' : '#0066cc'
                          }}>
                            {evt.event_type === 2 ? 'NFT' : 'FUNC'}
                          </span>
                        </td>
                        <td style={{ padding: '0.75rem', fontFamily: 'monospace', fontSize: '0.8rem' }}>
                          {evt.function || evt.hook_name || '-'}
                        </td>
                        <td style={{ padding: '0.75rem', fontSize: '0.8rem' }}>
                          <span style={{
                            padding: '0.2rem 0.4rem',
                            borderRadius: '3px',
                            fontSize: '0.7rem',
                            background: '#e9ecef',
                            color: '#495057'
                          }}>
                            {evt.layer || '-'}
                          </span>
                        </td>
                        <td style={{ padding: '0.75rem' }}>
                          <span style={{
                            padding: '0.25rem 0.5rem',
                            borderRadius: '4px',
                            fontSize: '0.7rem',
                            fontWeight: '600',
                            background: evt.verdict_name === 'ACCEPT' ? '#d4edda' :
                                       evt.verdict_name === 'DROP' ? '#f8d7da' : '#e9ecef',
                            color: evt.verdict_name === 'ACCEPT' ? '#155724' :
                                   evt.verdict_name === 'DROP' ? '#721c24' : '#666'
                          }}>
                            {evt.verdict_name || '-'}
                          </span>
                        </td>
                        <td style={{ padding: '0.75rem', fontSize: '0.8rem', color: '#666' }}>
                          {evt.protocol_name || evt.protocol || '-'}
                        </td>
                        <td style={{ padding: '0.75rem', fontFamily: 'monospace', fontSize: '0.75rem', color: '#495057' }}>
                          {evt.src_ip && evt.dst_ip ? `${evt.src_ip}:${evt.src_port || 0} → ${evt.dst_ip}:${evt.dst_port || 0}` : '-'}
                        </td>
                      </tr>

                      {/* Expanded Details Row */}
                      {isExpanded && (
                        <tr style={{ borderBottom: '2px solid #dee2e6' }}>
                          <td colSpan="8" style={{ padding: '1.5rem', background: '#f8f9fa' }}>
                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.5rem' }}>

                              {/* Packet Information */}
                              <div style={{ background: 'white', padding: '1rem', borderRadius: '8px', border: '1px solid #dee2e6' }}>
                                <h4 style={{ margin: '0 0 0.75rem 0', color: '#667eea', fontSize: '0.9rem', fontWeight: '600' }}>
                                  📦 Packet Information
                                </h4>
                                <div style={{ fontSize: '0.8rem', lineHeight: '1.8' }}>
                                  <div><strong>SKB Address:</strong> <code>{evt.skb_addr || '0x0'}</code></div>
                                  <div><strong>Protocol:</strong> {evt.protocol_name || 'N/A'} ({evt.protocol || 0})</div>
                                  <div><strong>PF (Protocol Family):</strong> {evt.pf || 0}</div>
                                  <div><strong>Source IP:Port:</strong> <code>{evt.src_ip || '0.0.0.0'}:{evt.src_port || 0}</code></div>
                                  <div><strong>Dest IP:Port:</strong> <code>{evt.dst_ip || '0.0.0.0'}:{evt.dst_port || 0}</code></div>
                                  <div><strong>Packet Length:</strong> {evt.length || 0} bytes</div>
                                  <div><strong>Hook:</strong> {evt.hook_name || 'N/A'} ({evt.hook !== undefined ? evt.hook : 'N/A'})</div>
                                </div>
                              </div>

                              {/* Chain Information */}
                              <div style={{ background: 'white', padding: '1rem', borderRadius: '8px', border: '1px solid #dee2e6' }}>
                                <h4 style={{ margin: '0 0 0.75rem 0', color: '#28a745', fontSize: '0.9rem', fontWeight: '600' }}>
                                  🔗 Chain Information
                                </h4>
                                <div style={{ fontSize: '0.8rem', lineHeight: '1.8' }}>
                                  <div><strong>Chain Address:</strong> <code>{evt.chain_addr || '0x0'}</code></div>
                                  <div><strong>Chain Name:</strong> {evt.chain_name || 'N/A'}</div>
                                  <div><strong>Chain Depth:</strong> {evt.chain_depth !== undefined ? evt.chain_depth : 'N/A'}</div>
                                  <div><strong>Hook Type:</strong> {evt.hook_name || 'N/A'}</div>
                                  <div style={{ marginTop: '0.5rem', padding: '0.5rem', background: '#f8f9fa', borderRadius: '4px', fontSize: '0.75rem' }}>
                                    ℹ️ Chain depth indicates nesting level of chain execution
                                  </div>
                                </div>
                              </div>

                              {/* Rule Information */}
                              <div style={{ background: 'white', padding: '1rem', borderRadius: '8px', border: '1px solid #dee2e6' }}>
                                <h4 style={{ margin: '0 0 0.75rem 0', color: '#ffc107', fontSize: '0.9rem', fontWeight: '600' }}>
                                  📋 Rule Information
                                </h4>
                                <div style={{ fontSize: '0.8rem', lineHeight: '1.8' }}>
                                  <div><strong>Rule Sequence:</strong> {evt.rule_seq !== undefined ? evt.rule_seq : 'N/A'}</div>
                                  <div><strong>Rule Handle:</strong> {evt.rule_handle || '0'}</div>
                                  <div><strong>Rule Type:</strong> {evt.rule_type || 'N/A'}</div>
                                  <div><strong>Expr Address (File Offset):</strong> <code>{evt.expr_addr || '0x0'}</code></div>
                                  <div><strong>Verdict:</strong>
                                    <span style={{
                                      marginLeft: '0.5rem',
                                      padding: '0.2rem 0.5rem',
                                      borderRadius: '3px',
                                      fontSize: '0.7rem',
                                      fontWeight: '600',
                                      background: evt.verdict_name === 'ACCEPT' ? '#d4edda' :
                                                 evt.verdict_name === 'DROP' ? '#f8d7da' : '#e9ecef',
                                      color: evt.verdict_name === 'ACCEPT' ? '#155724' :
                                             evt.verdict_name === 'DROP' ? '#721c24' : '#666'
                                    }}>
                                      {evt.verdict_name || 'N/A'}
                                    </span>
                                  </div>
                                  <div><strong>Verdict Code:</strong> {evt.verdict !== undefined ? evt.verdict : 'N/A'}</div>
                                  {evt.queue_num !== undefined && evt.queue_num > 0 && (
                                    <>
                                      <div><strong>Queue Num:</strong> {evt.queue_num}</div>
                                      <div><strong>Bypass Flag:</strong> {evt.has_queue_bypass ? 'Yes' : 'No'}</div>
                                    </>
                                  )}
                                </div>
                              </div>

                              {/* Function Flow Information */}
                              <div style={{ background: 'white', padding: '1rem', borderRadius: '8px', border: '1px solid #dee2e6' }}>
                                <h4 style={{ margin: '0 0 0.75rem 0', color: '#dc3545', fontSize: '0.9rem', fontWeight: '600' }}>
                                  ⚙️ Function Flow
                                </h4>
                                <div style={{ fontSize: '0.8rem', lineHeight: '1.8' }}>
                                  <div><strong>Function Name:</strong> <code>{evt.function || 'N/A'}</code></div>
                                  <div><strong>Timestamp:</strong> {eventTime}</div>
                                  <div><strong>Timestamp (ns):</strong> <code>{evt.timestamp || 0}</code></div>
                                  <div><strong>CPU ID:</strong> {evt.cpu_id !== undefined ? evt.cpu_id : 'N/A'}</div>
                                  <div><strong>Process ID:</strong> {evt.pid || 0}</div>
                                  <div><strong>Comm (Process):</strong> <code>{evt.comm || 'N/A'}</code></div>
                                  <div><strong>Regs Address:</strong> <code>{evt.regs_addr || '0x0'}</code></div>
                                  <div><strong>Layer:</strong> {evt.layer || 'N/A'}</div>
                                </div>
                              </div>

                              {/* Error Information (if any) */}
                              {(evt.error_code > 0 || evt.error_name) && (
                                <div style={{ background: 'white', padding: '1rem', borderRadius: '8px', border: '1px solid #dc3545' }}>
                                  <h4 style={{ margin: '0 0 0.75rem 0', color: '#dc3545', fontSize: '0.9rem', fontWeight: '600' }}>
                                    ⚠️ Error Information
                                  </h4>
                                  <div style={{ fontSize: '0.8rem', lineHeight: '1.8' }}>
                                    <div><strong>Error Code:</strong> {evt.error_code || 0}</div>
                                    <div><strong>Error Name:</strong> {evt.error_name || 'NONE'}</div>
                                  </div>
                                </div>
                              )}

                              {/* Raw Event Data */}
                              <div style={{
                                background: 'white',
                                padding: '1rem',
                                borderRadius: '8px',
                                border: '1px solid #dee2e6',
                                gridColumn: '1 / -1'
                              }}>
                                <h4 style={{ margin: '0 0 0.75rem 0', color: '#6c757d', fontSize: '0.9rem', fontWeight: '600' }}>
                                  🔍 Raw Event Data (All Fields)
                                </h4>
                                <pre style={{
                                  margin: 0,
                                  padding: '0.75rem',
                                  background: '#f8f9fa',
                                  borderRadius: '4px',
                                  fontSize: '0.75rem',
                                  overflow: 'auto',
                                  maxHeight: '300px',
                                  lineHeight: '1.6'
                                }}>
                                  {JSON.stringify(evt, null, 2)}
                                </pre>
                              </div>

                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
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