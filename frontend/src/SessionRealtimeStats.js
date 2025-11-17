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

// NEW: Pipeline structure definitions for Enhanced Full Mode Visualization
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

  // Verdict pie chart data for Netfilter nodes
  const verdictData = nodeData?.verdict || null;
  const isNetfilterNode = stageDef.name.includes('Netfilter');

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
        {isActive && nodeData?.top_functions && nodeData.top_functions.length > 0 && (
          <div className="node-functions">
            {nodeData.top_functions.slice(0, 2).map((func, idx) => (
              <div key={idx} className="func-line">
                <span className="func-name">{func.name}</span>
                <span className="func-pct">{func.pct}%</span>
              </div>
            ))}
          </div>
        )}

        {/* Latency */}
        {isActive && nodeData?.latency && nodeData.latency.p50 > 0 && (
          <div className="node-latency">
            ⏱️ p50: {nodeData.latency.p50.toFixed(1)}µs
          </div>
        )}

        {/* Verdict for Netfilter nodes */}
        {isActive && isNetfilterNode && verdictData && (
          <div className="node-verdict">
            {Object.entries(verdictData).map(([verdict, vCount]) => {
              const pct = count > 0 ? ((vCount / count) * 100).toFixed(0) : 0;
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
            {nodeData?.unique_packets && (
              <div className="tooltip-stat">Unique: {nodeData.unique_packets}</div>
            )}
            {nodeData?.latency && nodeData.latency.p50 > 0 && (
              <div className="tooltip-section">
                <div className="tooltip-label">Latency (µs):</div>
                <div className="tooltip-stat">p50: {nodeData.latency.p50.toFixed(1)}</div>
                <div className="tooltip-stat">p90: {nodeData.latency.p90.toFixed(1)}</div>
                <div className="tooltip-stat">p99: {nodeData.latency.p99.toFixed(1)}</div>
              </div>
            )}
            {nodeData?.top_functions && nodeData.top_functions.length > 0 && (
              <div className="tooltip-section">
                <div className="tooltip-label">Top Functions:</div>
                {nodeData.top_functions.map((func, idx) => (
                  <div key={idx} className="tooltip-stat">
                    {idx + 1}. {func.name} – {func.pct}%
                  </div>
                ))}
              </div>
            )}
            {verdictData && (
              <div className="tooltip-section">
                <div className="tooltip-label">Verdicts:</div>
                {Object.entries(verdictData).map(([verdict, vCount]) => (
                  <div key={verdict} className="tooltip-stat">
                    {verdict}: {vCount} ({((vCount / count) * 100).toFixed(1)}%)
                  </div>
                ))}
              </div>
            )}
            {nodeData?.drops > 0 && (
              <div className="tooltip-stat error">Drops: {nodeData.drops}</div>
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

      {/* ENHANCED FULL MODE: Pipeline Flow Visualization with Detailed Metrics */}
      {stats.mode === 'full' && stats.nodes && Object.keys(stats.nodes).length > 0 && (
        <div className="realtime-panel full-width">
          <h3>🔄 Enhanced Packet Pipeline Flow</h3>

          <div className="pipeline-flow-container">
            {/* Inbound Pipeline */}
            {(() => {
              const inboundNodes = PIPELINE_DEFINITIONS.Inbound.mainFlow.concat(
                ...Object.values(PIPELINE_DEFINITIONS.Inbound.branches)
              );
              const inboundCounts = inboundNodes.map(s => stats.nodes[s.name]?.count || 0);
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
                        const nodeData = stats.nodes[stageDef.name];
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
                          const nodeData = stats.nodes[stageDef.name];
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
                          const nodeData = stats.nodes[stageDef.name];
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
              const outboundCounts = PIPELINE_DEFINITIONS.Outbound.map(s => stats.nodes[s.name]?.count || 0);
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
                      const nodeData = stats.nodes[stageDef.name];
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

      {/* Hook Pipeline Graph - Only show for non-full modes */}
      {stats.mode !== 'full' && stats.hooks && Object.keys(stats.hooks).length > 0 ? (
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
      ) : stats.mode !== 'full' && (
        <div className="realtime-panel full-width">
          <div className="empty-events">
            <p>📊 Đang chờ dữ liệu packet flow...</p>
            <p className="hint">Generate network traffic để xem packet flow qua hooks</p>
          </div>
        </div>
      )}

      {/* Hook Distribution - Only show for non-full modes */}
      {stats.mode !== 'full' && stats.hooks && Object.keys(stats.hooks).length > 0 && (
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