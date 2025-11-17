import React, { useState, useEffect } from 'react';
import './MultiModeViewer.css';

const MultiModeViewer = ({ trace }) => {
  const [selectedFunction, setSelectedFunction] = useState(null);
  const [filterCategory, setFilterCategory] = useState('all');
  const [expandedSections, setExpandedSections] = useState({
    functions: true,
    nft: true,
    network: true
  });

  if (!trace) {
    return <div className="empty-state">No trace data</div>;
  }

  // Extract data from trace
  const functions = trace.functions_path || [];
  const nftEvents = trace.nft_events || [];
  const packetInfo = trace.packet_info || {};
  const stats = trace.stats || {};

  // Categorize functions
  const categorizeFunction = (funcName) => {
    if (funcName.includes('nft_') || funcName.includes('nf_tables'))
      return 'nft';
    if (funcName.includes('nf_') || funcName.includes('netfilter'))
      return 'netfilter';
    if (funcName.includes('tcp_'))
      return 'tcp';
    if (funcName.includes('udp_'))
      return 'udp';
    if (funcName.includes('ip_') || funcName.includes('ipv4') || funcName.includes('ipv6'))
      return 'ip';
    if (funcName.includes('netif_') || funcName.includes('dev_') || funcName.includes('__netif'))
      return 'network';
    if (funcName.includes('skb_'))
      return 'skb';
    return 'other';
  };

  const functionsByCategory = functions.reduce((acc, func) => {
    const category = categorizeFunction(func);
    if (!acc[category]) acc[category] = [];
    acc[category].push(func);
    return acc;
  }, {});

  const categoryColors = {
    nft: '#e74c3c',
    netfilter: '#e67e22',
    tcp: '#3498db',
    udp: '#9b59b6',
    ip: '#1abc9c',
    network: '#2ecc71',
    skb: '#f39c12',
    other: '#95a5a6'
  };

  const categoryIcons = {
    nft: '🔥',
    netfilter: '🛡️',
    tcp: '📡',
    udp: '📨',
    ip: '🌐',
    network: '🔌',
    skb: '📦',
    other: '⚙️'
  };

  const filteredFunctions = filterCategory === 'all'
    ? functions
    : functions.filter(f => categorizeFunction(f) === filterCategory);

  const toggleSection = (section) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  const formatTimestamp = (ns) => {
    if (!ns) return 'N/A';
    const ms = ns / 1000000;
    return `${ms.toFixed(3)}ms`;
  };

  const formatIP = (ip) => {
    if (!ip) return 'N/A';
    if (typeof ip === 'string') return ip;
    // Convert from integer if needed
    return `${(ip >> 24) & 0xFF}.${(ip >> 16) & 0xFF}.${(ip >> 8) & 0xFF}.${ip & 0xFF}`;
  };

  return (
    <div className="multi-mode-viewer">
      {/* Header Card */}
      <div className="mmv-header-card">
        <div className="mmv-header-title">
          <h2>🚀 Multi-Mode Comprehensive Trace</h2>
          <div className="mmv-header-badge">
            SKB: <code>{trace.skb_addr || 'N/A'}</code>
          </div>
        </div>

        <div className="mmv-stats-row">
          <div className="mmv-stat-item">
            <span className="mmv-stat-label">Total Functions</span>
            <span className="mmv-stat-value">{stats.total_functions || functions.length}</span>
          </div>
          <div className="mmv-stat-item">
            <span className="mmv-stat-label">NFT Rules</span>
            <span className="mmv-stat-value">{stats.total_rules_evaluated || nftEvents.length}</span>
          </div>
          <div className="mmv-stat-item">
            <span className="mmv-stat-label">Duration</span>
            <span className="mmv-stat-value">{formatTimestamp(trace.duration_ns)}</span>
          </div>
          <div className="mmv-stat-item">
            <span className="mmv-stat-label">Final Verdict</span>
            <span className={`mmv-verdict mmv-verdict-${stats.final_verdict?.toLowerCase()}`}>
              {stats.final_verdict || 'N/A'}
            </span>
          </div>
        </div>
      </div>

      {/* Packet Info Card */}
      <div className="mmv-card">
        <div className="mmv-card-header" onClick={() => toggleSection('network')}>
          <h3>🌐 Network Information</h3>
          <span className="mmv-toggle-icon">{expandedSections.network ? '▼' : '▶'}</span>
        </div>
        {expandedSections.network && (
          <div className="mmv-card-content">
            <div className="mmv-network-grid">
              <div className="mmv-network-item">
                <span className="mmv-network-label">Protocol</span>
                <span className="mmv-network-value">
                  <span className="mmv-badge">{packetInfo.protocol || 'N/A'}</span>
                </span>
              </div>
              <div className="mmv-network-item">
                <span className="mmv-network-label">Source</span>
                <span className="mmv-network-value">
                  <code>{formatIP(packetInfo.src_ip)}:{packetInfo.src_port || 'N/A'}</code>
                </span>
              </div>
              <div className="mmv-network-item">
                <span className="mmv-network-label">Destination</span>
                <span className="mmv-network-value">
                  <code>{formatIP(packetInfo.dst_ip)}:{packetInfo.dst_port || 'N/A'}</code>
                </span>
              </div>
              <div className="mmv-network-item">
                <span className="mmv-network-label">Length</span>
                <span className="mmv-network-value">{packetInfo.length || 'N/A'} bytes</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Function Path Card */}
      <div className="mmv-card">
        <div className="mmv-card-header" onClick={() => toggleSection('functions')}>
          <h3>📋 Function Call Path ({functions.length} functions)</h3>
          <span className="mmv-toggle-icon">{expandedSections.functions ? '▼' : '▶'}</span>
        </div>
        {expandedSections.functions && (
          <div className="mmv-card-content">
            {/* Category Filter */}
            <div className="mmv-filter-bar">
              <button
                className={`mmv-filter-btn ${filterCategory === 'all' ? 'active' : ''}`}
                onClick={() => setFilterCategory('all')}
              >
                All ({functions.length})
              </button>
              {Object.entries(functionsByCategory).map(([category, funcs]) => (
                <button
                  key={category}
                  className={`mmv-filter-btn ${filterCategory === category ? 'active' : ''}`}
                  onClick={() => setFilterCategory(category)}
                  style={{
                    '--category-color': categoryColors[category]
                  }}
                >
                  {categoryIcons[category]} {category} ({funcs.length})
                </button>
              ))}
            </div>

            {/* Function List */}
            <div className="mmv-function-list">
              {filteredFunctions.map((func, index) => {
                const category = categorizeFunction(func);
                const isSelected = selectedFunction === index;

                return (
                  <div
                    key={index}
                    className={`mmv-function-item ${isSelected ? 'selected' : ''}`}
                    onClick={() => setSelectedFunction(isSelected ? null : index)}
                  >
                    <div className="mmv-function-index">
                      {index + 1}
                    </div>
                    <div
                      className="mmv-function-category-dot"
                      style={{ background: categoryColors[category] }}
                      title={category}
                    />
                    <div className="mmv-function-name">
                      <code>{func}</code>
                    </div>
                    <div className="mmv-function-category">
                      {categoryIcons[category]} {category}
                    </div>
                  </div>
                );
              })}
            </div>

            {filteredFunctions.length === 0 && (
              <div className="mmv-empty-state">
                No functions in category "{filterCategory}"
              </div>
            )}
          </div>
        )}
      </div>

      {/* NFT Events Card */}
      {nftEvents.length > 0 && (
        <div className="mmv-card">
          <div className="mmv-card-header" onClick={() => toggleSection('nft')}>
            <h3>🔥 NFT Events ({nftEvents.length})</h3>
            <span className="mmv-toggle-icon">{expandedSections.nft ? '▼' : '▶'}</span>
          </div>
          {expandedSections.nft && (
            <div className="mmv-card-content">
              <div className="mmv-nft-timeline">
                {nftEvents.map((event, index) => (
                  <div key={index} className="mmv-nft-event">
                    <div className="mmv-nft-event-marker">
                      <div className="mmv-nft-event-dot" />
                      {index < nftEvents.length - 1 && (
                        <div className="mmv-nft-event-line" />
                      )}
                    </div>
                    <div className="mmv-nft-event-content">
                      <div className="mmv-nft-event-header">
                        <span className="mmv-nft-event-type">
                          {event.type === 'chain_entry' ? '🔗 Chain Entry' :
                           event.type === 'chain_exit' ? '🏁 Chain Exit' :
                           event.type === 'rule_eval' ? '📜 Rule Evaluation' :
                           '❓ Unknown'}
                        </span>
                        <span className="mmv-nft-event-time">
                          {formatTimestamp(event.timestamp_ns)}
                        </span>
                      </div>
                      <div className="mmv-nft-event-details">
                        {event.rule_seq && (
                          <div className="mmv-nft-detail">
                            <strong>Rule:</strong> #{event.rule_seq}
                            {event.rule_handle && ` (0x${event.rule_handle.toString(16)})`}
                          </div>
                        )}
                        {event.chain && (
                          <div className="mmv-nft-detail">
                            <strong>Chain:</strong> {event.chain}
                          </div>
                        )}
                        {event.verdict && (
                          <div className="mmv-nft-detail">
                            <strong>Verdict:</strong>
                            <span className={`mmv-verdict mmv-verdict-${event.verdict.toLowerCase()}`}>
                              {event.verdict}
                            </span>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Category Summary Card */}
      <div className="mmv-card">
        <div className="mmv-card-header">
          <h3>📊 Function Categories Distribution</h3>
        </div>
        <div className="mmv-card-content">
          <div className="mmv-category-grid">
            {Object.entries(functionsByCategory)
              .sort((a, b) => b[1].length - a[1].length)
              .map(([category, funcs]) => {
                const percentage = ((funcs.length / functions.length) * 100).toFixed(1);

                return (
                  <div key={category} className="mmv-category-card">
                    <div className="mmv-category-header">
                      <span className="mmv-category-icon">{categoryIcons[category]}</span>
                      <span className="mmv-category-name">{category}</span>
                    </div>
                    <div className="mmv-category-count">{funcs.length}</div>
                    <div
                      className="mmv-category-bar"
                      style={{
                        width: `${percentage}%`,
                        background: categoryColors[category]
                      }}
                    />
                    <div className="mmv-category-percentage">{percentage}%</div>
                  </div>
                );
              })}
          </div>
        </div>
      </div>
    </div>
  );
};

export default MultiModeViewer;
