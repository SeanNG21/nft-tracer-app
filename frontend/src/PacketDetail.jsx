import React, { useState } from 'react';
import './PacketDetail.css';

const PacketDetail = ({ packet, onClose }) => {
  const [activeTab, setActiveTab] = useState('overview');

  // Show placeholder if no packet selected
  if (!packet) {
    return (
      <div className="packet-detail">
        <div className="detail-placeholder">
          <div className="placeholder-icon">📦</div>
          <h3>No Packet Selected</h3>
          <p>Click on a packet in the list to view detailed information</p>
        </div>
      </div>
    );
  }

  // Format timestamp
  const formatTimestamp = (ns) => {
    if (!ns && ns !== 0) return 'N/A';
    return (ns / 1000000).toFixed(3) + ' ms';
  };

  // Format duration
  const formatDuration = (ns) => {
    if (!ns && ns !== 0) return 'N/A';
    if (ns < 1000) return ns + ' ns';
    if (ns < 1000000) return (ns / 1000).toFixed(2) + ' μs';
    return (ns / 1000000).toFixed(2) + ' ms';
  };

  // Render packet overview
  const renderOverview = () => (
    <div className="detail-section">
      <h4>Packet Information</h4>

      {/* Debug info - shows which packet is selected */}
      {packet.original_index !== undefined && (
        <div className="packet-identifier">
          <span className="identifier-label">Packet Index:</span>
          <span className="identifier-value">#{packet.original_index}</span>
          {packet.skb_addr && (
            <>
              <span className="identifier-separator">•</span>
              <span className="identifier-skb" title={packet.skb_addr}>
                {packet.skb_addr.substring(0, 16)}...
              </span>
            </>
          )}
        </div>
      )}

      <div className="info-grid">
        <div className="info-item">
          <label>SKB Address</label>
          <span className="mono">{packet.skb_addr || 'N/A'}</span>
        </div>
        <div className="info-item">
          <label>Protocol</label>
          <span className="badge protocol">{packet.protocol_name || 'N/A'}</span>
        </div>
        <div className="info-item">
          <label>Source</label>
          <span>
            {packet.src_ip || 'N/A'}
            {packet.src_port ? `:${packet.src_port}` : ''}
          </span>
        </div>
        <div className="info-item">
          <label>Destination</label>
          <span>
            {packet.dst_ip || 'N/A'}
            {packet.dst_port ? `:${packet.dst_port}` : ''}
          </span>
        </div>
        <div className="info-item">
          <label>First Seen</label>
          <span>{formatTimestamp(packet.first_seen)}</span>
        </div>
        <div className="info-item">
          <label>Last Seen</label>
          <span>{formatTimestamp(packet.last_seen)}</span>
        </div>
        <div className="info-item">
          <label>Duration</label>
          <span>{formatDuration(packet.duration_ns)}</span>
        </div>
        <div className="info-item">
          <label>Hook</label>
          <span className="badge hook">{packet.hook_name || 'N/A'}</span>
        </div>
        <div className="info-item">
          <label>Final Verdict</label>
          <span className={`badge verdict verdict-${packet.final_verdict?.toLowerCase()}`}>
            {packet.final_verdict || 'N/A'}
          </span>
        </div>
        <div className="info-item">
          <label>Unique Functions</label>
          <span>{packet.unique_functions ?? 0}</span>
        </div>
        <div className="info-item">
          <label>Unique Layers</label>
          <span>{packet.unique_layers ?? 0}</span>
        </div>
        <div className="info-item">
          <label>Total Events</label>
          <span>{packet.all_events_count ?? packet.total_events ?? 0}</span>
        </div>
        <div className="info-item">
          <label>Rules Evaluated</label>
          <span>{packet.total_rules_evaluated ?? 0}</span>
        </div>
        <div className="info-item">
          <label>Verdict Changes</label>
          <span className={packet.verdict_changes > 0 ? 'highlight-changes' : ''}>
            {packet.verdict_changes ?? 0}
            {packet.verdict_changes > 0 && ' ⚠️'}
          </span>
        </div>
        <div className="info-item">
          <label>All Events</label>
          <span>{packet.all_events_count}</span>
        </div>
      </div>

      {/* Layer Counts Section */}
      {packet.layer_counts && Object.keys(packet.layer_counts).length > 0 && (
        <div className="layer-counts-section">
          <h5>Layer Distribution</h5>
          <div className="layer-counts-grid">
            {Object.entries(packet.layer_counts).map(([layer, count]) => (
              <div key={layer} className="layer-count-item">
                <span className="layer-name">{layer}</span>
                <span className="layer-count badge">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );

  // Render function call flow
  const renderFunctionFlow = () => (
    <div className="detail-section">
      <h4>Function Call Flow</h4>
      {packet.analysis?.flow_summary && packet.analysis.flow_summary.length > 0 ? (
        <div className="flow-layers">
          {packet.analysis.flow_summary.map((layer, idx) => (
            <div key={idx} className="flow-layer">
              <div className="layer-header">{layer.layer}</div>
              <div className="layer-functions">
                {layer.functions.map((func, fidx) => (
                  <div key={fidx} className="function-item">
                    <span className="function-arrow">→</span>
                    <span className="function-name">{func}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="function-list">
          {packet.functions_path && packet.functions_path.length > 0 ? (
            packet.functions_path.map((func, idx) => (
              <div key={idx} className="function-item">
                <span className="function-index">{idx + 1}</span>
                <span className="function-arrow">→</span>
                <span className="function-name">{func}</span>
              </div>
            ))
          ) : (
            <p className="no-data">No function calls recorded</p>
          )}
        </div>
      )}
    </div>
  );

  // Render verdict chain
  const renderVerdictChain = () => (
    <div className="detail-section">
      <h4>Verdict Chain</h4>

      {/* Drop Reason */}
      {packet.analysis?.drop_reason && (
        <div className="drop-reason alert alert-danger">
          <strong>Drop Reason:</strong>
          <p>{packet.analysis.drop_reason.reason}</p>
          <div className="drop-details">
            <span><strong>Hook:</strong> {packet.analysis.drop_reason.hook}</span>
            <span><strong>Chain:</strong> {packet.analysis.drop_reason.chain}</span>
            <span><strong>Table:</strong> {packet.analysis.drop_reason.table}</span>
          </div>
        </div>
      )}

      {/* Verdict Chain Timeline */}
      {packet.analysis?.verdict_chain && packet.analysis.verdict_chain.length > 0 ? (
        <div className="verdict-timeline">
          {packet.analysis.verdict_chain.map((verdict, idx) => (
            <div key={idx} className="verdict-step">
              <div className="verdict-marker">
                <div className={`verdict-dot verdict-${verdict.verdict?.toLowerCase()}`}></div>
                {idx < packet.analysis.verdict_chain.length - 1 && (
                  <div className="verdict-line"></div>
                )}
              </div>
              <div className="verdict-content">
                <div className="verdict-header">
                  <span className={`verdict-badge verdict-${verdict.verdict?.toLowerCase()}`}>
                    {verdict.verdict}
                  </span>
                  <span className="verdict-time">{formatTimestamp(verdict.timestamp)}</span>
                </div>
                <div className="verdict-info">
                  <span><strong>Type:</strong> {verdict.type}</span>
                  {verdict.hook && <span><strong>Hook:</strong> {verdict.hook}</span>}
                  {verdict.chain && <span><strong>Chain:</strong> {verdict.chain}</span>}
                  {verdict.table && <span><strong>Table:</strong> {verdict.table}</span>}
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <p className="no-data">No verdict information available</p>
      )}

      {/* Jump/Goto Chain */}
      {packet.analysis?.jump_goto_chain && packet.analysis.jump_goto_chain.length > 0 && (
        <div className="jump-goto-section">
          <h5>Jump/Goto Chain</h5>
          <div className="jump-list">
            {packet.analysis.jump_goto_chain.map((jump, idx) => (
              <div key={idx} className="jump-item">
                <span className="jump-source">{jump.source_chain}</span>
                <span className="jump-arrow">
                  {jump.verdict_type === 'JUMP' ? '⇢' : '⇒'}
                </span>
                <span className="jump-target">{jump.target_chain}</span>
                <span className="jump-type badge">{jump.verdict_type}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );

  // Render all events
  const renderEvents = () => (
    <div className="detail-section">
      <h4>All Events ({packet.all_events?.length || packet.all_events_count || 0})</h4>
      <div className="events-list">
        {packet.all_events && packet.all_events.length > 0 ? (
          packet.all_events.map((event, idx) => (
            <div key={idx} className={`event-item event-${event.trace_type}`}>
              <div className="event-header">
                <span className="event-type badge">{event.trace_type}</span>
                <span className="event-time">{formatTimestamp(event.timestamp)}</span>
              </div>
              <div className="event-details">
                {event.trace_type === 'function_call' && (
                  <>
                    <span><strong>Function:</strong> {event.function}</span>
                    {event.layer && <span><strong>Layer:</strong> {event.layer}</span>}
                    {event.direction && <span><strong>Direction:</strong> {event.direction}</span>}
                    <span><strong>CPU:</strong> {event.cpu_id}</span>
                    {event.length && <span><strong>Length:</strong> {event.length}</span>}
                    {event.comm && <span><strong>Comm:</strong> {event.comm}</span>}
                  </>
                )}
                {event.trace_type === 'chain_exit' && (
                  <>
                    <span><strong>Verdict:</strong> {event.verdict || event.verdict_str || 'N/A'}</span>
                    <span><strong>Verdict Code:</strong> {event.verdict_code ?? 'N/A'}</span>
                    {event.chain_depth !== undefined && <span><strong>Chain Depth:</strong> {event.chain_depth}</span>}
                    {event.chain_addr && <span><strong>Chain Addr:</strong> {event.chain_addr}</span>}
                    {event.hook !== undefined && <span><strong>Hook:</strong> {event.hook}</span>}
                    <span><strong>CPU:</strong> {event.cpu_id}</span>
                    {event.comm && <span><strong>Comm:</strong> {event.comm}</span>}
                  </>
                )}
                {event.trace_type === 'hook_exit' && (
                  <>
                    <span><strong>Verdict:</strong> {event.verdict || event.verdict_str || 'N/A'}</span>
                    {event.hook !== undefined && <span><strong>Hook:</strong> {event.hook}</span>}
                    <span><strong>CPU:</strong> {event.cpu_id}</span>
                    {event.comm && <span><strong>Comm:</strong> {event.comm}</span>}
                  </>
                )}
                {event.trace_type === 'rule_eval' && (
                  <>
                    <span><strong>Rule Seq:</strong> {event.rule_seq ?? 'N/A'}</span>
                    <span><strong>Rule Handle:</strong> {event.rule_handle ?? event.rule_id ?? 'N/A'}</span>
                    {event.verdict && <span><strong>Verdict:</strong> {event.verdict}</span>}
                    <span><strong>Verdict Code:</strong> {event.verdict_code ?? 'N/A'}</span>
                    {event.chain_depth !== undefined && <span><strong>Chain Depth:</strong> {event.chain_depth}</span>}
                    {event.hook !== undefined && <span><strong>Hook:</strong> {event.hook}</span>}
                    <span><strong>CPU:</strong> {event.cpu_id}</span>
                    {event.comm && <span><strong>Comm:</strong> {event.comm}</span>}
                  </>
                )}
              </div>
            </div>
          ))
        ) : (
          <p className="no-data">No events recorded</p>
        )}
      </div>
    </div>
  );

  return (
    <div className="packet-detail">
      {/* Tabs */}
      <div className="detail-tabs">
        <button
          className={`tab ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          Overview
        </button>
        <button
          className={`tab ${activeTab === 'functions' ? 'active' : ''}`}
          onClick={() => setActiveTab('functions')}
        >
          Function Flow
        </button>
        <button
          className={`tab ${activeTab === 'verdict' ? 'active' : ''}`}
          onClick={() => setActiveTab('verdict')}
        >
          Verdict Chain
        </button>
        <button
          className={`tab ${activeTab === 'events' ? 'active' : ''}`}
          onClick={() => setActiveTab('events')}
        >
          All Events
        </button>
      </div>

      {/* Tab Content */}
      <div className="detail-content">
        {activeTab === 'overview' && renderOverview()}
        {activeTab === 'functions' && renderFunctionFlow()}
        {activeTab === 'verdict' && renderVerdictChain()}
        {activeTab === 'events' && renderEvents()}
      </div>
    </div>
  );
};

export default PacketDetail;
