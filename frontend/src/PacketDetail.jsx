import React, { useState } from 'react';
import './PacketDetail.css';

const PacketDetail = ({ packet, onClose }) => {
  const [activeTab, setActiveTab] = useState('overview');

  if (!packet) return null;

  // Format timestamp
  const formatTimestamp = (ns) => {
    return (ns / 1000000).toFixed(3) + ' ms';
  };

  // Format duration
  const formatDuration = (ns) => {
    if (ns < 1000) return ns + ' ns';
    if (ns < 1000000) return (ns / 1000).toFixed(2) + ' μs';
    return (ns / 1000000).toFixed(2) + ' ms';
  };

  // Render packet overview
  const renderOverview = () => (
    <div className="detail-section">
      <h4>Packet Information</h4>
      <div className="info-grid">
        <div className="info-item">
          <label>SKB Address</label>
          <span className="mono">{packet.skb_addr}</span>
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
          <span>{packet.unique_functions}</span>
        </div>
        <div className="info-item">
          <label>Total Functions Called</label>
          <span>{packet.total_functions_called}</span>
        </div>
        <div className="info-item">
          <label>Rules Evaluated</label>
          <span>{packet.total_rules_evaluated}</span>
        </div>
        <div className="info-item">
          <label>Verdict Changes</label>
          <span>{packet.verdict_changes}</span>
        </div>
        <div className="info-item">
          <label>All Events</label>
          <span>{packet.all_events_count}</span>
        </div>
      </div>
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
      <h4>All Events ({packet.important_events?.length || 0})</h4>
      <div className="events-list">
        {packet.important_events && packet.important_events.length > 0 ? (
          packet.important_events.map((event, idx) => (
            <div key={idx} className={`event-item event-${event.trace_type}`}>
              <div className="event-header">
                <span className="event-type badge">{event.trace_type}</span>
                <span className="event-time">{formatTimestamp(event.timestamp)}</span>
              </div>
              <div className="event-details">
                {event.trace_type === 'function_call' && (
                  <>
                    <span><strong>Function:</strong> {event.function}</span>
                    <span><strong>CPU:</strong> {event.cpu_id}</span>
                    <span><strong>Length:</strong> {event.length}</span>
                    {event.comm && <span><strong>Comm:</strong> {event.comm}</span>}
                  </>
                )}
                {event.trace_type === 'chain_exit' && (
                  <>
                    <span><strong>Verdict:</strong> {event.verdict_str}</span>
                    <span><strong>Chain:</strong> {event.chain_name}</span>
                    {event.table_name && <span><strong>Table:</strong> {event.table_name}</span>}
                    {event.hook_name && <span><strong>Hook:</strong> {event.hook_name}</span>}
                  </>
                )}
                {event.trace_type === 'hook_exit' && (
                  <>
                    <span><strong>Verdict:</strong> {event.verdict_str}</span>
                    <span><strong>Hook:</strong> {event.hook_name}</span>
                  </>
                )}
                {event.trace_type === 'rule_eval' && (
                  <>
                    <span><strong>Rule ID:</strong> {event.rule_id}</span>
                    {event.verdict_str && <span><strong>Verdict:</strong> {event.verdict_str}</span>}
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
