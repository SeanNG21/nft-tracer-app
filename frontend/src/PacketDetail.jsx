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

  // Format hook name
  const formatHookName = (hook) => {
    if (hook === null || hook === undefined) return 'N/A';
    const hooks = {
      0: 'PREROUTING',
      1: 'INPUT',
      2: 'FORWARD',
      3: 'OUTPUT',
      4: 'POSTROUTING',
      255: 'UNKNOWN'
    };
    return hooks[hook] || `HOOK_${hook}`;
  };

  // Format protocol family
  const formatProtocolFamily = (pf) => {
    if (pf === null || pf === undefined) return 'N/A';
    const families = {
      2: 'IPv4',
      10: 'IPv6',
      7: 'BRIDGE',
      0: 'UNSPEC'
    };
    return families[pf] || `PF_${pf}`;
  };

  // Format address (show full or truncated)
  const formatAddress = (addr, full = false) => {
    if (!addr) return 'N/A';
    if (typeof addr === 'number') {
      addr = '0x' + addr.toString(16);
    }
    if (full || addr.length <= 20) return addr;
    return addr.substring(0, 18) + '...';
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
          <label>Total Functions Called</label>
          <span>{packet.total_functions_called ?? 0}</span>
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

  // Render all events with comprehensive details
  const renderEvents = () => {
    // Sort events by timestamp to ensure chronological order
    const sortedEvents = packet.important_events
      ? [...packet.important_events].sort((a, b) => a.timestamp - b.timestamp)
      : [];

    return (
      <div className="detail-section">
        <h4>All Events ({sortedEvents.length})</h4>
        <div className="events-description">
          Showing all events in chronological order with complete information.
          Null/zero values are displayed for debugging purposes.
        </div>
        <div className="events-list-detailed">
          {sortedEvents.length > 0 ? (
            sortedEvents.map((event, idx) => (
              <div key={idx} className={`event-item-detailed event-${event.trace_type}`}>
                {/* Event Header */}
                <div className="event-header-detailed">
                  <div className="event-index">#{idx + 1}</div>
                  <span className={`event-type-badge badge-${event.trace_type}`}>
                    {event.trace_type}
                  </span>
                  <span className="event-timestamp">{formatTimestamp(event.timestamp)}</span>
                  <span className="event-cpu">CPU {event.cpu_id ?? 'N/A'}</span>
                </div>

                {/* Common Event Information */}
                <div className="event-section">
                  <h5>Process Information</h5>
                  <div className="event-info-grid">
                    <div className="info-field">
                      <label>PID:</label>
                      <span className="mono">{event.pid ?? 'N/A'}</span>
                    </div>
                    <div className="info-field">
                      <label>CPU ID:</label>
                      <span className="mono">{event.cpu_id ?? 'N/A'}</span>
                    </div>
                    <div className="info-field">
                      <label>Comm:</label>
                      <span className="mono">{event.comm || 'N/A'}</span>
                    </div>
                    <div className="info-field">
                      <label>Timestamp:</label>
                      <span className="mono">{event.timestamp ?? 'N/A'} ns</span>
                    </div>
                  </div>
                </div>

                {/* Function Call Specific Information */}
                {event.trace_type === 'function_call' && (
                  <div className="event-section">
                    <h5>Function Call Details</h5>
                    <div className="event-info-grid">
                      <div className="info-field full-width">
                        <label>Function Name:</label>
                        <span className="mono highlight">{event.function || 'N/A'}</span>
                      </div>
                      <div className="info-field">
                        <label>Packet Length:</label>
                        <span>{event.length ?? 'N/A'} bytes</span>
                      </div>
                      {event.func_ip && (
                        <div className="info-field">
                          <label>Function IP:</label>
                          <span className="mono">{formatAddress(event.func_ip)}</span>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* NFT Chain Information (for chain_exit, rule_eval) */}
                {(event.trace_type === 'chain_exit' || event.trace_type === 'rule_eval') && (
                  <div className="event-section">
                    <h5>Chain Information</h5>
                    <div className="event-info-grid">
                      <div className="info-field">
                        <label>Chain Address:</label>
                        <span className="mono" title={event.chain_addr}>
                          {formatAddress(event.chain_addr)}
                        </span>
                      </div>
                      <div className="info-field">
                        <label>Chain Depth:</label>
                        <span>{event.chain_depth ?? 'N/A'}</span>
                      </div>
                      <div className="info-field">
                        <label>Hook:</label>
                        <span className="badge hook">{formatHookName(event.hook)}</span>
                      </div>
                      <div className="info-field">
                        <label>Protocol Family:</label>
                        <span>{formatProtocolFamily(event.pf)}</span>
                      </div>
                      {event.chain_name && (
                        <div className="info-field">
                          <label>Chain Name:</label>
                          <span className="highlight">{event.chain_name}</span>
                        </div>
                      )}
                      {event.table_name && (
                        <div className="info-field">
                          <label>Table Name:</label>
                          <span className="highlight">{event.table_name}</span>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* NFT Rule Information (for rule_eval) */}
                {event.trace_type === 'rule_eval' && (
                  <div className="event-section">
                    <h5>Rule Evaluation Details</h5>
                    <div className="event-info-grid">
                      <div className="info-field">
                        <label>Rule Sequence:</label>
                        <span className="mono">{event.rule_seq ?? 0}</span>
                      </div>
                      <div className="info-field">
                        <label>Rule Handle:</label>
                        <span className="mono">{event.rule_handle ?? 0}</span>
                      </div>
                      <div className="info-field">
                        <label>Expression Address:</label>
                        <span className="mono" title={event.expr_addr}>
                          {formatAddress(event.expr_addr)}
                        </span>
                      </div>
                      <div className="info-field">
                        <label>Registers Address:</label>
                        <span className="mono" title={event.regs_addr}>
                          {formatAddress(event.regs_addr)}
                        </span>
                      </div>
                    </div>
                  </div>
                )}

                {/* Verdict Information (for chain_exit, rule_eval, hook_exit) */}
                {(event.trace_type === 'chain_exit' || event.trace_type === 'rule_eval' || event.trace_type === 'hook_exit') && (
                  <div className="event-section">
                    <h5>Verdict Information</h5>
                    <div className="event-info-grid">
                      <div className="info-field">
                        <label>Verdict:</label>
                        <span className={`badge verdict verdict-${event.verdict?.toLowerCase()}`}>
                          {event.verdict || 'N/A'}
                        </span>
                      </div>
                      <div className="info-field">
                        <label>Verdict Code:</label>
                        <span className="mono">{event.verdict_code ?? 'N/A'}</span>
                      </div>
                      <div className="info-field">
                        <label>Verdict Raw:</label>
                        <span className="mono">{event.verdict_raw ?? 'N/A'}</span>
                      </div>
                      {/* Queue information if verdict is QUEUE */}
                      {(event.verdict === 'QUEUE' || event.verdict_code === 3) && (
                        <>
                          <div className="info-field">
                            <label>Queue Number:</label>
                            <span className="mono">{event.queue_num ?? 'N/A'}</span>
                          </div>
                          <div className="info-field">
                            <label>Queue Bypass:</label>
                            <span>{event.has_queue_bypass ? 'Yes' : 'No'}</span>
                          </div>
                        </>
                      )}
                    </div>
                  </div>
                )}

                {/* Hook Exit Specific Information */}
                {event.trace_type === 'hook_exit' && (
                  <div className="event-section">
                    <h5>Hook Exit Details</h5>
                    <div className="event-info-grid">
                      <div className="info-field">
                        <label>Hook:</label>
                        <span className="badge hook">{formatHookName(event.hook)}</span>
                      </div>
                      <div className="info-field">
                        <label>Protocol Family:</label>
                        <span>{formatProtocolFamily(event.pf)}</span>
                      </div>
                      {event.hook_name && (
                        <div className="info-field">
                          <label>Hook Name:</label>
                          <span>{event.hook_name}</span>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Packet Information (if available in event) */}
                {(event.src_ip || event.dst_ip || packet.src_ip || packet.dst_ip) && (
                  <div className="event-section">
                    <h5>Packet Information (at this event)</h5>
                    <div className="event-info-grid">
                      <div className="info-field">
                        <label>SKB Address:</label>
                        <span className="mono" title={packet.skb_addr}>
                          {formatAddress(packet.skb_addr)}
                        </span>
                      </div>
                      <div className="info-field">
                        <label>Protocol:</label>
                        <span className="badge protocol">{packet.protocol_name || 'N/A'}</span>
                      </div>
                      <div className="info-field">
                        <label>Source:</label>
                        <span className="mono">
                          {event.src_ip || packet.src_ip || 'N/A'}
                          {(event.src_port || packet.src_port) ? `:${event.src_port || packet.src_port}` : ''}
                        </span>
                      </div>
                      <div className="info-field">
                        <label>Destination:</label>
                        <span className="mono">
                          {event.dst_ip || packet.dst_ip || 'N/A'}
                          {(event.dst_port || packet.dst_port) ? `:${event.dst_port || packet.dst_port}` : ''}
                        </span>
                      </div>
                    </div>
                  </div>
                )}

                {/* Raw Event Data (for debugging) */}
                <details className="event-raw-data">
                  <summary>Show Raw Event Data (for debugging)</summary>
                  <pre className="raw-json">{JSON.stringify(event, null, 2)}</pre>
                </details>
              </div>
            ))
          ) : (
            <p className="no-data">No events recorded</p>
          )}
        </div>
      </div>
    );
  };

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
