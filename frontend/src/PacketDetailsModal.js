import React from 'react';
import './PacketDetailsModal.css';

/**
 * PacketDetailsModal - Comprehensive packet detail viewer
 * Displays full information for a selected packet event including:
 * - Chain information (chain_addr, hook, depth)
 * - Rule information (rule_id, handle, type, verdict, queue)
 * - Function flow (call order, timestamps, CPU, PID, Comm)
 * - Packet information (protocol, IPs, ports, skb_addr, pf)
 * - Intermediate verdicts
 */
function PacketDetailsModal({ event, onClose }) {
  if (!event) return null;

  // Helper to format hex addresses
  const formatHex = (value) => {
    if (value === null || value === undefined) return 'N/A';
    if (typeof value === 'string' && value.startsWith('0x')) return value;
    if (typeof value === 'number') return `0x${value.toString(16)}`;
    return value;
  };

  // Helper to format timestamp
  const formatTimestamp = (ts) => {
    if (!ts) return 'N/A';
    const date = new Date(ts * 1000);
    return date.toLocaleString('en-US', {
      hour12: false,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      fractionalSecondDigits: 6
    });
  };

  // Helper to get verdict badge color
  const getVerdictColor = (verdict) => {
    const v = verdict?.toUpperCase();
    if (v === 'ACCEPT' || v === 'CONTINUE') return 'verdict-accept';
    if (v === 'DROP') return 'verdict-drop';
    if (v === 'QUEUE') return 'verdict-queue';
    if (v === 'STOLEN') return 'verdict-stolen';
    return 'verdict-unknown';
  };

  // Helper to render a field row
  const Field = ({ label, value, mono = false, badge = false, badgeColor = '' }) => (
    <div className="detail-field">
      <span className="detail-label">{label}:</span>
      {badge ? (
        <span className={`detail-badge ${badgeColor}`}>{value || 'N/A'}</span>
      ) : (
        <span className={`detail-value ${mono ? 'mono' : ''}`}>{value !== null && value !== undefined ? value : 'N/A'}</span>
      )}
    </div>
  );

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-container" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="modal-header">
          <h2>📦 Packet Event Details</h2>
          <button className="modal-close" onClick={onClose}>✕</button>
        </div>

        {/* Content */}
        <div className="modal-content">
          {/* Section 1: Packet Information */}
          <section className="detail-section">
            <h3 className="section-title">📊 Packet Information</h3>
            <div className="detail-grid">
              <Field label="SKB Address" value={formatHex(event.skb_addr)} mono />
              <Field label="Protocol Family (PF)" value={event.pf || 0} />
              <Field label="Protocol" value={event.protocol_name || event.protocol || 'Unknown'} badge badgeColor="badge-protocol" />
              <Field label="Protocol Code" value={event.protocol || 0} mono />
              <Field label="Source IP" value={event.src_ip} mono />
              <Field label="Destination IP" value={event.dst_ip} mono />
              <Field label="Source Port" value={event.src_port || 0} />
              <Field label="Destination Port" value={event.dst_port || 0} />
              <Field label="Packet Length" value={event.length ? `${event.length} bytes` : '0 bytes'} />
              <Field label="Flow" value={event.src_ip && event.dst_ip ? `${event.src_ip}:${event.src_port || 0} → ${event.dst_ip}:${event.dst_port || 0}` : 'N/A'} mono />
            </div>
          </section>

          {/* Section 2: Chain Information */}
          <section className="detail-section">
            <h3 className="section-title">🔗 Chain Information</h3>
            <div className="detail-grid">
              <Field label="Hook" value={event.hook_name || 'Unknown'} badge badgeColor="badge-hook" />
              <Field label="Hook Code" value={event.hook !== null && event.hook !== undefined ? event.hook : 'N/A'} mono />
              <Field label="Chain Address" value={formatHex(event.chain_addr)} mono />
              <Field label="Chain Depth" value={event.chain_depth !== null && event.chain_depth !== undefined ? event.chain_depth : 'N/A'} />
              <Field label="Layer" value={event.layer || 'Unknown'} badge badgeColor="badge-layer" />
              <Field label="Event Type" value={event.event_type !== null && event.event_type !== undefined ? event.event_type : 'N/A'} mono />
            </div>
          </section>

          {/* Section 3: Rule Information */}
          <section className="detail-section">
            <h3 className="section-title">⚖️ Rule Information</h3>
            <div className="detail-grid">
              <Field label="Rule Sequence" value={event.rule_seq !== null && event.rule_seq !== undefined ? event.rule_seq : 'N/A'} />
              <Field label="Rule Handle" value={formatHex(event.rule_handle)} mono />
              <Field label="Rule Type" value={event.rule_type || 'N/A'} />
              <Field label="Expression Address" value={formatHex(event.expr_addr)} mono />
              <Field label="Verdict" value={event.verdict_name || event.verdict || 'Unknown'} badge badgeColor={getVerdictColor(event.verdict_name)} />
              <Field label="Verdict (Raw)" value={event.verdict !== null && event.verdict !== undefined ? event.verdict : 'N/A'} mono />
              {event.queue_num !== null && event.queue_num !== undefined && (
                <Field label="Queue Number" value={event.queue_num} />
              )}
              {event.bypass !== null && event.bypass !== undefined && (
                <Field label="Bypass Flag" value={event.bypass ? 'Yes' : 'No'} />
              )}
            </div>
          </section>

          {/* Section 4: Function & Execution Context */}
          <section className="detail-section">
            <h3 className="section-title">⚙️ Function & Execution Context</h3>
            <div className="detail-grid">
              <Field label="Function Name" value={event.func_name || event.function || 'N/A'} mono />
              <Field label="Timestamp" value={formatTimestamp(event.timestamp)} mono />
              <Field label="CPU ID" value={event.cpu_id !== null && event.cpu_id !== undefined ? event.cpu_id : 'N/A'} />
              <Field label="Process ID (PID)" value={event.pid !== null && event.pid !== undefined ? event.pid : 'N/A'} />
              <Field label="Command (Comm)" value={event.comm || 'N/A'} mono />
              <Field label="Registers Address" value={formatHex(event.regs_addr)} mono />
            </div>
          </section>

          {/* Section 5: Error Information (if any) */}
          {(event.error_code || event.error_name) && (
            <section className="detail-section">
              <h3 className="section-title">⚠️ Error Information</h3>
              <div className="detail-grid">
                <Field label="Error Code" value={event.error_code || 0} mono />
                <Field label="Error Name" value={event.error_name || 'None'} badge badgeColor="badge-error" />
              </div>
            </section>
          )}

          {/* Section 6: Raw Event Data */}
          <section className="detail-section">
            <h3 className="section-title">🔍 Raw Event Data (JSON)</h3>
            <div className="raw-data-container">
              <pre className="raw-data">
                {JSON.stringify(event, null, 2)}
              </pre>
            </div>
          </section>
        </div>

        {/* Footer */}
        <div className="modal-footer">
          <button className="btn-primary" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}

export default PacketDetailsModal;
