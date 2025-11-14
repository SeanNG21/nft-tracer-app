import React, { useState } from 'react';
import './PacketList.css';

const PacketList = ({
  packets,
  filters,
  onFilterChange,
  onApplyFilters,
  onClearFilters,
  onPacketSelect,
  selectedPacket,
  loading
}) => {
  const [showFilters, setShowFilters] = useState(true);
  const [sortField, setSortField] = useState('first_seen');
  const [sortDirection, setSortDirection] = useState('asc');

  // Handle filter input change
  const handleFilterChange = (field, value) => {
    onFilterChange({ ...filters, [field]: value });
  };

  // Handle sort
  const handleSort = (field) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };

  // Sort packets
  const sortedPackets = [...packets].sort((a, b) => {
    let aVal = a[sortField];
    let bVal = b[sortField];

    if (typeof aVal === 'string') {
      aVal = aVal?.toLowerCase() || '';
      bVal = bVal?.toLowerCase() || '';
    }

    if (sortDirection === 'asc') {
      return aVal > bVal ? 1 : -1;
    } else {
      return aVal < bVal ? 1 : -1;
    }
  });

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

  return (
    <div className="packet-list">
      {/* Filter Section */}
      <div className="filter-section">
        <div className="filter-header">
          <h3>
            Filters
            <button
              className="toggle-filters"
              onClick={() => setShowFilters(!showFilters)}
            >
              {showFilters ? '▼' : '▶'}
            </button>
          </h3>
          <div className="filter-actions">
            <button onClick={onApplyFilters} className="apply-btn">
              Apply Filters
            </button>
            <button onClick={onClearFilters} className="clear-btn">
              Clear All
            </button>
          </div>
        </div>

        {showFilters && (
          <div className="filter-grid">
            <div className="filter-group">
              <label>Source IP</label>
              <input
                type="text"
                placeholder="e.g., 192.168.1.1"
                value={filters.src_ip}
                onChange={(e) => handleFilterChange('src_ip', e.target.value)}
              />
            </div>

            <div className="filter-group">
              <label>Destination IP</label>
              <input
                type="text"
                placeholder="e.g., 10.0.0.1"
                value={filters.dst_ip}
                onChange={(e) => handleFilterChange('dst_ip', e.target.value)}
              />
            </div>

            <div className="filter-group">
              <label>Source Port</label>
              <input
                type="text"
                placeholder="e.g., 5000"
                value={filters.src_port}
                onChange={(e) => handleFilterChange('src_port', e.target.value)}
              />
            </div>

            <div className="filter-group">
              <label>Destination Port</label>
              <input
                type="text"
                placeholder="e.g., 80"
                value={filters.dst_port}
                onChange={(e) => handleFilterChange('dst_port', e.target.value)}
              />
            </div>

            <div className="filter-group">
              <label>Protocol</label>
              <select
                value={filters.protocol}
                onChange={(e) => handleFilterChange('protocol', e.target.value)}
              >
                <option value="">All</option>
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ICMP">ICMP</option>
              </select>
            </div>

            <div className="filter-group">
              <label>Hook</label>
              <select
                value={filters.hook}
                onChange={(e) => handleFilterChange('hook', e.target.value)}
              >
                <option value="">All</option>
                <option value="PREROUTING">PREROUTING</option>
                <option value="LOCAL_IN">LOCAL_IN</option>
                <option value="FORWARD">FORWARD</option>
                <option value="LOCAL_OUT">LOCAL_OUT</option>
                <option value="POSTROUTING">POSTROUTING</option>
              </select>
            </div>

            <div className="filter-group">
              <label>Verdict</label>
              <select
                value={filters.verdict}
                onChange={(e) => handleFilterChange('verdict', e.target.value)}
              >
                <option value="">All</option>
                <option value="ACCEPT">ACCEPT</option>
                <option value="DROP">DROP</option>
                <option value="STOLEN">STOLEN</option>
                <option value="QUEUE">QUEUE</option>
                <option value="JUMP">JUMP</option>
                <option value="GOTO">GOTO</option>
                <option value="RETURN">RETURN</option>
              </select>
            </div>

            <div className="filter-group">
              <label>SKB Address</label>
              <input
                type="text"
                placeholder="e.g., 0xffff..."
                value={filters.skb}
                onChange={(e) => handleFilterChange('skb', e.target.value)}
              />
            </div>

            <div className="filter-group">
              <label>Function Name</label>
              <input
                type="text"
                placeholder="e.g., ip_rcv"
                value={filters.function}
                onChange={(e) => handleFilterChange('function', e.target.value)}
              />
            </div>

            <div className="filter-group full-width">
              <label>Keyword Search</label>
              <input
                type="text"
                placeholder="Search across all fields..."
                value={filters.keyword}
                onChange={(e) => handleFilterChange('keyword', e.target.value)}
              />
            </div>
          </div>
        )}
      </div>

      {/* Packet Table */}
      <div className="packet-table-container">
        <div className="packet-table-header">
          <h3>Packets ({sortedPackets.length})</h3>
          {loading && <div className="loading-spinner">Loading...</div>}
        </div>

        <div className="packet-table-wrapper">
          <table className="packet-table">
            <thead>
              <tr>
                <th onClick={() => handleSort('first_seen')}>
                  Time {sortField === 'first_seen' && (sortDirection === 'asc' ? '↑' : '↓')}
                </th>
                <th onClick={() => handleSort('duration_ns')}>
                  Duration {sortField === 'duration_ns' && (sortDirection === 'asc' ? '↑' : '↓')}
                </th>
                <th onClick={() => handleSort('protocol_name')}>
                  Protocol {sortField === 'protocol_name' && (sortDirection === 'asc' ? '↑' : '↓')}
                </th>
                <th onClick={() => handleSort('src_ip')}>
                  Source {sortField === 'src_ip' && (sortDirection === 'asc' ? '↑' : '↓')}
                </th>
                <th onClick={() => handleSort('dst_ip')}>
                  Destination {sortField === 'dst_ip' && (sortDirection === 'asc' ? '↑' : '↓')}
                </th>
                <th onClick={() => handleSort('hook_name')}>
                  Hook {sortField === 'hook_name' && (sortDirection === 'asc' ? '↑' : '↓')}
                </th>
                <th onClick={() => handleSort('final_verdict')}>
                  Verdict {sortField === 'final_verdict' && (sortDirection === 'asc' ? '↑' : '↓')}
                </th>
                <th>Functions</th>
                <th>SKB</th>
              </tr>
            </thead>
            <tbody>
              {sortedPackets.length === 0 ? (
                <tr>
                  <td colSpan="9" className="no-data">
                    No packets found
                  </td>
                </tr>
              ) : (
                sortedPackets.map((packet, index) => (
                  <tr
                    key={index}
                    className={`packet-row ${
                      selectedPacket?.packet_index === index ? 'selected' : ''
                    } verdict-${packet.final_verdict?.toLowerCase()}`}
                    onClick={() => onPacketSelect(packet, index)}
                  >
                    <td className="time">{formatTimestamp(packet.first_seen)}</td>
                    <td className="duration">{formatDuration(packet.duration_ns)}</td>
                    <td className="protocol">{packet.protocol_name || 'N/A'}</td>
                    <td className="ip">
                      {packet.src_ip || 'N/A'}
                      {packet.src_port ? `:${packet.src_port}` : ''}
                    </td>
                    <td className="ip">
                      {packet.dst_ip || 'N/A'}
                      {packet.dst_port ? `:${packet.dst_port}` : ''}
                    </td>
                    <td className="hook">{packet.hook_name || 'N/A'}</td>
                    <td className={`verdict verdict-${packet.final_verdict?.toLowerCase()}`}>
                      {packet.final_verdict || 'N/A'}
                    </td>
                    <td className="functions">
                      {packet.unique_functions} / {packet.total_functions_called}
                    </td>
                    <td className="skb" title={packet.skb_addr}>
                      {packet.skb_addr?.substring(0, 10)}...
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default PacketList;
