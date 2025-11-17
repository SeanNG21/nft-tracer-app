import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './NFTablesManager.css';

const API_BASE = process.env.REACT_APP_API_BASE || 'http://localhost:5000/api';

function NFTablesManager() {
  const [activeTab, setActiveTab] = useState('view'); // 'view' or 'manage'
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [nftHealth, setNftHealth] = useState(null);

  // Tab 1: View Rules state
  const [ruleset, setRuleset] = useState(null);
  const [ruleTree, setRuleTree] = useState(null);
  const [filters, setFilters] = useState({
    family: '',
    chainName: '',
    verdict: '',
    ruleHandle: '',
    textSearch: ''
  });
  const [expandedItems, setExpandedItems] = useState({});

  // Tab 2: Manage Rules state
  const [manageMode, setManageMode] = useState('add'); // 'add', 'edit', 'delete'
  const [tables, setTables] = useState([]);
  const [chains, setChains] = useState([]);
  const [ruleForm, setRuleForm] = useState({
    family: 'ip',
    table: '',
    chain: '',
    // Match conditions
    protocol: '',
    tcpDport: '',
    tcpSport: '',
    udpDport: '',
    udpSport: '',
    ipSaddr: '',
    ipDaddr: '',
    iifname: '',
    oifname: '',
    ctState: '',
    // Action
    action: 'accept',
    jumpTarget: '',
    logPrefix: '',
    counterEnabled: false,
    // For edit mode
    handle: null
  });
  const [rulePreview, setRulePreview] = useState('');
  const [selectedRule, setSelectedRule] = useState(null);

  // Check nftables health on mount
  useEffect(() => {
    checkNftHealth();
    fetchTables();
  }, []);

  const checkNftHealth = async () => {
    try {
      const response = await axios.get(`${API_BASE}/nft/health`);
      setNftHealth(response.data);
    } catch (err) {
      setError('Failed to check nftables availability');
    }
  };

  // ============================================================================
  // TAB 1: VIEW RULES
  // ============================================================================

  const fetchRuleset = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.get(`${API_BASE}/nft/rules`);
      setRuleset(response.data.raw_ruleset);
      setRuleTree(response.data.tree);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to fetch ruleset');
    } finally {
      setLoading(false);
    }
  };

  const toggleExpand = (key) => {
    setExpandedItems(prev => ({
      ...prev,
      [key]: !prev[key]
    }));
  };

  const applyFilters = (tree) => {
    if (!tree) return null;

    const filtered = {};

    Object.entries(tree).forEach(([family, tables]) => {
      // Filter by family
      if (filters.family && family !== filters.family) return;

      filtered[family] = {};

      Object.entries(tables).forEach(([tableName, tableData]) => {
        filtered[family][tableName] = {
          ...tableData,
          chains: {}
        };

        Object.entries(tableData.chains).forEach(([chainName, chainData]) => {
          // Filter by chain name
          if (filters.chainName && !chainName.toLowerCase().includes(filters.chainName.toLowerCase())) {
            return;
          }

          const filteredRules = chainData.rules.filter(rule => {
            // Filter by handle
            if (filters.ruleHandle && rule.handle !== parseInt(filters.ruleHandle)) {
              return false;
            }

            // Filter by verdict
            if (filters.verdict) {
              const ruleText = rule.rule_text.toLowerCase();
              if (!ruleText.includes(filters.verdict.toLowerCase())) {
                return false;
              }
            }

            // Filter by text search
            if (filters.textSearch) {
              const searchText = filters.textSearch.toLowerCase();
              const ruleText = rule.rule_text.toLowerCase();
              if (!ruleText.includes(searchText)) {
                return false;
              }
            }

            return true;
          });

          if (filteredRules.length > 0) {
            filtered[family][tableName].chains[chainName] = {
              ...chainData,
              rules: filteredRules
            };
          }
        });

        // Remove table if no chains match
        if (Object.keys(filtered[family][tableName].chains).length === 0) {
          delete filtered[family][tableName];
        }
      });

      // Remove family if no tables match
      if (Object.keys(filtered[family]).length === 0) {
        delete filtered[family];
      }
    });

    return filtered;
  };

  const exportToJSON = () => {
    const dataStr = JSON.stringify(ruleset, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `nftables-ruleset-${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const clearFilters = () => {
    setFilters({
      family: '',
      chainName: '',
      verdict: '',
      ruleHandle: '',
      textSearch: ''
    });
  };

  const selectRuleForEdit = (family, table, chain, rule) => {
    setSelectedRule({ family, table, chain, rule });
    setManageMode('edit');
    setActiveTab('manage');

    // Parse rule and populate form
    setRuleForm({
      family,
      table,
      chain,
      handle: rule.handle,
      // Parse rule_text to extract conditions (simplified)
      protocol: '',
      tcpDport: '',
      tcpSport: '',
      udpDport: '',
      udpSport: '',
      ipSaddr: '',
      ipDaddr: '',
      iifname: '',
      oifname: '',
      ctState: '',
      action: rule.rule_text.includes('accept') ? 'accept' :
              rule.rule_text.includes('drop') ? 'drop' :
              rule.rule_text.includes('reject') ? 'reject' : 'accept',
      jumpTarget: '',
      logPrefix: '',
      counterEnabled: rule.rule_text.includes('counter')
    });

    // Load chains for selected table
    fetchChains(family, table);
  };

  // ============================================================================
  // TAB 2: MANAGE RULES
  // ============================================================================

  const fetchTables = async () => {
    try {
      const response = await axios.get(`${API_BASE}/nft/tables`);
      setTables(response.data.tables || []);
    } catch (err) {
      console.error('Failed to fetch tables:', err);
    }
  };

  const fetchChains = async (family, table) => {
    if (!family || !table) {
      setChains([]);
      return;
    }

    try {
      const response = await axios.get(`${API_BASE}/nft/chains/${family}/${table}`);
      setChains(response.data.chains || []);
    } catch (err) {
      console.error('Failed to fetch chains:', err);
      setChains([]);
    }
  };

  useEffect(() => {
    if (ruleForm.family && ruleForm.table) {
      fetchChains(ruleForm.family, ruleForm.table);
    }
  }, [ruleForm.family, ruleForm.table]);

  const generateRulePreview = () => {
    const parts = [];

    // Protocol
    if (ruleForm.protocol) {
      parts.push(ruleForm.protocol);
    }

    // Ports
    if (ruleForm.tcpDport) {
      parts.push(`tcp dport ${ruleForm.tcpDport}`);
    }
    if (ruleForm.tcpSport) {
      parts.push(`tcp sport ${ruleForm.tcpSport}`);
    }
    if (ruleForm.udpDport) {
      parts.push(`udp dport ${ruleForm.udpDport}`);
    }
    if (ruleForm.udpSport) {
      parts.push(`udp sport ${ruleForm.udpSport}`);
    }

    // IP addresses
    if (ruleForm.ipSaddr) {
      parts.push(`ip saddr ${ruleForm.ipSaddr}`);
    }
    if (ruleForm.ipDaddr) {
      parts.push(`ip daddr ${ruleForm.ipDaddr}`);
    }

    // Interfaces
    if (ruleForm.iifname) {
      parts.push(`iifname "${ruleForm.iifname}"`);
    }
    if (ruleForm.oifname) {
      parts.push(`oifname "${ruleForm.oifname}"`);
    }

    // Connection tracking
    if (ruleForm.ctState) {
      parts.push(`ct state ${ruleForm.ctState}`);
    }

    // Counter
    if (ruleForm.counterEnabled) {
      parts.push('counter');
    }

    // Log
    if (ruleForm.action === 'log' && ruleForm.logPrefix) {
      parts.push(`log prefix "${ruleForm.logPrefix}"`);
    }

    // Action
    if (ruleForm.action === 'jump' || ruleForm.action === 'goto') {
      parts.push(`${ruleForm.action} ${ruleForm.jumpTarget}`);
    } else if (ruleForm.action !== 'log') {
      parts.push(ruleForm.action);
    }

    const preview = parts.join(' ');
    setRulePreview(preview || '<empty rule>');
    return preview;
  };

  const handleAddRule = async () => {
    const ruleText = generateRulePreview();

    if (!ruleForm.table || !ruleForm.chain) {
      alert('Please select table and chain');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await axios.post(`${API_BASE}/nft/rule/add`, {
        family: ruleForm.family,
        table: ruleForm.table,
        chain: ruleForm.chain,
        rule_text: ruleText
      });

      alert('Rule added successfully!');

      // Refresh ruleset
      await fetchRuleset();

      // Reset form
      resetRuleForm();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to add rule');
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateRule = async () => {
    const ruleText = generateRulePreview();

    if (!ruleForm.handle) {
      alert('No rule selected for update');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await axios.post(`${API_BASE}/nft/rule/update`, {
        family: ruleForm.family,
        table: ruleForm.table,
        chain: ruleForm.chain,
        handle: ruleForm.handle,
        new_rule_text: ruleText
      });

      alert('Rule updated successfully!');

      // Refresh ruleset
      await fetchRuleset();

      // Switch back to view tab
      setActiveTab('view');
      setManageMode('add');
      resetRuleForm();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to update rule');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteRule = async (family, table, chain, handle) => {
    if (!window.confirm('Are you sure you want to delete this rule?')) {
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await axios.post(`${API_BASE}/nft/rule/delete`, {
        family,
        table,
        chain,
        handle
      });

      alert('Rule deleted successfully!');

      // Refresh ruleset
      await fetchRuleset();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to delete rule');
    } finally {
      setLoading(false);
    }
  };

  const resetRuleForm = () => {
    setRuleForm({
      family: 'ip',
      table: '',
      chain: '',
      protocol: '',
      tcpDport: '',
      tcpSport: '',
      udpDport: '',
      udpSport: '',
      ipSaddr: '',
      ipDaddr: '',
      iifname: '',
      oifname: '',
      ctState: '',
      action: 'accept',
      jumpTarget: '',
      logPrefix: '',
      counterEnabled: false,
      handle: null
    });
    setRulePreview('');
    setSelectedRule(null);
  };

  // ============================================================================
  // RENDER
  // ============================================================================

  const filteredTree = applyFilters(ruleTree);

  return (
    <div className="nftables-manager">
      <div className="nft-header">
        <h1>NFTables Manager</h1>
        {nftHealth && (
          <div className={`nft-health ${nftHealth.available ? 'available' : 'unavailable'}`}>
            {nftHealth.available ? '✓' : '✗'} {nftHealth.message}
          </div>
        )}
      </div>

      {error && (
        <div className="error-banner">
          <strong>Error:</strong> {error}
          <button onClick={() => setError(null)}>×</button>
        </div>
      )}

      <div className="tabs">
        <button
          className={`tab ${activeTab === 'view' ? 'active' : ''}`}
          onClick={() => setActiveTab('view')}
        >
          View Rules
        </button>
        <button
          className={`tab ${activeTab === 'manage' ? 'active' : ''}`}
          onClick={() => setActiveTab('manage')}
        >
          Manage Rules
        </button>
      </div>

      <div className="tab-content">
        {activeTab === 'view' && (
          <div className="view-rules-tab">
            <div className="view-controls">
              <button onClick={fetchRuleset} disabled={loading} className="btn-primary">
                {loading ? 'Loading...' : 'Load Ruleset'}
              </button>
              <button onClick={exportToJSON} disabled={!ruleset} className="btn-secondary">
                Export to JSON
              </button>
              <button onClick={clearFilters} className="btn-secondary">
                Clear Filters
              </button>
            </div>

            <div className="filters-section">
              <h3>Filters</h3>
              <div className="filters-grid">
                <div className="filter-item">
                  <label>Family</label>
                  <select
                    value={filters.family}
                    onChange={(e) => setFilters({ ...filters, family: e.target.value })}
                  >
                    <option value="">All</option>
                    <option value="ip">ip</option>
                    <option value="ip6">ip6</option>
                    <option value="inet">inet</option>
                    <option value="arp">arp</option>
                    <option value="bridge">bridge</option>
                  </select>
                </div>

                <div className="filter-item">
                  <label>Chain Name</label>
                  <input
                    type="text"
                    value={filters.chainName}
                    onChange={(e) => setFilters({ ...filters, chainName: e.target.value })}
                    placeholder="Filter by chain name"
                  />
                </div>

                <div className="filter-item">
                  <label>Verdict</label>
                  <select
                    value={filters.verdict}
                    onChange={(e) => setFilters({ ...filters, verdict: e.target.value })}
                  >
                    <option value="">All</option>
                    <option value="accept">accept</option>
                    <option value="drop">drop</option>
                    <option value="reject">reject</option>
                    <option value="return">return</option>
                    <option value="jump">jump</option>
                    <option value="goto">goto</option>
                  </select>
                </div>

                <div className="filter-item">
                  <label>Rule Handle</label>
                  <input
                    type="number"
                    value={filters.ruleHandle}
                    onChange={(e) => setFilters({ ...filters, ruleHandle: e.target.value })}
                    placeholder="Filter by handle"
                  />
                </div>

                <div className="filter-item filter-item-wide">
                  <label>Text Search</label>
                  <input
                    type="text"
                    value={filters.textSearch}
                    onChange={(e) => setFilters({ ...filters, textSearch: e.target.value })}
                    placeholder="Search in rule text"
                  />
                </div>
              </div>
            </div>

            <div className="rules-tree">
              {filteredTree && Object.keys(filteredTree).length > 0 ? (
                Object.entries(filteredTree).map(([family, tables]) => (
                  <div key={family} className="tree-family">
                    <div
                      className="tree-header clickable"
                      onClick={() => toggleExpand(`family-${family}`)}
                    >
                      <span className="expand-icon">
                        {expandedItems[`family-${family}`] ? '▼' : '▶'}
                      </span>
                      <strong>Family:</strong> {family}
                    </div>

                    {expandedItems[`family-${family}`] && (
                      <div className="tree-tables">
                        {Object.entries(tables).map(([tableName, tableData]) => (
                          <div key={`${family}-${tableName}`} className="tree-table">
                            <div
                              className="tree-header clickable"
                              onClick={() => toggleExpand(`table-${family}-${tableName}`)}
                            >
                              <span className="expand-icon">
                                {expandedItems[`table-${family}-${tableName}`] ? '▼' : '▶'}
                              </span>
                              <strong>Table:</strong> {tableName}
                              {tableData.handle && <span className="handle"> (handle: {tableData.handle})</span>}
                            </div>

                            {expandedItems[`table-${family}-${tableName}`] && (
                              <div className="tree-chains">
                                {Object.entries(tableData.chains).map(([chainName, chainData]) => (
                                  <div key={`${family}-${tableName}-${chainName}`} className="tree-chain">
                                    <div
                                      className="tree-header clickable"
                                      onClick={() => toggleExpand(`chain-${family}-${tableName}-${chainName}`)}
                                    >
                                      <span className="expand-icon">
                                        {expandedItems[`chain-${family}-${tableName}-${chainName}`] ? '▼' : '▶'}
                                      </span>
                                      <strong>Chain:</strong> {chainName}
                                    </div>

                                    <div className="chain-info">
                                      {chainData.type && <span className="badge">type: {chainData.type}</span>}
                                      {chainData.hook && <span className="badge">hook: {chainData.hook}</span>}
                                      {chainData.prio !== undefined && <span className="badge">priority: {chainData.prio}</span>}
                                      {chainData.policy && <span className="badge badge-policy">{chainData.policy}</span>}
                                      {chainData.handle && <span className="badge">handle: {chainData.handle}</span>}
                                    </div>

                                    {expandedItems[`chain-${family}-${tableName}-${chainName}`] && (
                                      <div className="tree-rules">
                                        {chainData.rules.length > 0 ? (
                                          <table className="rules-table">
                                            <thead>
                                              <tr>
                                                <th>Handle</th>
                                                <th>Rule</th>
                                                <th>Actions</th>
                                              </tr>
                                            </thead>
                                            <tbody>
                                              {chainData.rules.map((rule) => (
                                                <tr key={rule.handle}>
                                                  <td className="handle-cell">{rule.handle}</td>
                                                  <td className="rule-text">{rule.rule_text}</td>
                                                  <td className="actions-cell">
                                                    <button
                                                      className="btn-small btn-edit"
                                                      onClick={() => selectRuleForEdit(family, tableName, chainName, rule)}
                                                    >
                                                      Edit
                                                    </button>
                                                    <button
                                                      className="btn-small btn-delete"
                                                      onClick={() => handleDeleteRule(family, tableName, chainName, rule.handle)}
                                                    >
                                                      Delete
                                                    </button>
                                                  </td>
                                                </tr>
                                              ))}
                                            </tbody>
                                          </table>
                                        ) : (
                                          <div className="no-rules">No rules in this chain</div>
                                        )}
                                      </div>
                                    )}
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))
              ) : (
                <div className="no-data">
                  {ruleTree ? 'No rules match the current filters' : 'Click "Load Ruleset" to view rules'}
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'manage' && (
          <div className="manage-rules-tab">
            <div className="manage-header">
              <h2>{manageMode === 'add' ? 'Add New Rule' : 'Edit Rule'}</h2>
              {manageMode === 'edit' && (
                <button
                  onClick={() => {
                    setManageMode('add');
                    resetRuleForm();
                  }}
                  className="btn-secondary"
                >
                  Switch to Add Mode
                </button>
              )}
            </div>

            <div className="rule-form">
              <div className="form-section">
                <h3>Target</h3>
                <div className="form-grid">
                  <div className="form-item">
                    <label>Family *</label>
                    <select
                      value={ruleForm.family}
                      onChange={(e) => setRuleForm({ ...ruleForm, family: e.target.value, table: '', chain: '' })}
                      disabled={manageMode === 'edit'}
                    >
                      <option value="ip">ip (IPv4)</option>
                      <option value="ip6">ip6 (IPv6)</option>
                      <option value="inet">inet (IPv4 + IPv6)</option>
                      <option value="arp">arp</option>
                      <option value="bridge">bridge</option>
                    </select>
                  </div>

                  <div className="form-item">
                    <label>Table *</label>
                    <select
                      value={ruleForm.table}
                      onChange={(e) => setRuleForm({ ...ruleForm, table: e.target.value, chain: '' })}
                      disabled={manageMode === 'edit'}
                    >
                      <option value="">Select table</option>
                      {tables
                        .filter(t => t.family === ruleForm.family)
                        .map(t => (
                          <option key={`${t.family}-${t.name}`} value={t.name}>
                            {t.name}
                          </option>
                        ))
                      }
                    </select>
                  </div>

                  <div className="form-item">
                    <label>Chain *</label>
                    <select
                      value={ruleForm.chain}
                      onChange={(e) => setRuleForm({ ...ruleForm, chain: e.target.value })}
                      disabled={manageMode === 'edit'}
                    >
                      <option value="">Select chain</option>
                      {chains.map(c => (
                        <option key={c.name} value={c.name}>
                          {c.name} {c.hook ? `(${c.hook})` : ''}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>
              </div>

              <div className="form-section">
                <h3>Match Conditions</h3>

                <div className="form-subsection">
                  <h4>Protocol</h4>
                  <div className="form-grid">
                    <div className="form-item">
                      <label>Protocol</label>
                      <select
                        value={ruleForm.protocol}
                        onChange={(e) => setRuleForm({ ...ruleForm, protocol: e.target.value })}
                      >
                        <option value="">Any</option>
                        <option value="tcp">tcp</option>
                        <option value="udp">udp</option>
                        <option value="icmp">icmp</option>
                        <option value="icmpv6">icmpv6</option>
                      </select>
                    </div>
                  </div>
                </div>

                <div className="form-subsection">
                  <h4>TCP/UDP Ports</h4>
                  <div className="form-grid">
                    <div className="form-item">
                      <label>TCP Destination Port</label>
                      <input
                        type="text"
                        value={ruleForm.tcpDport}
                        onChange={(e) => setRuleForm({ ...ruleForm, tcpDport: e.target.value })}
                        placeholder="e.g., 80, 443, 8000-9000"
                      />
                    </div>
                    <div className="form-item">
                      <label>TCP Source Port</label>
                      <input
                        type="text"
                        value={ruleForm.tcpSport}
                        onChange={(e) => setRuleForm({ ...ruleForm, tcpSport: e.target.value })}
                        placeholder="e.g., 1024-65535"
                      />
                    </div>
                    <div className="form-item">
                      <label>UDP Destination Port</label>
                      <input
                        type="text"
                        value={ruleForm.udpDport}
                        onChange={(e) => setRuleForm({ ...ruleForm, udpDport: e.target.value })}
                        placeholder="e.g., 53, 123"
                      />
                    </div>
                    <div className="form-item">
                      <label>UDP Source Port</label>
                      <input
                        type="text"
                        value={ruleForm.udpSport}
                        onChange={(e) => setRuleForm({ ...ruleForm, udpSport: e.target.value })}
                        placeholder="e.g., 1024-65535"
                      />
                    </div>
                  </div>
                </div>

                <div className="form-subsection">
                  <h4>IP Addresses</h4>
                  <div className="form-grid">
                    <div className="form-item">
                      <label>Source IP</label>
                      <input
                        type="text"
                        value={ruleForm.ipSaddr}
                        onChange={(e) => setRuleForm({ ...ruleForm, ipSaddr: e.target.value })}
                        placeholder="e.g., 192.168.1.0/24"
                      />
                    </div>
                    <div className="form-item">
                      <label>Destination IP</label>
                      <input
                        type="text"
                        value={ruleForm.ipDaddr}
                        onChange={(e) => setRuleForm({ ...ruleForm, ipDaddr: e.target.value })}
                        placeholder="e.g., 10.0.0.1"
                      />
                    </div>
                  </div>
                </div>

                <div className="form-subsection">
                  <h4>Interfaces</h4>
                  <div className="form-grid">
                    <div className="form-item">
                      <label>Input Interface</label>
                      <input
                        type="text"
                        value={ruleForm.iifname}
                        onChange={(e) => setRuleForm({ ...ruleForm, iifname: e.target.value })}
                        placeholder="e.g., eth0, wlan0"
                      />
                    </div>
                    <div className="form-item">
                      <label>Output Interface</label>
                      <input
                        type="text"
                        value={ruleForm.oifname}
                        onChange={(e) => setRuleForm({ ...ruleForm, oifname: e.target.value })}
                        placeholder="e.g., eth0, wlan0"
                      />
                    </div>
                  </div>
                </div>

                <div className="form-subsection">
                  <h4>Connection Tracking</h4>
                  <div className="form-grid">
                    <div className="form-item">
                      <label>CT State</label>
                      <select
                        value={ruleForm.ctState}
                        onChange={(e) => setRuleForm({ ...ruleForm, ctState: e.target.value })}
                      >
                        <option value="">Any</option>
                        <option value="new">new</option>
                        <option value="established">established</option>
                        <option value="related">related</option>
                        <option value="invalid">invalid</option>
                        <option value="established,related">established,related</option>
                      </select>
                    </div>
                  </div>
                </div>
              </div>

              <div className="form-section">
                <h3>Action</h3>
                <div className="form-grid">
                  <div className="form-item">
                    <label>Action *</label>
                    <select
                      value={ruleForm.action}
                      onChange={(e) => setRuleForm({ ...ruleForm, action: e.target.value })}
                    >
                      <option value="accept">accept</option>
                      <option value="drop">drop</option>
                      <option value="reject">reject</option>
                      <option value="return">return</option>
                      <option value="jump">jump</option>
                      <option value="goto">goto</option>
                      <option value="log">log</option>
                    </select>
                  </div>

                  {(ruleForm.action === 'jump' || ruleForm.action === 'goto') && (
                    <div className="form-item">
                      <label>Target Chain</label>
                      <input
                        type="text"
                        value={ruleForm.jumpTarget}
                        onChange={(e) => setRuleForm({ ...ruleForm, jumpTarget: e.target.value })}
                        placeholder="Chain name"
                      />
                    </div>
                  )}

                  {ruleForm.action === 'log' && (
                    <div className="form-item">
                      <label>Log Prefix</label>
                      <input
                        type="text"
                        value={ruleForm.logPrefix}
                        onChange={(e) => setRuleForm({ ...ruleForm, logPrefix: e.target.value })}
                        placeholder="Log message prefix"
                      />
                    </div>
                  )}

                  <div className="form-item form-item-checkbox">
                    <label>
                      <input
                        type="checkbox"
                        checked={ruleForm.counterEnabled}
                        onChange={(e) => setRuleForm({ ...ruleForm, counterEnabled: e.target.checked })}
                      />
                      Enable counter
                    </label>
                  </div>
                </div>
              </div>

              <div className="form-section">
                <h3>Rule Preview</h3>
                <div className="rule-preview">
                  <button onClick={generateRulePreview} className="btn-secondary">
                    Generate Preview
                  </button>
                  <div className="preview-text">
                    <code>{rulePreview || 'Click "Generate Preview" to see rule'}</code>
                  </div>
                </div>
              </div>

              <div className="form-actions">
                {manageMode === 'add' ? (
                  <button onClick={handleAddRule} disabled={loading} className="btn-primary">
                    {loading ? 'Adding...' : 'Add Rule'}
                  </button>
                ) : (
                  <button onClick={handleUpdateRule} disabled={loading} className="btn-primary">
                    {loading ? 'Updating...' : 'Update Rule'}
                  </button>
                )}
                <button onClick={resetRuleForm} className="btn-secondary">
                  Reset Form
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default NFTablesManager;
