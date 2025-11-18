import React, { useState, useEffect, useCallback } from 'react';
import Plot from 'react-plotly.js';
import axios from 'axios';
import './HistoryChart.css';

const HistoryChart = ({ enabled }) => {
  const [historyData, setHistoryData] = useState([]);
  const [timeRange, setTimeRange] = useState(1); // hours
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [summary, setSummary] = useState(null);

  // Fetch historical data
  const fetchHistory = useCallback(async () => {
    if (!enabled) return;

    setLoading(true);
    setError(null);

    try {
      const response = await axios.get('/api/monitoring/history', {
        params: { hours: timeRange }
      });

      if (response.data.success) {
        setHistoryData(response.data.data);
      } else {
        setError(response.data.error || 'Failed to fetch history');
      }
    } catch (err) {
      setError(err.message || 'Network error');
    } finally {
      setLoading(false);
    }
  }, [enabled, timeRange]);

  // Fetch summary stats
  const fetchSummary = useCallback(async () => {
    if (!enabled) return;

    try {
      const response = await axios.get('/api/monitoring/summary', {
        params: { hours: timeRange }
      });
      setSummary(response.data);
    } catch (err) {
      console.error('Failed to fetch summary:', err);
    }
  }, [enabled, timeRange]);

  // Initial fetch and periodic updates
  useEffect(() => {
    if (enabled) {
      fetchHistory();
      fetchSummary();

      // Refresh every 5 seconds
      const interval = setInterval(() => {
        fetchHistory();
        fetchSummary();
      }, 5000);

      return () => clearInterval(interval);
    }
  }, [enabled, fetchHistory, fetchSummary]);

  // Prepare data for charts
  const prepareChartData = () => {
    if (!historyData || historyData.length === 0) {
      return null;
    }

    const timestamps = historyData.map(d => new Date(d.timestamp * 1000));
    const packetsIn = historyData.map(d => d.packets_in || 0);
    const packetsDrop = historyData.map(d => d.packets_drop || 0);
    const packetsAccept = historyData.map(d => d.packets_accept || 0);
    const latencyAvg = historyData.map(d => d.latency_avg_us || 0);
    const latencyP99 = historyData.map(d => d.latency_p99_us || 0);

    return {
      timestamps,
      packetsIn,
      packetsDrop,
      packetsAccept,
      latencyAvg,
      latencyP99
    };
  };

  const chartData = prepareChartData();

  if (!enabled) {
    return (
      <div className="history-chart-container">
        <div className="history-chart-disabled">
          <p>Enable Realtime Monitoring to view historical data</p>
        </div>
      </div>
    );
  }

  return (
    <div className="history-chart-container">
      <div className="history-chart-header">
        <h3>Historical Metrics</h3>
        <div className="time-range-selector">
          <label>Time Range:</label>
          <select value={timeRange} onChange={(e) => setTimeRange(Number(e.target.value))}>
            <option value={0.25}>15 minutes</option>
            <option value={1}>1 hour</option>
            <option value={3}>3 hours</option>
            <option value={6}>6 hours</option>
            <option value={12}>12 hours</option>
            <option value={24}>24 hours</option>
            <option value={72}>3 days</option>
          </select>
        </div>
      </div>

      {loading && <div className="loading-indicator">Loading...</div>}
      {error && <div className="error-message">{error}</div>}

      {summary && (
        <div className="summary-stats">
          <div className="stat-card">
            <div className="stat-label">Total Packets</div>
            <div className="stat-value">{summary.total_packets.toLocaleString()}</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Total Drops</div>
            <div className="stat-value">{summary.total_drops.toLocaleString()}</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Drop Rate</div>
            <div className="stat-value">{summary.drop_rate.toFixed(2)}%</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Avg Latency</div>
            <div className="stat-value">{summary.avg_latency_us.toFixed(2)} μs</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Max Latency</div>
            <div className="stat-value">{summary.max_latency_us.toFixed(2)} μs</div>
          </div>
        </div>
      )}

      {chartData && (
        <div className="charts-grid">
          {/* Packet Flow Chart */}
          <div className="chart-wrapper">
            <Plot
              data={[
                {
                  x: chartData.timestamps,
                  y: chartData.packetsIn,
                  type: 'scatter',
                  mode: 'lines',
                  name: 'Packets In',
                  line: { color: '#4CAF50', width: 2 }
                },
                {
                  x: chartData.timestamps,
                  y: chartData.packetsAccept,
                  type: 'scatter',
                  mode: 'lines',
                  name: 'Accepted',
                  line: { color: '#2196F3', width: 2 }
                },
                {
                  x: chartData.timestamps,
                  y: chartData.packetsDrop,
                  type: 'scatter',
                  mode: 'lines',
                  name: 'Dropped',
                  line: { color: '#f44336', width: 2 },
                  fill: 'tozeroy'
                }
              ]}
              layout={{
                title: 'Packet Flow Over Time',
                xaxis: {
                  title: 'Time',
                  type: 'date'
                },
                yaxis: {
                  title: 'Packet Count'
                },
                height: 300,
                margin: { t: 40, r: 20, b: 40, l: 60 },
                legend: {
                  x: 0,
                  y: 1,
                  orientation: 'h'
                },
                paper_bgcolor: '#1a1a1a',
                plot_bgcolor: '#2a2a2a',
                font: { color: '#ffffff' }
              }}
              config={{ responsive: true }}
              style={{ width: '100%' }}
            />
          </div>

          {/* Latency Chart */}
          <div className="chart-wrapper">
            <Plot
              data={[
                {
                  x: chartData.timestamps,
                  y: chartData.latencyAvg,
                  type: 'scatter',
                  mode: 'lines',
                  name: 'Avg Latency',
                  line: { color: '#FF9800', width: 2 }
                },
                {
                  x: chartData.timestamps,
                  y: chartData.latencyP99,
                  type: 'scatter',
                  mode: 'lines',
                  name: 'P99 Latency',
                  line: { color: '#E91E63', width: 2, dash: 'dot' }
                }
              ]}
              layout={{
                title: 'Latency Over Time',
                xaxis: {
                  title: 'Time',
                  type: 'date'
                },
                yaxis: {
                  title: 'Latency (μs)'
                },
                height: 300,
                margin: { t: 40, r: 20, b: 40, l: 60 },
                legend: {
                  x: 0,
                  y: 1,
                  orientation: 'h'
                },
                paper_bgcolor: '#1a1a1a',
                plot_bgcolor: '#2a2a2a',
                font: { color: '#ffffff' }
              }}
              config={{ responsive: true }}
              style={{ width: '100%' }}
            />
          </div>

          {/* Drop Rate Chart */}
          <div className="chart-wrapper">
            <Plot
              data={[
                {
                  x: chartData.timestamps,
                  y: chartData.packetsIn.map((pIn, idx) => {
                    const drops = chartData.packetsDrop[idx] || 0;
                    return pIn > 0 ? (drops / pIn * 100) : 0;
                  }),
                  type: 'scatter',
                  mode: 'lines',
                  name: 'Drop Rate',
                  line: { color: '#FF5722', width: 2 },
                  fill: 'tozeroy'
                }
              ]}
              layout={{
                title: 'Drop Rate Over Time',
                xaxis: {
                  title: 'Time',
                  type: 'date'
                },
                yaxis: {
                  title: 'Drop Rate (%)',
                  range: [0, 100]
                },
                height: 300,
                margin: { t: 40, r: 20, b: 40, l: 60 },
                paper_bgcolor: '#1a1a1a',
                plot_bgcolor: '#2a2a2a',
                font: { color: '#ffffff' }
              }}
              config={{ responsive: true }}
              style={{ width: '100%' }}
            />
          </div>
        </div>
      )}

      {!loading && (!chartData || historyData.length === 0) && (
        <div className="no-data-message">
          <p>No historical data available yet. Data will appear after monitoring runs for a while.</p>
        </div>
      )}
    </div>
  );
};

export default HistoryChart;
