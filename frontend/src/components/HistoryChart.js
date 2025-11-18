import React, { useState, useEffect, useCallback } from 'react';
import Plot from 'react-plotly.js';
import axios from 'axios';
import './HistoryChart.css';

// Modern color palette (Grafana-inspired)
const COLORS = {
  packetsIn: '#73BF69',      // Green (packets in)
  accepted: '#5794F2',       // Blue (accepted)
  dropped: '#F2495C',        // Red (dropped)
  latencyAvg: '#FF9830',     // Orange (avg latency)
  latencyP99: '#B877D9',     // Purple (p99 latency)
  dropRate: '#FF5722'        // Red-orange (drop rate)
};

const HistoryChart = ({ enabled }) => {
  const [historyData, setHistoryData] = useState([]);
  const [timeRange, setTimeRange] = useState(1); // hours
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [summary, setSummary] = useState(null);

  // Format large numbers (10K, 1.5M, etc.)
  const formatNumber = (num) => {
    if (num >= 1000000) {
      return (num / 1000000).toFixed(1) + 'M';
    } else if (num >= 1000) {
      return (num / 1000).toFixed(1) + 'K';
    }
    return num.toFixed(0);
  };

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

  // Common Plotly layout configuration (Grafana-style)
  const getCommonLayout = (title, yAxisTitle) => ({
    title: {
      text: title,
      font: {
        family: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
        size: 16,
        color: '#D8D9DA',
        weight: 500
      },
      x: 0.02,
      xanchor: 'left'
    },
    xaxis: {
      title: '',
      type: 'date',
      gridcolor: 'rgba(255, 255, 255, 0.05)',
      gridwidth: 1,
      showgrid: true,
      zeroline: false,
      tickformat: '%H:%M\n%b %d',
      tickangle: 0,
      tickfont: {
        size: 11,
        color: '#9FA1A3'
      },
      showline: false
    },
    yaxis: {
      title: {
        text: yAxisTitle,
        font: {
          size: 12,
          color: '#9FA1A3'
        }
      },
      gridcolor: 'rgba(255, 255, 255, 0.05)',
      gridwidth: 1,
      showgrid: true,
      zeroline: false,
      tickformat: ',',
      tickfont: {
        size: 11,
        color: '#9FA1A3'
      },
      showline: false
    },
    height: 340,
    margin: { t: 50, r: 30, b: 60, l: 70 },
    paper_bgcolor: 'rgba(22, 23, 25, 0.95)',
    plot_bgcolor: 'rgba(22, 23, 25, 0.95)',
    font: {
      family: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      color: '#D8D9DA'
    },
    legend: {
      orientation: 'h',
      yanchor: 'bottom',
      y: 1.02,
      xanchor: 'left',
      x: 0,
      font: {
        size: 11,
        color: '#D8D9DA'
      },
      bgcolor: 'rgba(0, 0, 0, 0)'
    },
    hovermode: 'x unified',
    hoverlabel: {
      bgcolor: 'rgba(22, 23, 25, 0.98)',
      bordercolor: 'rgba(255, 255, 255, 0.1)',
      font: {
        family: 'Inter, "SF Mono", Consolas, monospace',
        size: 12,
        color: '#D8D9DA'
      }
    }
  });

  const chartData = prepareChartData();

  if (!enabled) {
    return (
      <div className="history-chart-container">
        <div className="history-chart-disabled">
          <p>📊 Enable Realtime Monitoring to view historical metrics</p>
        </div>
      </div>
    );
  }

  return (
    <div className="history-chart-container">
      <div className="history-chart-header">
        <div className="header-title">
          <h3>📈 Historical Metrics</h3>
          <span className="header-subtitle">Time-series visualization of network performance</span>
        </div>
        <div className="time-range-selector">
          <label>Time Range</label>
          <select value={timeRange} onChange={(e) => setTimeRange(Number(e.target.value))}>
            <option value={0.25}>Last 15 minutes</option>
            <option value={1}>Last 1 hour</option>
            <option value={3}>Last 3 hours</option>
            <option value={6}>Last 6 hours</option>
            <option value={12}>Last 12 hours</option>
            <option value={24}>Last 24 hours</option>
            <option value={72}>Last 3 days</option>
          </select>
        </div>
      </div>

      {loading && (
        <div className="loading-indicator">
          <div className="spinner"></div>
          <span>Loading metrics...</span>
        </div>
      )}

      {error && (
        <div className="error-message">
          <span className="error-icon">⚠️</span>
          {error}
        </div>
      )}

      {summary && (
        <div className="summary-stats">
          <div className="stat-card drop-rate">
            <div className="stat-icon">📉</div>
            <div className="stat-content">
              <div className="stat-label">Drop Rate</div>
              <div className="stat-value">{summary.drop_rate.toFixed(2)}%</div>
            </div>
            <div className="stat-sparkline"></div>
          </div>

          <div className="stat-card accept-rate">
            <div className="stat-icon">✓</div>
            <div className="stat-content">
              <div className="stat-label">Accept Rate</div>
              <div className="stat-value">
                {(100 - summary.drop_rate).toFixed(2)}%
              </div>
            </div>
            <div className="stat-sparkline"></div>
          </div>

          <div className="stat-card avg-latency">
            <div className="stat-icon">⚡</div>
            <div className="stat-content">
              <div className="stat-label">Avg Latency</div>
              <div className="stat-value">{summary.avg_latency_us.toFixed(1)} μs</div>
            </div>
            <div className="stat-sparkline"></div>
          </div>

          <div className="stat-card max-latency">
            <div className="stat-icon">🔥</div>
            <div className="stat-content">
              <div className="stat-label">P99 Latency</div>
              <div className="stat-value">{summary.max_latency_us.toFixed(1)} μs</div>
            </div>
            <div className="stat-sparkline"></div>
          </div>
        </div>
      )}

      {chartData && (
        <div className="charts-grid">
          {/* Packet Flow Chart */}
          <div className="chart-panel">
            <Plot
              data={[
                {
                  x: chartData.timestamps,
                  y: chartData.packetsIn,
                  type: 'scatter',
                  mode: 'lines',
                  name: 'Packets In',
                  line: {
                    color: COLORS.packetsIn,
                    width: 2.5,
                    shape: 'spline',
                    smoothing: 1.3
                  },
                  hovertemplate: '<b>Packets In</b><br>%{y:,.0f} pkts<br>%{x|%H:%M:%S}<extra></extra>'
                },
                {
                  x: chartData.timestamps,
                  y: chartData.packetsAccept,
                  type: 'scatter',
                  mode: 'lines',
                  name: 'Accepted',
                  line: {
                    color: COLORS.accepted,
                    width: 2,
                    shape: 'spline',
                    smoothing: 1.3
                  },
                  hovertemplate: '<b>Accepted</b><br>%{y:,.0f} pkts<br>%{x|%H:%M:%S}<extra></extra>'
                },
                {
                  x: chartData.timestamps,
                  y: chartData.packetsDrop,
                  type: 'scatter',
                  mode: 'lines',
                  name: 'Dropped',
                  line: {
                    color: COLORS.dropped,
                    width: 3,
                    shape: 'spline',
                    smoothing: 1.3
                  },
                  fill: 'tozeroy',
                  fillcolor: 'rgba(242, 73, 92, 0.08)',
                  hovertemplate: '<b>Dropped</b><br>%{y:,.0f} pkts<br>%{x|%H:%M:%S}<extra></extra>'
                }
              ]}
              layout={getCommonLayout('Packet Flow', 'Packets')}
              config={{
                responsive: true,
                displayModeBar: false
              }}
              style={{ width: '100%', height: '100%' }}
            />
          </div>

          {/* Latency Chart */}
          <div className="chart-panel">
            <Plot
              data={[
                {
                  x: chartData.timestamps,
                  y: chartData.latencyAvg,
                  type: 'scatter',
                  mode: 'lines',
                  name: 'Avg Latency',
                  line: {
                    color: COLORS.latencyAvg,
                    width: 2.5,
                    shape: 'spline',
                    smoothing: 1.3
                  },
                  hovertemplate: '<b>Avg Latency</b><br>%{y:.2f} μs<br>%{x|%H:%M:%S}<extra></extra>'
                },
                {
                  x: chartData.timestamps,
                  y: chartData.latencyP99,
                  type: 'scatter',
                  mode: 'lines',
                  name: 'P99 Latency',
                  line: {
                    color: COLORS.latencyP99,
                    width: 2.5,
                    dash: 'dot',
                    shape: 'spline',
                    smoothing: 1.3
                  },
                  hovertemplate: '<b>P99 Latency</b><br>%{y:.2f} μs<br>%{x|%H:%M:%S}<extra></extra>'
                }
              ]}
              layout={getCommonLayout('Latency', 'Latency (μs)')}
              config={{
                responsive: true,
                displayModeBar: false
              }}
              style={{ width: '100%', height: '100%' }}
            />
          </div>

          {/* Drop Rate Chart */}
          <div className="chart-panel full-width">
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
                  line: {
                    color: COLORS.dropRate,
                    width: 3,
                    shape: 'spline',
                    smoothing: 1.3
                  },
                  fill: 'tozeroy',
                  fillcolor: 'rgba(255, 87, 34, 0.08)',
                  hovertemplate: '<b>Drop Rate</b><br>%{y:.2f}%<br>%{x|%H:%M:%S}<extra></extra>'
                }
              ]}
              layout={{
                ...getCommonLayout('Drop Rate', 'Drop Rate (%)'),
                yaxis: {
                  ...getCommonLayout('', '').yaxis,
                  title: {
                    text: 'Drop Rate (%)',
                    font: {
                      size: 12,
                      color: '#9FA1A3'
                    }
                  },
                  range: [0, Math.max(5, Math.max(...chartData.packetsIn.map((pIn, idx) => {
                    const drops = chartData.packetsDrop[idx] || 0;
                    return pIn > 0 ? (drops / pIn * 100) : 0;
                  })) * 1.1)]
                }
              }}
              config={{
                responsive: true,
                displayModeBar: false
              }}
              style={{ width: '100%', height: '100%' }}
            />
          </div>
        </div>
      )}

      {!loading && (!chartData || historyData.length === 0) && (
        <div className="no-data-message">
          <div className="no-data-icon">📊</div>
          <h4>No Historical Data Available</h4>
          <p>Data will appear after monitoring runs for a while. Keep monitoring enabled to collect metrics.</p>
        </div>
      )}
    </div>
  );
};

export default HistoryChart;
