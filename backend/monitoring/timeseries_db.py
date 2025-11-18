"""
Time-Series Database for NFT Tracer Monitoring
Stores historical metrics with automatic aggregation and cleanup
"""

import sqlite3
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import json
import logging

logger = logging.getLogger(__name__)


class TimeSeriesDB:
    """
    Time-series database for storing network monitoring metrics

    Storage strategy:
    - Raw data (1s granularity): 1 hour retention
    - 1min aggregation: 24 hours retention
    - 5min aggregation: 3 days retention

    Metrics stored:
    - packets_in, packets_out, packets_drop, packets_accept
    - bytes_in, bytes_out
    - latency_avg_us, latency_p99_us
    - error_count, active_flows
    - verdict breakdown (JSON)
    - node statistics (JSON)
    """

    def __init__(self, db_path: str = None):
        """
        Initialize time-series database

        Args:
            db_path: Path to SQLite database file.
                    Defaults to backend/data/monitoring.db
        """
        if db_path is None:
            # Default to backend/data/monitoring.db
            backend_dir = Path(__file__).parent.parent
            data_dir = backend_dir / 'data'
            data_dir.mkdir(exist_ok=True)
            db_path = str(data_dir / 'monitoring.db')

        self.db_path = db_path
        self.lock = threading.RLock()

        # Initialize database schema
        self._init_db()

        # Start background cleanup thread
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_worker,
            daemon=True,
            name="TimeSeriesDB-Cleanup"
        )
        self._cleanup_thread.start()

        logger.info(f"TimeSeriesDB initialized: {db_path}")

    def _init_db(self):
        """Initialize database schema"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Raw metrics table (1 second granularity, 1 hour retention)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metrics_raw (
                    timestamp INTEGER PRIMARY KEY,
                    packets_in INTEGER DEFAULT 0,
                    packets_out INTEGER DEFAULT 0,
                    packets_drop INTEGER DEFAULT 0,
                    packets_accept INTEGER DEFAULT 0,
                    bytes_in INTEGER DEFAULT 0,
                    bytes_out INTEGER DEFAULT 0,
                    latency_avg_us REAL DEFAULT 0,
                    latency_p99_us REAL DEFAULT 0,
                    error_count INTEGER DEFAULT 0,
                    active_flows INTEGER DEFAULT 0,
                    verdict_breakdown TEXT,
                    node_stats TEXT,
                    pipeline_stats TEXT
                )
            """)

            # 1-minute aggregation (24 hours retention)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metrics_1min (
                    timestamp INTEGER PRIMARY KEY,
                    packets_in INTEGER DEFAULT 0,
                    packets_out INTEGER DEFAULT 0,
                    packets_drop INTEGER DEFAULT 0,
                    packets_accept INTEGER DEFAULT 0,
                    bytes_in INTEGER DEFAULT 0,
                    bytes_out INTEGER DEFAULT 0,
                    latency_avg_us REAL DEFAULT 0,
                    latency_p99_us REAL DEFAULT 0,
                    error_count INTEGER DEFAULT 0,
                    active_flows INTEGER DEFAULT 0,
                    verdict_breakdown TEXT,
                    node_stats TEXT,
                    pipeline_stats TEXT
                )
            """)

            # 5-minute aggregation (3 days retention)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metrics_5min (
                    timestamp INTEGER PRIMARY KEY,
                    packets_in INTEGER DEFAULT 0,
                    packets_out INTEGER DEFAULT 0,
                    packets_drop INTEGER DEFAULT 0,
                    packets_accept INTEGER DEFAULT 0,
                    bytes_in INTEGER DEFAULT 0,
                    bytes_out INTEGER DEFAULT 0,
                    latency_avg_us REAL DEFAULT 0,
                    latency_p99_us REAL DEFAULT 0,
                    error_count INTEGER DEFAULT 0,
                    active_flows INTEGER DEFAULT 0,
                    verdict_breakdown TEXT,
                    node_stats TEXT,
                    pipeline_stats TEXT
                )
            """)

            # Create indexes for faster time-range queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_raw_timestamp
                ON metrics_raw(timestamp)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_1min_timestamp
                ON metrics_1min(timestamp)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_5min_timestamp
                ON metrics_5min(timestamp)
            """)

            conn.commit()
            conn.close()

    def insert_metrics(self, metrics: Dict):
        """
        Insert current metrics snapshot

        Args:
            metrics: Dictionary containing current metrics from RealtimeTracer
        """
        timestamp = int(time.time())

        # Extract metrics from the realtime stats structure
        packets_in = metrics.get('total_packets', 0)
        packets_drop = metrics.get('total_verdicts', {}).get('DROP', 0)
        packets_accept = metrics.get('total_verdicts', {}).get('ACCEPT', 0)

        # Calculate packets_out from outbound pipeline
        packets_out = 0
        for pipeline in metrics.get('pipelines', []):
            if pipeline.get('name') == 'Outbound':
                packets_out = pipeline.get('completed', 0)

        # Get latency stats
        latency_avg = 0
        latency_p99 = 0
        top_latency = metrics.get('top_latency', [])
        if top_latency:
            latencies = [node.get('avg_latency_us', 0) for node in top_latency]
            latency_avg = sum(latencies) / len(latencies) if latencies else 0
            latency_p99 = max(latencies) if latencies else 0

        # Error count from nodes
        error_count = sum(
            node.get('error_count', 0)
            for node in metrics.get('nodes', {}).values()
        )

        # Active flows (estimate from unique SKBs)
        active_flows = len(metrics.get('active_skbs', set()))

        # Serialize complex data as JSON
        verdict_breakdown = json.dumps(metrics.get('total_verdicts', {}))
        node_stats = json.dumps(metrics.get('nodes', {}))
        pipeline_stats = json.dumps(metrics.get('pipelines', []))

        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT OR REPLACE INTO metrics_raw
                (timestamp, packets_in, packets_out, packets_drop, packets_accept,
                 bytes_in, bytes_out, latency_avg_us, latency_p99_us,
                 error_count, active_flows, verdict_breakdown, node_stats, pipeline_stats)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp, packets_in, packets_out, packets_drop, packets_accept,
                0, 0,  # bytes_in, bytes_out (TODO: track from eBPF)
                latency_avg, latency_p99,
                error_count, active_flows,
                verdict_breakdown, node_stats, pipeline_stats
            ))

            conn.commit()
            conn.close()

    def get_metrics(
        self,
        start_time: Optional[int] = None,
        end_time: Optional[int] = None,
        granularity: str = 'auto'
    ) -> List[Dict]:
        """
        Query metrics for a time range

        Args:
            start_time: Start timestamp (unix seconds). Default: 1 hour ago
            end_time: End timestamp (unix seconds). Default: now
            granularity: 'raw', '1min', '5min', or 'auto' (auto-select based on range)

        Returns:
            List of metric dictionaries with timestamp and values
        """
        if end_time is None:
            end_time = int(time.time())
        if start_time is None:
            start_time = end_time - 3600  # Default: last hour

        # Auto-select granularity based on time range
        time_range = end_time - start_time
        if granularity == 'auto':
            if time_range <= 3600:  # <= 1 hour
                granularity = 'raw'
            elif time_range <= 86400:  # <= 24 hours
                granularity = '1min'
            else:  # > 24 hours
                granularity = '5min'

        # Select appropriate table
        table_map = {
            'raw': 'metrics_raw',
            '1min': 'metrics_1min',
            '5min': 'metrics_5min'
        }
        table = table_map.get(granularity, 'metrics_raw')

        with self.lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute(f"""
                SELECT * FROM {table}
                WHERE timestamp >= ? AND timestamp <= ?
                ORDER BY timestamp ASC
            """, (start_time, end_time))

            rows = cursor.fetchall()
            conn.close()

        # Convert to list of dicts
        results = []
        for row in rows:
            metric = dict(row)
            # Parse JSON fields
            if metric.get('verdict_breakdown'):
                metric['verdict_breakdown'] = json.loads(metric['verdict_breakdown'])
            if metric.get('node_stats'):
                metric['node_stats'] = json.loads(metric['node_stats'])
            if metric.get('pipeline_stats'):
                metric['pipeline_stats'] = json.loads(metric['pipeline_stats'])
            results.append(metric)

        return results

    def aggregate_1min(self):
        """Aggregate raw data into 1-minute intervals"""
        now = int(time.time())
        last_minute = (now // 60) * 60 - 60  # Previous complete minute

        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Aggregate raw data from the last minute
            cursor.execute("""
                INSERT OR REPLACE INTO metrics_1min
                SELECT
                    ? as timestamp,
                    SUM(packets_in) as packets_in,
                    SUM(packets_out) as packets_out,
                    SUM(packets_drop) as packets_drop,
                    SUM(packets_accept) as packets_accept,
                    SUM(bytes_in) as bytes_in,
                    SUM(bytes_out) as bytes_out,
                    AVG(latency_avg_us) as latency_avg_us,
                    MAX(latency_p99_us) as latency_p99_us,
                    SUM(error_count) as error_count,
                    AVG(active_flows) as active_flows,
                    NULL as verdict_breakdown,
                    NULL as node_stats,
                    NULL as pipeline_stats
                FROM metrics_raw
                WHERE timestamp >= ? AND timestamp < ?
            """, (last_minute, last_minute, last_minute + 60))

            conn.commit()
            conn.close()

    def aggregate_5min(self):
        """Aggregate 1-minute data into 5-minute intervals"""
        now = int(time.time())
        last_5min = (now // 300) * 300 - 300  # Previous complete 5-minute block

        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT OR REPLACE INTO metrics_5min
                SELECT
                    ? as timestamp,
                    SUM(packets_in) as packets_in,
                    SUM(packets_out) as packets_out,
                    SUM(packets_drop) as packets_drop,
                    SUM(packets_accept) as packets_accept,
                    SUM(bytes_in) as bytes_in,
                    SUM(bytes_out) as bytes_out,
                    AVG(latency_avg_us) as latency_avg_us,
                    MAX(latency_p99_us) as latency_p99_us,
                    SUM(error_count) as error_count,
                    AVG(active_flows) as active_flows,
                    NULL as verdict_breakdown,
                    NULL as node_stats,
                    NULL as pipeline_stats
                FROM metrics_1min
                WHERE timestamp >= ? AND timestamp < ?
            """, (last_5min, last_5min, last_5min + 300))

            conn.commit()
            conn.close()

    def cleanup_old_data(self):
        """Remove data older than retention periods"""
        now = int(time.time())

        # Retention periods
        raw_cutoff = now - 3600        # 1 hour
        min1_cutoff = now - 86400      # 24 hours
        min5_cutoff = now - 259200     # 3 days

        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Delete old raw data
            cursor.execute("DELETE FROM metrics_raw WHERE timestamp < ?", (raw_cutoff,))
            raw_deleted = cursor.rowcount

            # Delete old 1-minute data
            cursor.execute("DELETE FROM metrics_1min WHERE timestamp < ?", (min1_cutoff,))
            min1_deleted = cursor.rowcount

            # Delete old 5-minute data
            cursor.execute("DELETE FROM metrics_5min WHERE timestamp < ?", (min5_cutoff,))
            min5_deleted = cursor.rowcount

            # Vacuum to reclaim space
            cursor.execute("VACUUM")

            conn.commit()
            conn.close()

            if raw_deleted + min1_deleted + min5_deleted > 0:
                logger.info(
                    f"Cleaned up old data: {raw_deleted} raw, "
                    f"{min1_deleted} 1min, {min5_deleted} 5min records"
                )

    def _cleanup_worker(self):
        """Background thread for periodic cleanup and aggregation"""
        while True:
            try:
                time.sleep(60)  # Run every minute

                # Run aggregations
                self.aggregate_1min()

                # Run 5-minute aggregation every 5 minutes
                if int(time.time()) % 300 < 60:
                    self.aggregate_5min()

                # Run cleanup every hour
                if int(time.time()) % 3600 < 60:
                    self.cleanup_old_data()

            except Exception as e:
                logger.error(f"Error in cleanup worker: {e}", exc_info=True)

    def get_summary_stats(self, hours: int = 1) -> Dict:
        """
        Get summary statistics for the last N hours

        Args:
            hours: Number of hours to look back (max 72 for 3 days)

        Returns:
            Dictionary with summary stats
        """
        end_time = int(time.time())
        start_time = end_time - (hours * 3600)

        metrics = self.get_metrics(start_time, end_time, granularity='auto')

        if not metrics:
            return {
                'time_range_hours': hours,
                'total_packets': 0,
                'total_drops': 0,
                'drop_rate': 0,
                'avg_latency_us': 0,
                'max_latency_us': 0
            }

        total_packets = sum(m['packets_in'] for m in metrics)
        total_drops = sum(m['packets_drop'] for m in metrics)
        drop_rate = (total_drops / total_packets * 100) if total_packets > 0 else 0

        latencies = [m['latency_avg_us'] for m in metrics if m['latency_avg_us'] > 0]
        avg_latency = sum(latencies) / len(latencies) if latencies else 0
        max_latency = max((m['latency_p99_us'] for m in metrics), default=0)

        return {
            'time_range_hours': hours,
            'start_time': start_time,
            'end_time': end_time,
            'data_points': len(metrics),
            'total_packets': total_packets,
            'total_drops': total_drops,
            'drop_rate': round(drop_rate, 2),
            'avg_latency_us': round(avg_latency, 2),
            'max_latency_us': round(max_latency, 2)
        }

    def close(self):
        """Close database connection"""
        # Nothing to close (connections are opened/closed per operation)
        pass
