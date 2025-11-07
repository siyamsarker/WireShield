package database

import (
	"time"
)

// AuditLogRepository handles audit log operations
type AuditLogRepository struct {
	db *DB
}

// NewAuditLogRepository creates a new audit log repository
func NewAuditLogRepository(db *DB) *AuditLogRepository {
	return &AuditLogRepository{db: db}
}

// Log records an audit event
func (r *AuditLogRepository) Log(log *AuditLog) error {
	if log.Timestamp.IsZero() {
		log.Timestamp = time.Now()
	}

	result, err := r.db.Exec(`
		INSERT INTO audit_logs (timestamp, username, action, resource_type, resource_name, ip_address, user_agent, details, success)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, log.Timestamp, log.Username, log.Action, log.ResourceType, log.ResourceName, log.IPAddress, log.UserAgent, log.Details, log.Success)

	if err != nil {
		return err
	}

	log.ID, err = result.LastInsertId()
	return err
}

// List retrieves audit logs with pagination
func (r *AuditLogRepository) List(limit, offset int) ([]*AuditLog, error) {
	if limit <= 0 {
		limit = 50
	}

	rows, err := r.db.Query(`
		SELECT id, timestamp, username, action, resource_type, resource_name, ip_address, user_agent, details, success
		FROM audit_logs
		ORDER BY timestamp DESC
		LIMIT ? OFFSET ?
	`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*AuditLog
	for rows.Next() {
		log := &AuditLog{}
		err := rows.Scan(&log.ID, &log.Timestamp, &log.Username, &log.Action, &log.ResourceType,
			&log.ResourceName, &log.IPAddress, &log.UserAgent, &log.Details, &log.Success)
		if err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}
	return logs, rows.Err()
}

// ListByUsername retrieves logs for a specific user
func (r *AuditLogRepository) ListByUsername(username string, limit, offset int) ([]*AuditLog, error) {
	if limit <= 0 {
		limit = 50
	}

	rows, err := r.db.Query(`
		SELECT id, timestamp, username, action, resource_type, resource_name, ip_address, user_agent, details, success
		FROM audit_logs
		WHERE username = ?
		ORDER BY timestamp DESC
		LIMIT ? OFFSET ?
	`, username, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*AuditLog
	for rows.Next() {
		log := &AuditLog{}
		err := rows.Scan(&log.ID, &log.Timestamp, &log.Username, &log.Action, &log.ResourceType,
			&log.ResourceName, &log.IPAddress, &log.UserAgent, &log.Details, &log.Success)
		if err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}
	return logs, rows.Err()
}

// ListByResource retrieves logs for a specific resource
func (r *AuditLogRepository) ListByResource(resourceType, resourceName string, limit, offset int) ([]*AuditLog, error) {
	if limit <= 0 {
		limit = 50
	}

	rows, err := r.db.Query(`
		SELECT id, timestamp, username, action, resource_type, resource_name, ip_address, user_agent, details, success
		FROM audit_logs
		WHERE resource_type = ? AND resource_name = ?
		ORDER BY timestamp DESC
		LIMIT ? OFFSET ?
	`, resourceType, resourceName, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*AuditLog
	for rows.Next() {
		log := &AuditLog{}
		err := rows.Scan(&log.ID, &log.Timestamp, &log.Username, &log.Action, &log.ResourceType,
			&log.ResourceName, &log.IPAddress, &log.UserAgent, &log.Details, &log.Success)
		if err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}
	return logs, rows.Err()
}

// Count returns total number of audit logs
func (r *AuditLogRepository) Count() (int, error) {
	var count int
	err := r.db.QueryRow(`SELECT COUNT(*) FROM audit_logs`).Scan(&count)
	return count, err
}

// Cleanup removes logs older than the specified duration
func (r *AuditLogRepository) Cleanup(olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan)
	result, err := r.db.Exec(`DELETE FROM audit_logs WHERE timestamp < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// MetricsRepository handles system and bandwidth metrics
type MetricsRepository struct {
	db *DB
}

// NewMetricsRepository creates a new metrics repository
func NewMetricsRepository(db *DB) *MetricsRepository {
	return &MetricsRepository{db: db}
}

// RecordSystemMetric stores a system metric snapshot
func (r *MetricsRepository) RecordSystemMetric(metric *SystemMetric) error {
	if metric.Timestamp.IsZero() {
		metric.Timestamp = time.Now()
	}

	result, err := r.db.Exec(`
		INSERT INTO system_metrics (timestamp, cpu_percent, mem_used_bytes, mem_used_percent, total_rx_bytes, total_tx_bytes, active_peers)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, metric.Timestamp, metric.CPUPercent, metric.MemUsedBytes, metric.MemUsedPercent, metric.TotalRxBytes, metric.TotalTxBytes, metric.ActivePeers)

	if err != nil {
		return err
	}

	metric.ID, err = result.LastInsertId()
	return err
}

// GetSystemMetrics retrieves system metrics within a time range
func (r *MetricsRepository) GetSystemMetrics(from, to time.Time, limit int) ([]*SystemMetric, error) {
	if limit <= 0 {
		limit = 1000
	}

	rows, err := r.db.Query(`
		SELECT id, timestamp, cpu_percent, mem_used_bytes, mem_used_percent, total_rx_bytes, total_tx_bytes, active_peers
		FROM system_metrics
		WHERE timestamp BETWEEN ? AND ?
		ORDER BY timestamp ASC
		LIMIT ?
	`, from, to, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metrics []*SystemMetric
	for rows.Next() {
		metric := &SystemMetric{}
		err := rows.Scan(&metric.ID, &metric.Timestamp, &metric.CPUPercent, &metric.MemUsedBytes,
			&metric.MemUsedPercent, &metric.TotalRxBytes, &metric.TotalTxBytes, &metric.ActivePeers)
		if err != nil {
			return nil, err
		}
		metrics = append(metrics, metric)
	}
	return metrics, rows.Err()
}

// RecordBandwidthStat stores bandwidth statistics for a client
func (r *MetricsRepository) RecordBandwidthStat(stat *BandwidthStat) error {
	if stat.Timestamp.IsZero() {
		stat.Timestamp = time.Now()
	}

	result, err := r.db.Exec(`
		INSERT INTO bandwidth_stats (timestamp, client_id, rx_bytes, tx_bytes)
		VALUES (?, ?, ?, ?)
	`, stat.Timestamp, stat.ClientID, stat.RxBytes, stat.TxBytes)

	if err != nil {
		return err
	}

	stat.ID, err = result.LastInsertId()
	return err
}

// GetBandwidthStats retrieves bandwidth stats for a client
func (r *MetricsRepository) GetBandwidthStats(clientID int64, from, to time.Time, limit int) ([]*BandwidthStat, error) {
	if limit <= 0 {
		limit = 1000
	}

	rows, err := r.db.Query(`
		SELECT id, timestamp, client_id, rx_bytes, tx_bytes
		FROM bandwidth_stats
		WHERE client_id = ? AND timestamp BETWEEN ? AND ?
		ORDER BY timestamp ASC
		LIMIT ?
	`, clientID, from, to, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []*BandwidthStat
	for rows.Next() {
		stat := &BandwidthStat{}
		err := rows.Scan(&stat.ID, &stat.Timestamp, &stat.ClientID, &stat.RxBytes, &stat.TxBytes)
		if err != nil {
			return nil, err
		}
		stats = append(stats, stat)
	}
	return stats, rows.Err()
}

// CleanupOldMetrics removes metrics older than the specified duration
func (r *MetricsRepository) CleanupOldMetrics(olderThan time.Duration) error {
	cutoff := time.Now().Add(-olderThan)

	// Clean system metrics
	_, err := r.db.Exec(`DELETE FROM system_metrics WHERE timestamp < ?`, cutoff)
	if err != nil {
		return err
	}

	// Clean bandwidth stats
	_, err = r.db.Exec(`DELETE FROM bandwidth_stats WHERE timestamp < ?`, cutoff)
	return err
}

// SettingsRepository handles configuration settings
type SettingsRepository struct {
	db *DB
}

// NewSettingsRepository creates a new settings repository
func NewSettingsRepository(db *DB) *SettingsRepository {
	return &SettingsRepository{db: db}
}

// Set stores or updates a setting
func (r *SettingsRepository) Set(key, value string) error {
	_, err := r.db.Exec(`
		INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
	`, key, value, time.Now())
	return err
}

// Get retrieves a setting value
func (r *SettingsRepository) Get(key string) (string, error) {
	var value string
	err := r.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	if err != nil {
		return "", err
	}
	return value, nil
}

// GetWithDefault retrieves a setting or returns default if not found
func (r *SettingsRepository) GetWithDefault(key, defaultValue string) string {
	value, err := r.Get(key)
	if err != nil {
		return defaultValue
	}
	return value
}

// Delete removes a setting
func (r *SettingsRepository) Delete(key string) error {
	_, err := r.db.Exec(`DELETE FROM settings WHERE key = ?`, key)
	return err
}

// All retrieves all settings
func (r *SettingsRepository) All() (map[string]string, error) {
	rows, err := r.db.Query(`SELECT key, value FROM settings ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	settings := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		settings[key] = value
	}
	return settings, rows.Err()
}
