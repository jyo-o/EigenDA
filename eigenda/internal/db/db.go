package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

type ObservedBlob struct {
	BlobKey            string
	AccountID          string
	BlobStatus         string
	BlobSizeBytes      int
	RequestedAt        uint64
	ExpiryUnixSec      uint64
	CommitmentX        string
	CommitmentY        string
	QuorumNumbers      string
	IsSelfDispersed    bool
	DispersalLatencyMs int
	CumulativePayment  *string // from DataAPI PaymentMetadata, nullable
}

type ProbeResult struct {
	BlobKey       string
	BlobAgeHours  float64
	RelayKey      int
	Success       bool
	LatencyMs     int
	ErrorMessage  string
	DataSizeBytes int
	KZGVerified   *bool
	KZGError      string
}

type AttestationSnapshot struct {
	BlobKey               string
	QuorumNumber          int
	TotalNonSigners       int
	SigningStakePercentage float64
}

type OperatorProbeResult struct {
	BlobKey        string
	BlobAgeHours   float64
	OperatorID     string
	OperatorSocket string
	QuorumID       int
	Success        bool
	LatencyMs      int
	ChunksReturned int
	ErrorMessage   string
}

type StakeSnapshot struct {
	QuorumID      int
	TotalStake    string
	OperatorCount int
	HHI           float64
}

type StakeSnapshotOperator struct {
	QuorumID   int
	OperatorID string
	Stake      string
	StakePct   float64
}

type EjectionEvent struct {
	EventTime    time.Time
	BlockNumber  int64
	TxHash       string
	LogIndex     int
	OperatorID   string
	QuorumNumber int
}

type OperatorStatus struct {
	OperatorAddress string
	MetadataName    string
	Status          string // "active" or "inactive"
	TotalStakers    int
	TotalAvs        int
	TVLETH          float64
}

type AttestationNonsigner struct {
	BlobKey      string
	QuorumNumber int
	OperatorID   string // 0x-prefixed 64-char keccak256 hex
}

type AgedBlobKey struct {
	BlobKey     string
	RequestedAt uint64
}

type DB struct {
	conn *sql.DB
}

func New(databaseURL string) (*DB, error) {
	conn, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	conn.SetMaxOpenConns(10)
	conn.SetMaxIdleConns(5)
	conn.SetConnMaxLifetime(5 * time.Minute)

	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}

	return &DB{conn: conn}, nil
}

func (d *DB) RunMigrations(ctx context.Context) error {
	migrations := `
CREATE SCHEMA IF NOT EXISTS eigenda;

CREATE TABLE IF NOT EXISTS eigenda.observed_blobs (
    blob_key         VARCHAR(128) PRIMARY KEY,
    account_id       VARCHAR(64),
    blob_status      VARCHAR(32),
    blob_size_bytes  INTEGER,
    requested_at     BIGINT,
    expiry_unix_sec  BIGINT,
    commitment_x     TEXT,
    commitment_y     TEXT,
    quorum_numbers   TEXT,
    is_self_dispersed BOOLEAN DEFAULT FALSE,
    dispersal_latency_ms INTEGER,
    first_observed_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS eigenda.indexer_cursors (
    indexer_name     VARCHAR(64) PRIMARY KEY,
    last_block       BIGINT NOT NULL DEFAULT 0,
    updated_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS eigenda.retrieval_probes (
    probe_time       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    blob_key         VARCHAR(128) NOT NULL,
    blob_age_hours   FLOAT,
    relay_key        INTEGER,
    success          BOOLEAN,
    latency_ms       INTEGER,
    error_message    TEXT,
    data_size_bytes  INTEGER,
    kzg_verified     BOOLEAN,
    kzg_error        TEXT
);

CREATE TABLE IF NOT EXISTS eigenda.operator_probes (
    probe_time       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    blob_key         VARCHAR(128) NOT NULL,
    blob_age_hours   FLOAT,
    operator_id      VARCHAR(128),
    operator_socket  TEXT,
    quorum_id        INTEGER,
    success          BOOLEAN,
    latency_ms       INTEGER,
    chunks_returned  INTEGER,
    error_message    TEXT
);

CREATE TABLE IF NOT EXISTS eigenda.attestation_snapshots (
    snapshot_time            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    blob_key                 VARCHAR(128) NOT NULL,
    quorum_number            INTEGER,
    total_nonsigners         INTEGER,
    signing_stake_percentage FLOAT
);

CREATE TABLE IF NOT EXISTS eigenda.stake_snapshots (
    snapshot_time    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    quorum_id        INTEGER NOT NULL,
    total_stake      NUMERIC,
    operator_count   INTEGER,
    hhi              FLOAT
);

CREATE TABLE IF NOT EXISTS eigenda.stake_snapshot_operators (
    snapshot_time    TIMESTAMPTZ NOT NULL,
    quorum_id        INTEGER NOT NULL,
    operator_id      VARCHAR(128),
    stake            NUMERIC,
    stake_pct        FLOAT
);

CREATE TABLE IF NOT EXISTS eigenda.operator_status_snapshots (
    snapshot_time       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    operator_address    VARCHAR(42) NOT NULL,
    metadata_name       TEXT,
    status              VARCHAR(16) NOT NULL,
    total_stakers       INTEGER,
    total_avs           INTEGER,
    tvl_eth             FLOAT
);

CREATE TABLE IF NOT EXISTS eigenda.ejection_events (
    event_time       TIMESTAMPTZ NOT NULL,
    block_number     BIGINT NOT NULL,
    tx_hash          VARCHAR(66),
    log_index        INTEGER,
    operator_id      VARCHAR(128),
    quorum_number    INTEGER,
    UNIQUE(tx_hash, log_index)
);

CREATE INDEX IF NOT EXISTS idx_rp_blob_key ON eigenda.retrieval_probes(blob_key);
CREATE INDEX IF NOT EXISTS idx_rp_age ON eigenda.retrieval_probes(blob_age_hours);
CREATE INDEX IF NOT EXISTS idx_op_blob ON eigenda.operator_probes(blob_key);
CREATE INDEX IF NOT EXISTS idx_op_ts ON eigenda.operator_probes(probe_time);

CREATE TABLE IF NOT EXISTS eigenda.da_layer_metadata (
    da_layer                TEXT PRIMARY KEY,
    chain_decimals          INT,
    native_token            TEXT,
    block_time_seconds      NUMERIC,
    retention_policy        TEXT,
    retention_days_claim    NUMERIC,
    retention_source_url    TEXT,
    finality_seconds_claim  NUMERIC,
    notes                   TEXT,
    updated_at              TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO eigenda.da_layer_metadata (
    da_layer, chain_decimals, native_token,
    block_time_seconds, retention_policy, retention_days_claim,
    retention_source_url, finality_seconds_claim, notes
) VALUES
    ('eigenda', 18, 'ETH', 12, 'hard', 14,
     'https://docs.eigenlayer.xyz/eigenda/overview', 720,
     'Documented 14-day retention via operator stake commitment.'),
    ('ethereum', 18, 'ETH', 12, 'hard', 18,
     'https://eips.ethereum.org/EIPS/eip-4844', 780,
     'EIP-4844 blob retention 4096 epochs ~ 18.2 days.'),
    ('celestia', 6, 'TIA', 6, 'soft', NULL,
     'https://docs.celestia.org/concepts/data-availability-faq', 6,
     'No hard retention guarantee. Pruning window commonly ~30 days.'),
    ('avail', 18, 'AVAIL', 20, 'soft', NULL,
     'https://docs.availproject.org/docs/learn-about-avail/lcs-and-clients', 20,
     'Light client retention depends on config.')
ON CONFLICT (da_layer) DO NOTHING;

ALTER TABLE eigenda.observed_blobs
    ADD COLUMN IF NOT EXISTS cumulative_payment NUMERIC;

CREATE TABLE IF NOT EXISTS eigenda.prober_health (
    ts                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    goroutines          INT,
    heap_alloc_mb       FLOAT,
    heap_sys_mb         FLOAT,
    db_open_conns       INT,
    db_in_use           INT,
    db_idle             INT,
    db_wait_count       BIGINT,
    db_wait_duration_ms BIGINT,
    uptime_seconds      BIGINT
);

CREATE TABLE IF NOT EXISTS eigenda.attestation_nonsigners (
    snapshot_timestamp TIMESTAMPTZ DEFAULT NOW(),
    blob_key           VARCHAR(128) NOT NULL,
    quorum_number      INTEGER NOT NULL,
    operator_id        VARCHAR(66) NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_att_nonsigner_op   ON eigenda.attestation_nonsigners(operator_id, snapshot_timestamp);
CREATE INDEX IF NOT EXISTS idx_att_nonsigner_blob ON eigenda.attestation_nonsigners(blob_key);
-- The bonda collector's incremental ETL reads new rows by time
-- (WHERE snapshot_timestamp > watermark ORDER BY snapshot_timestamp LIMIT N).
-- Neither index above leads with snapshot_timestamp, so that query seq-scans
-- the full ~20M-row table every 30s cycle and trips the 30s statement_timeout.
CREATE INDEX IF NOT EXISTS idx_att_nonsigner_ts   ON eigenda.attestation_nonsigners(snapshot_timestamp);

CREATE OR REPLACE VIEW eigenda.account_usage AS
SELECT
    account_id,
    COUNT(*)                                          AS blob_count,
    SUM(blob_size_bytes)                              AS total_bytes,
    MIN(first_observed_at)                            AS first_seen,
    MAX(first_observed_at)                            AS last_seen,
    COUNT(*) FILTER (WHERE is_self_dispersed)          AS self_dispersed_count,
    AVG(blob_size_bytes)::INT                          AS avg_blob_size,
    MAX(cumulative_payment)                            AS latest_cumulative_payment
FROM eigenda.observed_blobs
WHERE account_id IS NOT NULL AND account_id != ''
GROUP BY account_id;

CREATE OR REPLACE VIEW eigenda.account_usage_hourly AS
SELECT
    date_trunc('hour', first_observed_at) AS hour,
    account_id,
    COUNT(*)                              AS blob_count,
    SUM(blob_size_bytes)                  AS total_bytes,
    AVG(blob_size_bytes)::INT             AS avg_blob_size
FROM eigenda.observed_blobs
WHERE account_id IS NOT NULL AND account_id != ''
GROUP BY 1, 2;
`
	_, err := d.conn.ExecContext(ctx, migrations)
	return err
}

func (d *DB) UpsertBlob(ctx context.Context, b *ObservedBlob) error {
	_, err := d.conn.ExecContext(ctx, `
		INSERT INTO eigenda.observed_blobs (blob_key, account_id, blob_status, blob_size_bytes,
			requested_at, expiry_unix_sec, commitment_x, commitment_y, quorum_numbers,
			is_self_dispersed, dispersal_latency_ms, cumulative_payment)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (blob_key) DO UPDATE SET
			is_self_dispersed = EXCLUDED.is_self_dispersed OR eigenda.observed_blobs.is_self_dispersed,
			dispersal_latency_ms = COALESCE(NULLIF(EXCLUDED.dispersal_latency_ms, 0), eigenda.observed_blobs.dispersal_latency_ms),
			cumulative_payment = COALESCE(EXCLUDED.cumulative_payment, eigenda.observed_blobs.cumulative_payment)`,
		b.BlobKey, b.AccountID, b.BlobStatus, b.BlobSizeBytes,
		b.RequestedAt, b.ExpiryUnixSec, b.CommitmentX, b.CommitmentY, b.QuorumNumbers,
		b.IsSelfDispersed, b.DispersalLatencyMs, b.CumulativePayment,
	)
	return err
}

func (d *DB) InsertProbeResult(ctx context.Context, p *ProbeResult) error {
	_, err := d.conn.ExecContext(ctx, `
		INSERT INTO eigenda.retrieval_probes (blob_key, blob_age_hours, relay_key, success,
			latency_ms, error_message, data_size_bytes, kzg_verified, kzg_error)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		p.BlobKey, p.BlobAgeHours, p.RelayKey, p.Success,
		p.LatencyMs, p.ErrorMessage, p.DataSizeBytes, p.KZGVerified, p.KZGError,
	)
	return err
}

func (d *DB) InsertAttestation(ctx context.Context, a *AttestationSnapshot) error {
	_, err := d.conn.ExecContext(ctx, `
		INSERT INTO eigenda.attestation_snapshots (blob_key, quorum_number,
			total_nonsigners, signing_stake_percentage)
		VALUES ($1, $2, $3, $4)`,
		a.BlobKey, a.QuorumNumber,
		a.TotalNonSigners, a.SigningStakePercentage,
	)
	return err
}

func (d *DB) InsertAttestationNonsigner(ctx context.Context, n *AttestationNonsigner) error {
	_, err := d.conn.ExecContext(ctx, `
		INSERT INTO eigenda.attestation_nonsigners (blob_key, quorum_number, operator_id)
		VALUES ($1, $2, $3)`,
		n.BlobKey, n.QuorumNumber, n.OperatorID,
	)
	return err
}

func (d *DB) InsertOperatorProbe(ctx context.Context, p *OperatorProbeResult) error {
	_, err := d.conn.ExecContext(ctx, `
		INSERT INTO eigenda.operator_probes (blob_key, blob_age_hours, operator_id, operator_socket,
			quorum_id, success, latency_ms, chunks_returned, error_message)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		p.BlobKey, p.BlobAgeHours, p.OperatorID, p.OperatorSocket,
		p.QuorumID, p.Success, p.LatencyMs, p.ChunksReturned, p.ErrorMessage,
	)
	return err
}

func (d *DB) GetUnprobedBlobs(ctx context.Context, limit int) ([]AgedBlobKey, error) {
	rows, err := d.conn.QueryContext(ctx, `
		SELECT ob.blob_key, ob.requested_at FROM eigenda.observed_blobs ob
		LEFT JOIN eigenda.retrieval_probes rp ON ob.blob_key = rp.blob_key
		WHERE rp.blob_key IS NULL
		ORDER BY ob.requested_at DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []AgedBlobKey
	for rows.Next() {
		var bk AgedBlobKey
		if err := rows.Scan(&bk.BlobKey, &bk.RequestedAt); err != nil {
			return nil, err
		}
		results = append(results, bk)
	}
	return results, rows.Err()
}

func (d *DB) GetUnprobedOperatorBlobs(ctx context.Context, limit int) ([]AgedBlobKey, error) {
	rows, err := d.conn.QueryContext(ctx, `
		SELECT ob.blob_key, ob.requested_at FROM eigenda.observed_blobs ob
		LEFT JOIN eigenda.operator_probes op ON ob.blob_key = op.blob_key
		WHERE op.blob_key IS NULL
		ORDER BY ob.requested_at DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []AgedBlobKey
	for rows.Next() {
		var bk AgedBlobKey
		if err := rows.Scan(&bk.BlobKey, &bk.RequestedAt); err != nil {
			return nil, err
		}
		results = append(results, bk)
	}
	return results, rows.Err()
}

func (d *DB) GetAgedBlobKeys(ctx context.Context, hoursAgo float64, windowHours float64, limit int) ([]AgedBlobKey, error) {
	nowNano := time.Now().UnixNano()
	targetNano := nowNano - int64(hoursAgo*float64(time.Hour))
	windowNano := int64(windowHours * float64(time.Hour))

	rows, err := d.conn.QueryContext(ctx, `
		SELECT blob_key, requested_at FROM eigenda.observed_blobs
		WHERE requested_at BETWEEN $1 AND $2
		ORDER BY RANDOM()
		LIMIT $3`,
		targetNano-windowNano, targetNano+windowNano, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []AgedBlobKey
	for rows.Next() {
		var bk AgedBlobKey
		if err := rows.Scan(&bk.BlobKey, &bk.RequestedAt); err != nil {
			return nil, err
		}
		results = append(results, bk)
	}
	return results, rows.Err()
}

func (d *DB) InsertStakeSnapshot(ctx context.Context, s *StakeSnapshot) error {
	_, err := d.conn.ExecContext(ctx, `
		INSERT INTO eigenda.stake_snapshots (quorum_id, total_stake, operator_count, hhi)
		VALUES ($1, $2, $3, $4)`,
		s.QuorumID, s.TotalStake, s.OperatorCount, s.HHI,
	)
	return err
}

func (d *DB) InsertStakeSnapshotOperator(ctx context.Context, s *StakeSnapshotOperator) error {
	_, err := d.conn.ExecContext(ctx, `
		INSERT INTO eigenda.stake_snapshot_operators (quorum_id, operator_id, stake, stake_pct)
		VALUES ($1, $2, $3, $4)`,
		s.QuorumID, s.OperatorID, s.Stake, s.StakePct,
	)
	return err
}

func (d *DB) InsertEjectionEvent(ctx context.Context, e *EjectionEvent) error {
	_, err := d.conn.ExecContext(ctx, `
		INSERT INTO eigenda.ejection_events (event_time, block_number, tx_hash, log_index,
			operator_id, quorum_number)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tx_hash, log_index) DO NOTHING`,
		e.EventTime, e.BlockNumber, e.TxHash, e.LogIndex,
		e.OperatorID, e.QuorumNumber,
	)
	return err
}

func (d *DB) GetIndexerCursor(ctx context.Context, indexerName string) (int64, error) {
	var lastBlock int64
	err := d.conn.QueryRowContext(ctx, `
		SELECT last_block FROM eigenda.indexer_cursors WHERE indexer_name = $1`,
		indexerName,
	).Scan(&lastBlock)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return lastBlock, err
}

func (d *DB) UpdateIndexerCursor(ctx context.Context, indexerName string, lastBlock int64) error {
	_, err := d.conn.ExecContext(ctx, `
		INSERT INTO eigenda.indexer_cursors (indexer_name, last_block, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (indexer_name) DO UPDATE SET last_block = $2, updated_at = NOW()`,
		indexerName, lastBlock,
	)
	return err
}

// GetBlobCommitment returns the commitment coordinates for a blob key.
func (d *DB) GetBlobCommitment(ctx context.Context, blobKey string) (commitmentX, commitmentY string, err error) {
	err = d.conn.QueryRowContext(ctx, `
		SELECT commitment_x, commitment_y FROM eigenda.observed_blobs WHERE blob_key = $1`,
		blobKey,
	).Scan(&commitmentX, &commitmentY)
	return
}

func (d *DB) UpsertOperatorStatus(ctx context.Context, o *OperatorStatus) error {
	_, err := d.conn.ExecContext(ctx, `
		INSERT INTO eigenda.operator_status_snapshots
			(operator_address, metadata_name, status, total_stakers, total_avs, tvl_eth)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		o.OperatorAddress, o.MetadataName, o.Status,
		o.TotalStakers, o.TotalAvs, o.TVLETH,
	)
	return err
}

func (d *DB) GetDeadOperators(ctx context.Context) ([]OperatorStatus, error) {
	rows, err := d.conn.QueryContext(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (operator_address)
				operator_address, metadata_name, status, total_stakers, total_avs, tvl_eth
			FROM eigenda.operator_status_snapshots
			ORDER BY operator_address, snapshot_time DESC
		)
		SELECT operator_address, metadata_name, status, total_stakers, total_avs, tvl_eth
		FROM latest
		WHERE status = 'inactive'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []OperatorStatus
	for rows.Next() {
		var o OperatorStatus
		if err := rows.Scan(&o.OperatorAddress, &o.MetadataName, &o.Status,
			&o.TotalStakers, &o.TotalAvs, &o.TVLETH); err != nil {
			return nil, err
		}
		result = append(result, o)
	}
	return result, rows.Err()
}

type ProberHealth struct {
	Goroutines      int
	HeapAllocMB     float64
	HeapSysMB       float64
	DBOpenConns     int
	DBInUse         int
	DBIdle          int
	DBWaitCount     int64
	DBWaitDurationMs int64
	UptimeSeconds   int64
}

func (d *DB) InsertProberHealth(ctx context.Context, h *ProberHealth) error {
	_, err := d.conn.ExecContext(ctx, `
		INSERT INTO eigenda.prober_health (goroutines, heap_alloc_mb, heap_sys_mb,
			db_open_conns, db_in_use, db_idle, db_wait_count, db_wait_duration_ms, uptime_seconds)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		h.Goroutines, h.HeapAllocMB, h.HeapSysMB,
		h.DBOpenConns, h.DBInUse, h.DBIdle, h.DBWaitCount, h.DBWaitDurationMs, h.UptimeSeconds,
	)
	return err
}

// DBStats returns the underlying connection pool stats.
func (d *DB) DBStats() sql.DBStats {
	return d.conn.Stats()
}

// Conn returns the underlying *sql.DB for use by the API server.
func (d *DB) Conn() *sql.DB {
	return d.conn
}

func (d *DB) Close() error {
	return d.conn.Close()
}
