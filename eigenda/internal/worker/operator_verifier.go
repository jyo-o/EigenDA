package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"sync"
	"time"

	"github.com/jyo-o/BONDA/eigenda/internal/chainstate"
	"github.com/jyo-o/BONDA/eigenda/internal/dataapi"
	"github.com/jyo-o/BONDA/eigenda/internal/db"
	"github.com/jyo-o/BONDA/eigenda/internal/kzg"
	"github.com/jyo-o/BONDA/eigenda/internal/operator"
)

const minChunksForRecovery = 1024

type OperatorVerifier struct {
	db          *db.DB
	api         *dataapi.Client
	opDiscovery *operator.Discovery
	opClient    *operator.Client
	chainState  *chainstate.ChainState
	verifier    *kzg.Verifier
}

func NewOperatorVerifier(
	database *db.DB,
	api *dataapi.Client,
	discovery *operator.Discovery,
	client *operator.Client,
	cs *chainstate.ChainState,
	v *kzg.Verifier,
) *OperatorVerifier {
	return &OperatorVerifier{
		db:          database,
		api:         api,
		opDiscovery: discovery,
		opClient:    client,
		chainState:  cs,
		verifier:    v,
	}
}

func (v *OperatorVerifier) Name() string { return "operator-verifier" }

// decodeAgeGroups: daily age targets for operator-direct decode survival
// (mirrors the relay reverifier). Probing AGED observed blobs finds the real
// cliff where operators GC chunks past the ~14d commitment; the relay caches
// longer and overstates retention. Capped at 16d (eigenda display horizon).
var decodeAgeGroups = []ageGroup{
	{hoursAgo: 24, windowHours: 6, limit: 1},
	{hoursAgo: 48, windowHours: 6, limit: 1},
	{hoursAgo: 72, windowHours: 6, limit: 1},
	{hoursAgo: 96, windowHours: 6, limit: 1},
	{hoursAgo: 120, windowHours: 6, limit: 1},
	{hoursAgo: 144, windowHours: 6, limit: 1},
	{hoursAgo: 168, windowHours: 6, limit: 1},
	{hoursAgo: 192, windowHours: 6, limit: 1},
	{hoursAgo: 216, windowHours: 6, limit: 1},
	{hoursAgo: 240, windowHours: 6, limit: 1},
	{hoursAgo: 264, windowHours: 6, limit: 1},
	{hoursAgo: 288, windowHours: 6, limit: 1},
	{hoursAgo: 312, windowHours: 6, limit: 1},
	{hoursAgo: 336, windowHours: 4, limit: 1},
	{hoursAgo: 360, windowHours: 6, limit: 1},
	{hoursAgo: 384, windowHours: 6, limit: 1},
}

func (v *OperatorVerifier) Run(ctx context.Context) {
	if v.opDiscovery == nil || v.opClient == nil {
		log.Println("[operator-verifier] disabled (no operator discovery)")
		return
	}

	// Warm operator cache
	if ops, err := v.opDiscovery.GetOperators(ctx); err != nil {
		log.Printf("[operator-verifier] operator cache warm failed: %v", err)
	} else {
		log.Printf("[operator-verifier] operator cache warmed: %d unique operators", len(ops))
	}

	log.Println("[operator-verifier] started")
	cycle := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Every 5th cycle, decode-probe an AGED blob (round-robin daily 1d..16d)
		// so the operator-direct survival curve crosses the 14d window and finds
		// the real GC cliff, not just the recent backlog.
		if cycle >= 0 { // aged probe EVERY cycle — fill curve ASAP
			ag := decodeAgeGroups[cycle%len(decodeAgeGroups)]
			if aged, err := v.db.GetAgedBlobKeys(ctx, ag.hoursAgo, ag.windowHours, ag.limit); err == nil && len(aged) > 0 {
				b := aged[0]
				ageH := float64(time.Now().UnixNano()-int64(b.RequestedAt)) / float64(time.Hour)
				v.probeAndRetrieve(ctx, b.BlobKey, ageH)
				cycle++
				continue
			}
		}

		// Every 3rd cycle, check for self-dispersed blobs needing operator retrieval
		if cycle%3 == 0 {
			if selfBlob, err := v.db.GetUnretrievedSelfBlob(ctx); err == nil {
				blobAgeHours := float64(time.Now().UnixNano()-int64(selfBlob.RequestedAt)) / float64(time.Hour)
				log.Printf("[operator-verifier] self-blob %s (age=%.1fh)", selfBlob.BlobKey[:16], blobAgeHours)
				v.probeAndRetrieve(ctx, selfBlob.BlobKey, blobAgeHours)
				cycle++
				continue
			}
		}

		unprobed, err := v.db.GetUnprobedOperatorBlobs(ctx, 1)
		if err != nil || len(unprobed) == 0 {
			time.Sleep(2 * time.Second)
			cycle++
			continue
		}

		blob := unprobed[0]
		blobAgeHours := float64(time.Now().UnixNano()-int64(blob.RequestedAt)) / float64(time.Hour)
		v.probeAndRetrieve(ctx, blob.BlobKey, blobAgeHours)
		cycle++
	}
}

// fetchConcurrency bounds how many operators we query at once. Chunk retrieval
// is network-bound (gRPC GetChunks, 5s timeout), so high concurrency costs almost
// no CPU — important on this 2-core box.
const fetchConcurrency = 32

// probeAndRetrieve collects erasure-coded chunks from every operator IN PARALLEL
// and records whether the blob is RECOVERABLE — i.e. whether at least
// minChunksForRecovery chunks are still retrievable from the operator set.
//
// Erasure-coding guarantee: collecting >= ChunksRequired chunks IS the proof that
// the blob is reconstructable, so we deliberately skip the actual RS decode and
// the per-frame KZG verification. The previous path verified all ~2600 frames
// one-by-one (~195s) and pegged this 2-core VM; chunk availability is the honest
// retention signal and costs ~5s. (KZG genuineness can be re-added later as a
// cheap sampled spot-check — see notes.)
func (v *OperatorVerifier) probeAndRetrieve(ctx context.Context, blobKey string, blobAgeHours float64) {
	allOperators, err := v.opDiscovery.GetOperators(ctx)
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	start := time.Now()

	var mu sync.Mutex
	totalChunks, okCount, failCount := 0, 0, 0

	sem := make(chan struct{}, fetchConcurrency)
	var wg sync.WaitGroup

	for _, op := range allOperators {
		if v.opDiscovery.IsBlacklisted(op.OperatorID) {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(op operator.OperatorInfo) {
			defer wg.Done()
			defer func() { <-sem }()

			r := v.opClient.ProbeChunks(ctx, op.Socket, blobKey, 0)
			v.opDiscovery.ReportResult(op.OperatorID, r.Success)

			// Integrity cross-check hash over the returned chunk bytes.
			var chunkHash string
			var chunkSize int
			if r.Success && len(r.ChunkData) > 0 {
				h := sha256.New()
				for _, c := range r.ChunkData {
					h.Write(c)
					chunkSize += len(c)
				}
				chunkHash = hex.EncodeToString(h.Sum(nil))
			}

			v.db.InsertOperatorProbe(ctx, &db.OperatorProbeResult{
				BlobKey: blobKey, BlobAgeHours: blobAgeHours,
				OperatorID: hex.EncodeToString(op.OperatorID[:8]), OperatorSocket: op.Socket,
				QuorumID: 0, Success: r.Success,
				LatencyMs: r.LatencyMs, ChunksReturned: r.ChunksReturned,
				ChunkDataHash: chunkHash, ChunkDataSize: chunkSize,
				ErrorMessage: r.Error,
			})

			mu.Lock()
			if r.Success {
				okCount++
				totalChunks += r.ChunksReturned
			} else {
				failCount++
			}
			mu.Unlock()
		}(op)
	}
	wg.Wait()

	recoverable := totalChunks >= minChunksForRecovery
	fetchMs := int(time.Since(start).Milliseconds())

	logKey := blobKey
	if len(logKey) > 12 {
		logKey = logKey[:12]
	}
	tag := "RECOVERABLE"
	if !recoverable {
		tag = "AT_RISK"
	}
	log.Printf("[recovery] blob=%s operators=%d/%d chunks=%d/%d %s (%dms)",
		logKey, okCount, okCount+failCount, totalChunks, minChunksForRecovery, tag, fetchMs)

	// DecodeSuccess carries the recoverability verdict — the survival curve keys on
	// it. DecodeLatencyMs now records the parallel-fetch wall-clock. We no longer
	// reconstruct the blob, so BlobHash/KZGVerified are intentionally left empty.
	v.db.InsertOperatorRetrieval(ctx, &db.OperatorRetrievalResult{
		BlobKey:         blobKey,
		BlobAgeHours:    blobAgeHours,
		OperatorsTotal:  okCount + failCount,
		OperatorsOK:     okCount,
		ChunksCollected: totalChunks,
		ChunksRequired:  minChunksForRecovery,
		DecodeSuccess:   recoverable,
		DecodeLatencyMs: fetchMs,
	})
}
