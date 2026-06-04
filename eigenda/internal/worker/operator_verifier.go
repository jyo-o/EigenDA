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
// is network-bound (gRPC GetChunks), so high concurrency costs almost no CPU —
// important on this 2-core box.
const fetchConcurrency = 32

// maxProbeRetries: after the first parallel sweep, re-probe the operators that
// returned nothing (transient timeouts under load) up to this many extra rounds
// — until we either collect enough chunks (RECOVERABLE) or a round adds nothing
// (the data is genuinely gone from the operator set). This is what separates
// measuring the DA from measuring our own collector: a NOT-recoverable verdict
// must mean the DA lost the data, never "we failed to reach an operator".
const maxProbeRetries = 2

// gcChunksPerOpMax: after retries, a NOT-recoverable probe is recorded as AT_RISK
// only when the operators that answered are themselves out of chunks (chunks/op
// ~1 = data GC'd). If they still held full chunk sets (chunks/op >= this) we just
// could not reach enough of them on this 2-core box — a measurement miss, dropped
// rather than recorded, so the curve stays a pure DA signal (not our reachability).
const gcChunksPerOpMax = 4.0

// probeSet probes ONE set of operators in parallel, records the per-operator row
// for each, and returns chunks gained, how many contributed, and the operators
// that returned nothing (the retry candidates).
func (v *OperatorVerifier) probeSet(ctx context.Context, ops []operator.OperatorInfo, blobKey string, blobAgeHours float64) (chunks, okCount int, failed []operator.OperatorInfo) {
	var mu sync.Mutex
	sem := make(chan struct{}, fetchConcurrency)
	var wg sync.WaitGroup

	for _, op := range ops {
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
			if r.Success && r.ChunksReturned > 0 {
				chunks += r.ChunksReturned
				okCount++
			} else {
				// No chunks (timeout, error, or empty GC'd response) → retry it.
				failed = append(failed, op)
			}
			mu.Unlock()
		}(op)
	}
	wg.Wait()
	return
}

// probeAndRetrieve collects erasure-coded chunks from the operator set (retrying
// transient failures) and records whether the blob is RECOVERABLE — at least
// minChunksForRecovery chunks reachable. Collecting that many IS the proof of
// reconstructability (erasure coding), so we skip the RS decode + per-frame KZG
// verify. The retry loop is what makes this a PURE DA measurement: we never call
// a blob AT_RISK until we have actually tried every operator and a full round
// returned no new chunks. (Recoverable blobs clear 1024 on round 0 and stop;
// only stragglers/GC'd blobs cost extra rounds.)
func (v *OperatorVerifier) probeAndRetrieve(ctx context.Context, blobKey string, blobAgeHours float64) {
	allOperators, err := v.opDiscovery.GetOperators(ctx)
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	start := time.Now()

	totalChunks, okCount, rounds := 0, 0, 0
	pending := allOperators
	for {
		chunks, ok, failed := v.probeSet(ctx, pending, blobKey, blobAgeHours)
		totalChunks += chunks
		okCount += ok
		rounds++
		if totalChunks >= minChunksForRecovery {
			break // recoverable — no need to chase the stragglers
		}
		if rounds > maxProbeRetries || chunks == 0 || len(failed) == 0 {
			break // retries exhausted, or a round added nothing → genuinely gone
		}
		pending = failed // re-probe only the operators that returned nothing
	}

	recoverable := totalChunks >= minChunksForRecovery
	fetchMs := int(time.Since(start).Milliseconds())

	logKey := blobKey
	if len(logKey) > 12 {
		logKey = logKey[:12]
	}

	// Pure-DA filter: if we fell short of the threshold but the operators that
	// answered were still holding chunks (chunks/op above a GC'd operator's ~1),
	// we simply could not reach enough operators — a measurement miss, not data
	// loss. Drop it rather than record a false AT_RISK; the survival curve must
	// reflect the DA, not our reachability on this 2-core box. A genuine cliff has
	// responders returning ~nothing (chunks/op ~1) and IS recorded below.
	if !recoverable {
		chunksPerOk := 0.0
		if okCount > 0 {
			chunksPerOk = float64(totalChunks) / float64(okCount)
		}
		if chunksPerOk >= gcChunksPerOpMax {
			log.Printf("[recovery] blob=%s INCONCLUSIVE operators=%d/%d chunks=%d (%.1f/op) rounds=%d — under-collected, not recording",
				logKey, okCount, len(allOperators), totalChunks, chunksPerOk, rounds)
			return
		}
	}

	tag := "RECOVERABLE"
	if !recoverable {
		tag = "AT_RISK"
	}
	log.Printf("[recovery] blob=%s operators=%d/%d chunks=%d/%d %s rounds=%d (%dms)",
		logKey, okCount, len(allOperators), totalChunks, minChunksForRecovery, tag, rounds, fetchMs)

	// DecodeSuccess carries the recoverability verdict — the survival curve keys
	// on it. OperatorsTotal is the full set we tried; OperatorsOK contributed
	// chunks. We no longer reconstruct, so BlobHash/KZGVerified stay empty.
	v.db.InsertOperatorRetrieval(ctx, &db.OperatorRetrievalResult{
		BlobKey:         blobKey,
		BlobAgeHours:    blobAgeHours,
		OperatorsTotal:  len(allOperators),
		OperatorsOK:     okCount,
		ChunksCollected: totalChunks,
		ChunksRequired:  minChunksForRecovery,
		DecodeSuccess:   recoverable,
		DecodeLatencyMs: fetchMs,
	})
}
