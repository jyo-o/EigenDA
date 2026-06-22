package relay

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	relaypb "github.com/Layr-Labs/eigenda/api/grpc/relay"
)

type RetrieveResult struct {
	Success       bool
	LatencyMs     int
	DataSizeBytes int
	Error         string
	Data          []byte // raw blob data for KZG verification
}

type Client struct {
	timeout time.Duration
}

func NewClient() *Client {
	return &Client{
		timeout: 30 * time.Second,
	}
}

// GetBlob attempts to retrieve a blob from the relay at the given URL.
// blobKeyHex is the hex-encoded blob key from the DataAPI.
func (c *Client) GetBlob(ctx context.Context, relayURL string, blobKeyHex string) *RetrieveResult {
	start := time.Now()

	blobKeyBytes, err := hex.DecodeString(strings.TrimPrefix(blobKeyHex, "0x"))
	if err != nil {
		return &RetrieveResult{
			Success: false,
			Error:   fmt.Sprintf("decode blob key: %v", err),
		}
	}

	// Append default gRPC port if missing
	if !strings.Contains(relayURL, ":") {
		relayURL = relayURL + ":443"
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, relayURL,
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(32*1024*1024)),
	)
	if err != nil {
		return &RetrieveResult{
			Success:   false,
			LatencyMs: int(time.Since(start).Milliseconds()),
			Error:     fmt.Sprintf("dial relay %s: %v", relayURL, err),
		}
	}
	defer conn.Close()

	client := relaypb.NewRelayClient(conn)
	resp, err := client.GetBlob(ctx, &relaypb.GetBlobRequest{
		BlobKey: blobKeyBytes,
	})

	latencyMs := int(time.Since(start).Milliseconds())

	if err != nil {
		return &RetrieveResult{
			Success:   false,
			LatencyMs: latencyMs,
			Error:     fmt.Sprintf("GetBlob: %v", err),
		}
	}

	return &RetrieveResult{
		Success:       true,
		LatencyMs:     latencyMs,
		DataSizeBytes: len(resp.Blob),
		Data:          resp.Blob,
	}
}
