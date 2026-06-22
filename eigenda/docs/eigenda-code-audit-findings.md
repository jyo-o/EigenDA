# EigenDA Code-Level Audit Findings

**Date**: 2026-05-13
**Codebase**: `github.com/Layr-Labs/eigenda` (local: `~/dabeat/research/eigenda/`)
**Method**: 기존 audit 보고서(Sigma Prime Offchain/Blazar, ChainLight LittDB) 버그 패턴을 현재 V2 코드에서 검색
**Status**: 발견 → PoC 검증 필요

---

## Findings Summary

| # | Severity | File | Bug | Auth | PoC Status |
|---|----------|------|-----|------|------------|
| F-01 | ~~High~~ **Info** | `relay/server.go:503` | BlobKey raw cast panic — **unreachable** (getKeysFromChunkRequest가 먼저 검증) | operator | DISPROVEN |
| F-02 | Medium | `relay/server.go:785` | uint32 overflow → rate limit bypass (32 blob reqs에서 wrap-around, MaxKeys 설정 의존) | operator | **CONFIRMED (조건부)** |
| F-03 | Medium | `relay/server.go:162` | ReplayGuardian copy-paste bug | - | **CONFIRMED** |
| F-04 | Medium | `server_v2.go:498` | uint32→uint8 quorum downcast | no auth | **CONFIRMED** |
| F-05 | Medium | `thegraph/state.go:265,334` | BN254 IsInSubGroup() missing | TheGraph | **CONFIRMED** |
| F-06 | Medium | `dataapi/utils.go:49-78` | BN254 IsInSubGroup() missing | TheGraph | **CONFIRMED** |
| F-07 | Low | `server_v2.go:453` | uint64→uint32 timestamp | - | confirmed (not exploitable) |
| F-08 | Info | `authorize_payment_hashing.go:23` | length prefix missing | - | confirmed (code review) |

---

## F-01: Relay BlobKey Raw Cast Panic (High)

**Pattern source**: EDA2-03 (nil pointer dereference due to incorrect validation order)

**Location**: `relay/server.go:503`

```go
blobKey := v2.BlobKey(chunkRequest.GetByRange().GetBlobKey())
```

**Bug**: `v2.BlobKey`는 `[32]byte` 타입. `GetBlobKey()`가 32바이트 미만을 반환하면 Go의 array conversion이 panic. 반면 다른 곳에서는 `v2.BytesToBlobKey()`를 사용하는데, 이 함수는 길이를 검증함.

**같은 패턴 두 번째**: `relay/server.go:572`에도 동일.

**공격 경로**:
1. 등록된 operator가 `GetChunks` 요청을 보냄 (BLS 인증 통과)
2. `ByRange` 필드의 `BlobKey`를 31바이트 이하로 설정
3. relay가 `gatherChunkDataToSend` → `downloadDataFromRelays`에서 panic
4. relay 프로세스 크래시 → 단일 relay SPOF이므로 전체 chunk pull 중단

**영향**: relay 크래시 → operator들이 chunk를 받지 못함 → attestation 실패 → liveness 영향

**PoC plan**: Go 테스트 코드에서 `v2.BlobKey(shortSlice)` 호출 시 panic 확인

**PoC result**:
```
$ go run poc_f01.go
32 bytes: OK
SHORT SLICE PANIC: runtime error: cannot convert slice with length 31
  to array or pointer to array with length 32
F-01 CONFIRMED: v2.BlobKey() panics on <32 byte input

BUT: 실제 GetChunks 경로에서는 getKeysFromChunkRequest() (line 345)가
downloadDataFromRelays() (line 503)보다 먼저 실행되며,
BytesToBlobKey()로 길이를 검증합니다. 31바이트는 line 345에서 에러로 거부되어
line 503에 도달하지 않습니다.

DISPROVEN: panic 가능한 코드이지만 unreachable path.
코드 품질 문제(defensive programming 위반)이지 exploit은 아님.
```

---

## F-02: uint32 Overflow in Relay Bandwidth Calculation (High)

**Pattern source**: EDA-04 (unsafe downcasting of integers)

**Location**: `relay/server.go:785-812`

```go
requiredBandwidth := uint32(0)
// ...
requiredBandwidth += requestedChunks * metadata.chunkSizeBytes
```

**Bug**: `requestedChunks * metadata.chunkSizeBytes` 곱셈이 uint32 범위(4GB)를 초과하면 silent overflow. 결과적으로 `requiredBandwidth`가 작은 값이 되어 rate limit 체크를 통과.

**공격 경로**:
1. 등록된 operator가 대량의 chunk 요청을 단일 `GetChunks`에 넣음
2. 개별 요청은 한도 내이지만, 합계의 uint32 곱셈이 overflow
3. `requiredBandwidth`가 실제보다 작게 계산됨
4. rate limiter의 bandwidth 체크를 우회
5. relay가 과도한 리소스를 소비 (메모리, I/O)

**PoC plan**: Go 코드에서 uint32 overflow 재현 + 실제 rate limit 우회 여부 확인

**PoC result**:
```
현실적 값으로 재계산:
- Per request: 8192 chunks * 16384 bytes = 134,217,728 (128 MB)
- 32 requests: uint32 total = 0 (128MB * 32 = 4GB = uint32 wrap to 0)
- Rate limit: 20 MiB
- 0 < 20 MiB → BYPASSES rate limit

F-02 CONFIRMED (조건부):
  32개 blob 요청(각 전체 chunk range)을 단일 GetChunks에 넣으면
  128MB * 32 = 4GB → uint32 overflow → 0 → rate limit 우회
  
  단, MaxKeysPerGetChunksRequest >= 32이어야 함.
  테스트 설정: 1024 (충분), 프로덕션 설정: 미확인.
  기본값이 없으므로(Go zero value = 0), 설정 안 하면 체크 무효화.
```

---

## F-03: ReplayGuardian Copy-Paste Bug (Medium)

**Pattern source**: EDA2-02 (missing signature replay protection)

**Location**: `relay/server.go:159-162`

```go
replayGuardian, err := replay.NewReplayGuardian(
    time.Now,
    config.GetChunksRequestMaxPastAge,
    config.GetChunksRequestMaxPastAge)  // BUG: should be GetChunksRequestMaxFutureAge
```

**Bug**: `NewReplayGuardian`의 두 번째와 세 번째 인자는 각각 `maxTimeInPast`와 `maxTimeInFuture`. 그런데 둘 다 `GetChunksRequestMaxPastAge`를 전달. `GetChunksRequestMaxFutureAge` 설정값이 무시됨.

**영향**:
- `maxPastAge > maxFutureAge`인 경우: 의도보다 넓은 미래 시간 윈도우 → replay 공격 윈도우 확대
- `maxPastAge < maxFutureAge`인 경우: 정당한 미래 타임스탬프 요청이 거부됨

**PoC plan**: config 기본값 비교 + replay 윈도우 차이 계산

**PoC result**:
```
relay/server.go:159-162:
  replayGuardian, err := replay.NewReplayGuardian(
      time.Now,
      config.GetChunksRequestMaxPastAge,     // arg2: maxTimeInPast ✓
      config.GetChunksRequestMaxPastAge)     // arg3: maxTimeInFuture ✗ (should be MaxFutureAge)

NewReplayGuardian signature (common/replay/replay_guardian_impl.go:41):
  func NewReplayGuardian(
      timeSource func() time.Time,
      maxTimeInPast time.Duration,    // arg2
      maxTimeInFuture time.Duration,  // arg3 ← gets wrong value

Config defines both separately (relay/config.go:56,59):
  GetChunksRequestMaxPastAge time.Duration
  GetChunksRequestMaxFutureAge time.Duration

F-03 CONFIRMED: copy-paste bug, GetChunksRequestMaxFutureAge config is dead code
```

---

## F-04: Quorum ID Downcast Without Validation (Medium)

**Pattern source**: EDA-04 (unsafe downcasting of integers)

**Location**: `disperser/apiserver/server_v2.go:498`

```go
core.QuorumID(request.GetQuorum()),  // uint32 → uint8, no range check
```

**Bug**: `GetQuorum()`은 protobuf `uint32`를 반환. `QuorumID`는 `uint8`. 값 256 → quorum 0, 257 → quorum 1 등으로 의도하지 않은 quorum 매핑.

**공격 경로**:
1. `GetValidatorSigningRate` 엔드포인트는 인증 불필요
2. `quorum=256`을 전송하면 `uint8(256) = 0` → quorum 0의 데이터 반환
3. 직접적 피해는 정보 노출 수준이지만, 입력 검증 누락 패턴

**PoC plan**: grpcurl로 quorum=256 전송 → quorum 0 결과 반환 확인

**PoC result**:
```
$ grpcurl -d '{"validator_id":"AAA...","quorum":256,...}' \
    disperser-testnet-sepolia.eigenda.xyz:443 \
    disperser.v2.Disperser/GetValidatorSigningRate

{"validatorSigningRate":{"validatorId":"AAA..."}}

quorum=0과 quorum=256이 동일한 응답 반환.
에러 없이 처리됨 — 입력 검증 없이 uint32→uint8 truncation 발생.

F-04 CONFIRMED: invalid quorum values silently accepted (Sepolia testnet)
```

---

## F-05: BN254 IsInSubGroup() Missing on TheGraph Data (Medium)

**Pattern source**: EDA-02 (missing IsOnCurve & IsInSubgroup checks)

**Location**: `core/thegraph/state.go:265-273, 334-365`

```go
// line 265-273: quorumAPKPoint
var quorumAPKPoint bn254.G1Affine
quorumAPKPoint.X.SetString(quorumAPK.ApkX)
quorumAPKPoint.Y.SetString(quorumAPK.ApkY)
// NO IsInSubGroup() check

// line 334-365: operator pubkey G1/G2
var pubkeyG1 bn254.G1Affine
pubkeyG1.X.SetString(operatorGql.PubkeyG1_X)
pubkeyG1.Y.SetString(operatorGql.PubkeyG1_Y)
// NO IsInSubGroup() check
```

**Bug**: TheGraph 인덱서에서 가져온 BN254 포인트에 on-curve / in-subgroup 검증 없음. 메인 역직렬화 경로(PR #422에서 수정)와 달리 이 경로는 수정되지 않음.

**영향**: TheGraph 인덱서가 타협되면 잘못된 curve point가 `quorumAPKPoint`에 주입 → BLS 서명 검증에서 undefined behavior → 서명 위조 가능성

**PoC plan**: 코드에서 `IsInSubGroup()` 호출 여부 확인 (코드 리뷰로 충분)

**PoC result**:
```
$ grep -n "IsInSubGroup" core/thegraph/state.go
(0 results — 호출 없음)

$ grep -n "IsInSubGroup" disperser/dataapi/utils.go
(0 results — 호출 없음)

비교 — 메인 역직렬화 경로에는 있음:
$ grep -n "IsInSubGroup" core/v2/types.go
110:  if !(*bn254.G1Affine)(commitment).IsInSubGroup() {
114:  if !(*bn254.G2Affine)(lengthCommitment).IsInSubGroup() {
118:  if !(*bn254.G2Affine)(lengthProof).IsInSubGroup() {

F-05/F-06 CONFIRMED: TheGraph/DataAPI 경로에 IsInSubGroup() 미호출
  메인 경로(PR #422)에서 수정된 동일 패턴이 이 경로에는 적용되지 않음
```

---

## F-06: BN254 IsInSubGroup() Missing on DataAPI GraphQL (Medium)

**Pattern source**: EDA-02

**Location**: `disperser/dataapi/utils.go:49-78`

동일 패턴. `ConvertOperatorInfoGqlToIndexedOperatorInfo()`에서 GraphQL 데이터를 BN254 포인트로 변환할 때 `IsInSubGroup()` 미호출.

---

## F-07: Timestamp uint64→uint32 Downcast (Low)

**Location**: `disperser/apiserver/server_v2.go:453-454`

```go
StartTimestamp: uint32(reservation.StartTimestamp),
EndTimestamp:   uint32(reservation.EndTimestamp),
```

Y2106 버그. 현재는 exploit 불가.

---

## F-08: ClientSignature Length Prefix Missing (Info)

**Location**: `api/hashing/authorize_payment_request_hashing.go:23`

```go
hasher.Write(request.GetClientSignature())  // no hashByteArray(), no length prefix
```

EDA2-06 수정 컨벤션 위반. 현재는 terminal field이고 65B 고정이라 collision 불가. 하지만 필드 추가 시 위험.

---

## PoC Verification Plan

1. **F-01** (BlobKey panic): Go unit test에서 `v2.BlobKey([]byte{1,2,3})` panic 확인
2. **F-02** (uint32 overflow): Go에서 `uint32(65536) * uint32(65537)` = overflow 확인 + rate limit 로직 분석
3. **F-03** (copy-paste): 코드 diff로 확인 (config 값 비교)
4. **F-04** (quorum downcast): grpcurl로 Sepolia disperser에 quorum=256 전송
5. **F-05/06** (BN254): 코드 리뷰로 확인 (IsInSubGroup 미호출 여부)
