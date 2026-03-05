// ALICE-API UE5 C++ Header
// Auto-generated — 20 extern C + RAII wrappers
// Author: Moroya Sakamoto

#pragma once

#include <cstdint>
#include <utility>

// ============================================
// FFI structs
// ============================================

struct FGatewayStats
{
    uint64_t RequestsTotal;
    uint64_t RequestsForwarded;
    uint64_t RequestsRateLimited;
    uint64_t RequestsQueued;
    uint64_t RequestsNotFound;
    uint64_t BytesForwarded;
};

struct FGatewayDecision
{
    uint8_t Kind;   // 0=Forward,1=Queued,2=RateLimited,3=NotFound,...
    uint64_t Value; // backend_id or retry_after_ns
    bool IsForward() const { return Kind == 0; }
    bool IsRateLimited() const { return Kind == 2; }
    uint32_t BackendId() const { return static_cast<uint32_t>(Value); }
    uint64_t RetryAfterNs() const { return Value; }
};

struct FSfqStats
{
    uint64_t Enqueued;
    uint64_t Dequeued;
    uint64_t Drops;
    uint32_t CurrentLen;
};

// ============================================
// C API (20 functions)
// ============================================

extern "C"
{
    // Opaque handles
    typedef struct GcraCell GcraCell;
    typedef struct TestGateway TestGateway;
    typedef struct StochasticFairQueue StochasticFairQueue;

    // 1. Create GCRA cell
    GcraCell* alice_api_gcra_create(double rate, uint32_t burst);
    // 2. Destroy GCRA cell
    void alice_api_gcra_destroy(GcraCell* cell);
    // 3. Check rate limit (returns 1=allow, 0=deny)
    uint8_t alice_api_gcra_check(const GcraCell* cell, uint64_t now_ns, uint64_t* out_ns);
    // 4. Would allow (peek)
    uint8_t alice_api_gcra_would_allow(const GcraCell* cell, uint64_t now_ns);
    // 5. Get TAT
    uint64_t alice_api_gcra_tat(const GcraCell* cell);
    // 6. CRDT merge
    void alice_api_gcra_merge(const GcraCell* cell, uint64_t other_tat);
    // 7. Reset
    void alice_api_gcra_reset(const GcraCell* cell);

    // 8. Create gateway
    TestGateway* alice_api_gateway_create();
    // 9. Destroy gateway
    void alice_api_gateway_destroy(TestGateway* gw);
    // 10. Add backend
    uint32_t alice_api_gateway_add_backend(
        TestGateway* gw, uint32_t backend_id,
        const uint8_t* host, uint32_t host_len, uint16_t port);
    // 11. Add route
    uint8_t alice_api_gateway_add_route(
        TestGateway* gw, const uint8_t* prefix, uint32_t prefix_len, uint32_t backend_id);
    // 12. Process request
    FGatewayDecision alice_api_gateway_process(
        TestGateway* gw, uint64_t client_hash, uint8_t method,
        const uint8_t* path, uint32_t path_len,
        uint32_t content_length, uint64_t timestamp_ns);
    // 13. Get stats
    FGatewayStats alice_api_gateway_stats(const TestGateway* gw);
    // 14. Hash client
    uint64_t alice_api_gateway_hash_client(const uint8_t* data, uint32_t len);

    // 15. Create SFQ
    StochasticFairQueue* alice_api_sfq_create(uint32_t quantum);
    // 16. Destroy SFQ
    void alice_api_sfq_destroy(StochasticFairQueue* sfq);
    // 17. Enqueue
    uint8_t alice_api_sfq_enqueue(
        StochasticFairQueue* sfq, uint64_t flow_hash,
        uint32_t size, uint64_t id, uint64_t enqueue_time);
    // 18. Dequeue
    uint64_t alice_api_sfq_dequeue(
        StochasticFairQueue* sfq, uint64_t* out_flow_hash, uint32_t* out_size);
    // 19. Free string
    void alice_api_string_free(char* s);
    // 20. Version
    char* alice_api_version();
}

// ============================================
// RAII Wrappers
// ============================================

namespace Alice
{

/// RAII wrapper for GcraCell
class FGcraCell
{
    GcraCell* Handle;

public:
    FGcraCell(double Rate, uint32_t Burst)
        : Handle(alice_api_gcra_create(Rate, Burst)) {}

    ~FGcraCell()
    {
        if (Handle) alice_api_gcra_destroy(Handle);
    }

    FGcraCell(FGcraCell&& Other) noexcept : Handle(Other.Handle) { Other.Handle = nullptr; }
    FGcraCell& operator=(FGcraCell&& Other) noexcept
    {
        if (this != &Other) { if (Handle) alice_api_gcra_destroy(Handle); Handle = Other.Handle; Other.Handle = nullptr; }
        return *this;
    }
    FGcraCell(const FGcraCell&) = delete;
    FGcraCell& operator=(const FGcraCell&) = delete;

    bool Check(uint64_t NowNs, uint64_t& OutNs) const { return alice_api_gcra_check(Handle, NowNs, &OutNs) == 1; }
    bool WouldAllow(uint64_t NowNs) const { return alice_api_gcra_would_allow(Handle, NowNs) == 1; }
    uint64_t Tat() const { return alice_api_gcra_tat(Handle); }
    void Merge(uint64_t OtherTat) const { alice_api_gcra_merge(Handle, OtherTat); }
    void Reset() const { alice_api_gcra_reset(Handle); }
};

/// RAII wrapper for Gateway
class FGateway
{
    TestGateway* Handle;

public:
    FGateway() : Handle(alice_api_gateway_create()) {}

    ~FGateway()
    {
        if (Handle) alice_api_gateway_destroy(Handle);
    }

    FGateway(FGateway&& Other) noexcept : Handle(Other.Handle) { Other.Handle = nullptr; }
    FGateway& operator=(FGateway&& Other) noexcept
    {
        if (this != &Other) { if (Handle) alice_api_gateway_destroy(Handle); Handle = Other.Handle; Other.Handle = nullptr; }
        return *this;
    }
    FGateway(const FGateway&) = delete;
    FGateway& operator=(const FGateway&) = delete;

    uint32_t AddBackend(uint32_t Id, const uint8_t* Host, uint32_t HostLen, uint16_t Port)
    {
        return alice_api_gateway_add_backend(Handle, Id, Host, HostLen, Port);
    }

    bool AddRoute(const uint8_t* Prefix, uint32_t PrefixLen, uint32_t BackendId)
    {
        return alice_api_gateway_add_route(Handle, Prefix, PrefixLen, BackendId) == 1;
    }

    FGatewayDecision Process(uint64_t ClientHash, uint8_t Method,
        const uint8_t* Path, uint32_t PathLen, uint32_t ContentLength, uint64_t TimestampNs)
    {
        return alice_api_gateway_process(Handle, ClientHash, Method, Path, PathLen, ContentLength, TimestampNs);
    }

    FGatewayStats Stats() const { return alice_api_gateway_stats(Handle); }

    static uint64_t HashClient(const uint8_t* Data, uint32_t Len)
    {
        return alice_api_gateway_hash_client(Data, Len);
    }
};

/// RAII wrapper for SFQ
class FFairQueue
{
    StochasticFairQueue* Handle;

public:
    explicit FFairQueue(uint32_t Quantum) : Handle(alice_api_sfq_create(Quantum)) {}

    ~FFairQueue()
    {
        if (Handle) alice_api_sfq_destroy(Handle);
    }

    FFairQueue(FFairQueue&& Other) noexcept : Handle(Other.Handle) { Other.Handle = nullptr; }
    FFairQueue& operator=(FFairQueue&& Other) noexcept
    {
        if (this != &Other) { if (Handle) alice_api_sfq_destroy(Handle); Handle = Other.Handle; Other.Handle = nullptr; }
        return *this;
    }
    FFairQueue(const FFairQueue&) = delete;
    FFairQueue& operator=(const FFairQueue&) = delete;

    bool Enqueue(uint64_t FlowHash, uint32_t Size, uint64_t Id, uint64_t EnqueueTime)
    {
        return alice_api_sfq_enqueue(Handle, FlowHash, Size, Id, EnqueueTime) == 1;
    }

    uint64_t Dequeue(uint64_t& OutFlowHash, uint32_t& OutSize)
    {
        return alice_api_sfq_dequeue(Handle, &OutFlowHash, &OutSize);
    }
};

} // namespace Alice
