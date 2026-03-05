// ALICE-API Unity C# Bindings
// Auto-generated — 20 DllImport functions
// Author: Moroya Sakamoto

using System;
using System.Runtime.InteropServices;

namespace Alice.Api
{
    // ========================================
    // FFI structs
    // ========================================

    [StructLayout(LayoutKind.Sequential)]
    public struct GatewayStats
    {
        public ulong RequestsTotal;
        public ulong RequestsForwarded;
        public ulong RequestsRateLimited;
        public ulong RequestsQueued;
        public ulong RequestsNotFound;
        public ulong BytesForwarded;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct GatewayDecision
    {
        public byte Kind;
        public ulong Value;

        public bool IsForward => Kind == 0;
        public bool IsRateLimited => Kind == 2;
        public bool IsNotFound => Kind == 3;
        public uint BackendId => (uint)Value;
        public ulong RetryAfterNs => Value;
    }

    // ========================================
    // GcraCell — Distributed Rate Limiter
    // ========================================

    public sealed class GcraCell : IDisposable
    {
        private IntPtr _handle;
        private bool _disposed;

        /// <summary>Create a GCRA rate limiter.</summary>
        public GcraCell(double rate, uint burst)
        {
            _handle = NativeMethods.alice_api_gcra_create(rate, burst);
        }

        /// <summary>Check rate limit. Returns true if allowed.</summary>
        public bool Check(ulong nowNs, out ulong outNs)
        {
            outNs = 0;
            return NativeMethods.alice_api_gcra_check(_handle, nowNs, ref outNs) == 1;
        }

        /// <summary>Check without updating state.</summary>
        public bool WouldAllow(ulong nowNs)
        {
            return NativeMethods.alice_api_gcra_would_allow(_handle, nowNs) == 1;
        }

        /// <summary>Current TAT.</summary>
        public ulong Tat => NativeMethods.alice_api_gcra_tat(_handle);

        /// <summary>CRDT merge.</summary>
        public void Merge(ulong otherTat) => NativeMethods.alice_api_gcra_merge(_handle, otherTat);

        /// <summary>Reset the cell.</summary>
        public void Reset() => NativeMethods.alice_api_gcra_reset(_handle);

        public void Dispose()
        {
            if (!_disposed && _handle != IntPtr.Zero)
            {
                NativeMethods.alice_api_gcra_destroy(_handle);
                _handle = IntPtr.Zero;
                _disposed = true;
            }
        }

        ~GcraCell() { Dispose(); }
    }

    // ========================================
    // Gateway — API Gateway
    // ========================================

    public sealed class Gateway : IDisposable
    {
        private IntPtr _handle;
        private bool _disposed;

        public Gateway()
        {
            _handle = NativeMethods.alice_api_gateway_create();
        }

        /// <summary>Add a backend server.</summary>
        public uint AddBackend(uint id, byte[] host, ushort port)
        {
            return NativeMethods.alice_api_gateway_add_backend(
                _handle, id, host, (uint)host.Length, port);
        }

        /// <summary>Add a route with a path prefix.</summary>
        public bool AddRoute(byte[] prefix, uint backendId)
        {
            return NativeMethods.alice_api_gateway_add_route(
                _handle, prefix, (uint)prefix.Length, backendId) == 1;
        }

        /// <summary>Process a request.</summary>
        public GatewayDecision Process(ulong clientHash, byte method,
            byte[] path, uint contentLength, ulong timestampNs)
        {
            return NativeMethods.alice_api_gateway_process(
                _handle, clientHash, method, path, (uint)path.Length,
                contentLength, timestampNs);
        }

        /// <summary>Get statistics.</summary>
        public GatewayStats Stats => NativeMethods.alice_api_gateway_stats(_handle);

        /// <summary>Hash a client identifier.</summary>
        public static ulong HashClient(byte[] data)
        {
            return NativeMethods.alice_api_gateway_hash_client(data, (uint)data.Length);
        }

        public void Dispose()
        {
            if (!_disposed && _handle != IntPtr.Zero)
            {
                NativeMethods.alice_api_gateway_destroy(_handle);
                _handle = IntPtr.Zero;
                _disposed = true;
            }
        }

        ~Gateway() { Dispose(); }
    }

    // ========================================
    // StochasticFairQueue — SFQ
    // ========================================

    public sealed class FairQueue : IDisposable
    {
        private IntPtr _handle;
        private bool _disposed;

        /// <summary>Create SFQ with quantum (bytes per DRR round).</summary>
        public FairQueue(uint quantum)
        {
            _handle = NativeMethods.alice_api_sfq_create(quantum);
        }

        /// <summary>Enqueue a request. Returns true if enqueued.</summary>
        public bool Enqueue(ulong flowHash, uint size, ulong id, ulong enqueueTime)
        {
            return NativeMethods.alice_api_sfq_enqueue(
                _handle, flowHash, size, id, enqueueTime) == 1;
        }

        /// <summary>Dequeue next request. Returns request id (0 if empty).</summary>
        public ulong Dequeue(out ulong flowHash, out uint size)
        {
            flowHash = 0;
            size = 0;
            return NativeMethods.alice_api_sfq_dequeue(_handle, ref flowHash, ref size);
        }

        public void Dispose()
        {
            if (!_disposed && _handle != IntPtr.Zero)
            {
                NativeMethods.alice_api_sfq_destroy(_handle);
                _handle = IntPtr.Zero;
                _disposed = true;
            }
        }

        ~FairQueue() { Dispose(); }
    }

    // ========================================
    // Version
    // ========================================

    public static class Version
    {
        public static string Get()
        {
            var ptr = NativeMethods.alice_api_version();
            if (ptr == IntPtr.Zero) return "";
            var str = Marshal.PtrToStringAnsi(ptr);
            NativeMethods.alice_api_string_free(ptr);
            return str ?? "";
        }
    }

    // ========================================
    // P/Invoke declarations (20 functions)
    // ========================================

    internal static class NativeMethods
    {
        private const string Lib = "alice_api";

        // 1
        [DllImport(Lib)] internal static extern IntPtr alice_api_gcra_create(double rate, uint burst);
        // 2
        [DllImport(Lib)] internal static extern void alice_api_gcra_destroy(IntPtr cell);
        // 3
        [DllImport(Lib)] internal static extern byte alice_api_gcra_check(
            IntPtr cell, ulong nowNs, ref ulong outNs);
        // 4
        [DllImport(Lib)] internal static extern byte alice_api_gcra_would_allow(
            IntPtr cell, ulong nowNs);
        // 5
        [DllImport(Lib)] internal static extern ulong alice_api_gcra_tat(IntPtr cell);
        // 6
        [DllImport(Lib)] internal static extern void alice_api_gcra_merge(
            IntPtr cell, ulong otherTat);
        // 7
        [DllImport(Lib)] internal static extern void alice_api_gcra_reset(IntPtr cell);
        // 8
        [DllImport(Lib)] internal static extern IntPtr alice_api_gateway_create();
        // 9
        [DllImport(Lib)] internal static extern void alice_api_gateway_destroy(IntPtr gw);
        // 10
        [DllImport(Lib)] internal static extern uint alice_api_gateway_add_backend(
            IntPtr gw, uint backendId, byte[] host, uint hostLen, ushort port);
        // 11
        [DllImport(Lib)] internal static extern byte alice_api_gateway_add_route(
            IntPtr gw, byte[] prefix, uint prefixLen, uint backendId);
        // 12
        [DllImport(Lib)] internal static extern GatewayDecision alice_api_gateway_process(
            IntPtr gw, ulong clientHash, byte method,
            byte[] path, uint pathLen, uint contentLength, ulong timestampNs);
        // 13
        [DllImport(Lib)] internal static extern GatewayStats alice_api_gateway_stats(IntPtr gw);
        // 14
        [DllImport(Lib)] internal static extern ulong alice_api_gateway_hash_client(
            byte[] data, uint len);
        // 15
        [DllImport(Lib)] internal static extern IntPtr alice_api_sfq_create(uint quantum);
        // 16
        [DllImport(Lib)] internal static extern void alice_api_sfq_destroy(IntPtr sfq);
        // 17
        [DllImport(Lib)] internal static extern byte alice_api_sfq_enqueue(
            IntPtr sfq, ulong flowHash, uint size, ulong id, ulong enqueueTime);
        // 18
        [DllImport(Lib)] internal static extern ulong alice_api_sfq_dequeue(
            IntPtr sfq, ref ulong flowHash, ref uint size);
        // 19
        [DllImport(Lib)] internal static extern void alice_api_string_free(IntPtr s);
        // 20
        [DllImport(Lib)] internal static extern IntPtr alice_api_version();
    }
}
