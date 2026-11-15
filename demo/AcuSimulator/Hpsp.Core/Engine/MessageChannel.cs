// =============================================================================
//  HPSP Demo  -  Hpsp.Core
//  File:    Engine/MessageChannel.cs
//  Purpose: Send and receive HPSP messages over a stream, including fragments
//           (specification section 4.6), and log every one of them.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  IN PLAIN TERMS
//  --------------
//  This wraps a TLS stream so the rest of the code can just say
//  "send this message" and "give me the next message". It also:
//    - splits a message that is bigger than the other side can take in one
//      piece into numbered fragments, and joins received fragments back
//      together (certificate chains during pairing can exceed 1,024 bytes);
//    - makes sure two threads never write to the stream at the same time;
//    - reports every message to the activity window.
// =============================================================================

using Hpsp.Core.Cbor;
using Hpsp.Core.Protocol;
using Hpsp.Core.Localization;

namespace Hpsp.Core.Engine;

public sealed class MessageChannel : IDisposable
{
    private readonly Stream _stream;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly Action<ActivityEntry> _log;
    private readonly string _channel;
    private readonly string? _peer;
    private long _nextFid = 1;

    // Fragment assembly state (one set at a time in each direction, spec 4.6)
    private byte[]? _fragBuf;
    private long _fragId, _fragGot;
    private DateTime _fragStarted;

    /// <summary>Largest single message the peer accepts (from hello; 1024 until then).</summary>
    public int PeerMaxMsg { get; set; } = Framing.MinMaxMsg;
    /// <summary>Largest fragmented message the peer can assemble.</summary>
    public int PeerMaxAssembled { get; set; } = 4096;
    /// <summary>Largest single message we accept.</summary>
    public int OurMaxMsg { get; init; } = 1024;
    /// <summary>Largest fragmented message we assemble.</summary>
    public int OurMaxAssembled { get; init; } = 8192;

    public MessageChannel(Stream stream, Action<ActivityEntry> log, string channel, string? peer = null)
    {
        _stream = stream; _log = log; _channel = channel; _peer = peer;
    }

    /// <summary>Send one message, fragmenting it if the peer cannot take it in one frame.</summary>
    public async Task SendAsync(HpspMessage m, CancellationToken ct = default, string? note = null)
    {
        byte[] body = m.Encode();
        Log(ActivityKind.Sent, m, body, note);
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (body.Length <= PeerMaxMsg)
            {
                await Framing.WriteAsync(_stream, body, ct).ConfigureAwait(false);
                return;
            }
            if (body.Length > PeerMaxAssembled) throw new InvalidOperationException(L.F("message of {0} bytes is larger than the peer can assemble ({1})", body.Length, PeerMaxAssembled));
            // Each fragment carries a piece of the encoded message. Leave room for the fragment's own envelope.
            long fid = _nextFid++;
            int piece = PeerMaxMsg - 64;
            for (int off = 0; off < body.Length; off += piece)
            {
                int n = Math.Min(piece, body.Length - off);
                var frag = new HpspMessage
                {
                    Type = "frag",
                    Data = new() { ["fid"] = fid, ["total"] = (long)body.Length, ["offset"] = (long)off, ["data_b64"] = body.AsSpan(off, n).ToArray() },
                };
                byte[] fb = frag.Encode();
                Log(ActivityKind.Sent, frag, fb, null, quiet: true);
                await Framing.WriteAsync(_stream, fb, ct).ConfigureAwait(false);
            }
        }
        finally { _writeLock.Release(); }
    }

    /// <summary>
    /// Receive the next complete message, joining fragments. Returns null when the
    /// peer closes cleanly. Throws on malformed input (the caller closes the session).
    /// </summary>
    public async Task<HpspMessage?> ReceiveAsync(CancellationToken ct = default)
    {
        while (true)
        {
            byte[]? body = await Framing.ReadAsync(_stream, OurMaxMsg, ct).ConfigureAwait(false);
            if (body is null) return null;
            var m = HpspMessage.Decode(body);
            if (m.Type != "frag")
            {
                Log(ActivityKind.Received, m, body);
                return m;
            }
            Log(ActivityKind.Received, m, body, null, quiet: true);
            byte[]? whole = AddFragment(m);
            if (whole is null) continue;
            var joined = HpspMessage.Decode(whole);
            if (joined.Type == "frag") throw new HpspCborException(L.T("a fragment set may not contain another fragment"));
            Log(ActivityKind.Received, joined, whole, L.T("joined from fragments"));
            return joined;
        }
    }

    private byte[]? AddFragment(HpspMessage f)
    {
        long? fid = f.GetLong("fid"), total = f.GetLong("total"), off = f.GetLong("offset");
        byte[]? piece = f.GetBytes("data_b64");
        if (fid is null || total is null || off is null || piece is null || piece.Length == 0) throw new HpspCborException(L.T("malformed fragment"));
        if (_fragBuf is not null && (DateTime.UtcNow - _fragStarted).TotalSeconds > 10) _fragBuf = null;   // spec: discard after 10 s
        if (off == 0)
        {
            if (total > OurMaxAssembled || total < 2) throw new HpspCborException(L.F("fragment set of {0} bytes is larger than we assemble ({1})", total, OurMaxAssembled));
            _fragBuf = new byte[total.Value]; _fragId = fid.Value; _fragGot = 0; _fragStarted = DateTime.UtcNow;
        }
        else if (_fragBuf is null || fid != _fragId || total != _fragBuf.Length) throw new HpspCborException(L.T("fragment does not belong to the set in progress"));
        if (off != _fragGot || piece.Length > _fragBuf.Length - _fragGot) throw new HpspCborException(L.T("fragment offset or length does not fit"));
        piece.CopyTo(_fragBuf, _fragGot);
        _fragGot += piece.Length;
        if (_fragGot < _fragBuf.Length) return null;
        var whole = _fragBuf; _fragBuf = null;
        return whole;
    }

    private void Log(ActivityKind kind, HpspMessage m, byte[] raw, string? note = null, bool quiet = false)
    {
        bool hb = m.Op == "heartbeat";
        _log(new ActivityEntry
        {
            Kind = kind, Channel = _channel, Peer = _peer, Message = m, Raw = raw,
            Summary = (kind == ActivityKind.Sent ? "-> " : "<- ") + MessageSummary.Of(m) + (note is null ? "" : "  (" + note + ")"),
            IsHeartbeat = hb || quiet,
        });
    }

    public void Dispose() { try { _stream.Dispose(); } catch { } _writeLock.Dispose(); }
}
