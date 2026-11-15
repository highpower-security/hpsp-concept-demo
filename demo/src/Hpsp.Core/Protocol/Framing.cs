// =============================================================================
//  HPSP Demo  -  Hpsp.Core
//  File:    Protocol/Framing.cs
//  Purpose: Put messages on a byte stream and take them off again
//           (specification section 4.5, "Message framing").
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  IN PLAIN TERMS
//  --------------
//  TLS gives us a stream of bytes with no message boundaries. HPSP marks the
//  boundaries by putting a 4-byte length (big-endian) in front of each CBOR
//  message:
//
//      [00 00 00 17] [23 bytes of CBOR]  [00 00 00 2f] [47 bytes of CBOR] ...
//
//  The receiver reads 4 bytes, checks that the length is sensible (at least 2
//  and no more than the agreed maximum), then reads exactly that many bytes.
//  A length that is too large is treated as an attack or a bug, and the
//  connection is closed, so a peer can never make us allocate a huge buffer.
// =============================================================================

using System.Buffers.Binary;

namespace Hpsp.Core.Protocol;

public static class Framing
{
    /// <summary>The smallest max_msg any HPSP implementation may advertise (spec 8.1, hello).</summary>
    public const int MinMaxMsg = 1024;

    /// <summary>Write one framed message and flush.</summary>
    public static async Task WriteAsync(Stream s, byte[] body, CancellationToken ct = default)
    {
        var frame = new byte[4 + body.Length];
        BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)body.Length);
        body.CopyTo(frame, 4);
        await s.WriteAsync(frame, ct).ConfigureAwait(false);
        await s.FlushAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Read one framed message. Returns null when the peer closed the stream cleanly
    /// between messages. Throws <see cref="IOException"/> on a bad length or a stream
    /// that ends in the middle of a message.
    /// </summary>
    public static async Task<byte[]?> ReadAsync(Stream s, int maxMsg, CancellationToken ct = default)
    {
        var hdr = new byte[4];
        int got = await ReadFullyAsync(s, hdr, ct).ConfigureAwait(false);
        if (got == 0) return null;                                // clean close
        if (got < 4) throw new IOException("connection closed inside a frame header");
        uint len = BinaryPrimitives.ReadUInt32BigEndian(hdr);
        if (len < 2 || len > maxMsg) throw new IOException($"bad frame length {len} (limit {maxMsg})");
        var body = new byte[len];
        if (await ReadFullyAsync(s, body, ct).ConfigureAwait(false) < len) throw new IOException("connection closed inside a message");
        return body;
    }

    private static async Task<int> ReadFullyAsync(Stream s, byte[] buf, CancellationToken ct)
    {
        int off = 0;
        while (off < buf.Length)
        {
            int n = await s.ReadAsync(buf.AsMemory(off), ct).ConfigureAwait(false);
            if (n == 0) break;
            off += n;
        }
        return off;
    }
}
